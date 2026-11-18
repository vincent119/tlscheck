package input

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/idna"

	"github.com/vincent119/tlscheck/internal/model"
)

func writeFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func certDER(t *testing.T) []byte {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test.invalid"}, NotBefore: time.Unix(0, 0), NotAfter: time.Unix(2000000000, 0)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func pemData(kind string, data []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: data})
}

func requireIssue(t *testing.T, result model.InputResult, code model.IssueCode) {
	t.Helper()
	for _, issue := range result.Issues {
		if issue.Code == code {
			return
		}
	}
	t.Fatalf("預期錯誤 %s，實際為 %v", code, result.Issues)
}

func TestClassifiesFilesBeforeTargets(t *testing.T) {
	p := NewParser()
	data := pemData("CERTIFICATE", certDER(t))
	file := writeFile(t, "example.com", data)
	results := p.ParseAll(context.Background(), []string{file, filepath.Join(t.TempDir(), "missing.pem"), "example.com", t.TempDir()})
	if len(results) != 4 || len(results[0].Certificates) != 1 || results[0].Target != nil {
		t.Fatalf("現有檔案未優先：%v", results)
	}
	requireIssue(t, results[1], model.FileNotFound)
	if results[2].Target == nil {
		t.Fatal("失敗後未繼續處理遠端")
	}
	requireIssue(t, results[3], model.NotRegularFile)
	for i, result := range results {
		if result.InputIndex != i {
			t.Fatal("來源輸入順序錯誤")
		}
	}
	for _, value := range []string{"missing.PEM", "missing.cer", "missing.crt", "missing.key", "./missing", `C:\missing\site.pem`, `\\server\share\missing`} {
		t.Run(value, func(t *testing.T) { requireIssue(t, p.Parse(context.Background(), value, 0), model.FileNotFound) })
	}
}

func TestNormalizesHTTPSAndIDNWithoutSecrets(t *testing.T) {
	tests := []struct {
		input, host, ascii string
		port               uint16
	}{
		{"example.com", "example.com", "example.com", 443},
		{"EXAMPLE.com:8443", "EXAMPLE.com", "example.com", 8443},
		{"https://example.com/", "example.com", "example.com", 443},
		{"https://user:password@example.com:8443/path?token=secret#fragment", "example.com", "example.com", 8443},
		{"https://例子.測試/path?token=secret", "例子.測試", "xn--fsqu00a.xn--g6w251d", 443},
		{"bücher.example", "bücher.example", "xn--bcher-kva.example", 443},
		{"localhost", "localhost", "localhost", 443},
		{"intranet", "intranet", "intranet", 443},
		{"example.com.", "example.com.", "example.com", 443},
	}
	longIDN := strings.Repeat("例", 30) + "." + strings.Repeat("測", 30) + "." + strings.Repeat("試", 30)
	tests = append(tests, struct {
		input, host, ascii string
		port               uint16
	}{longIDN, longIDN, "", 443})
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if tt.ascii == "" {
				var err error
				tt.ascii, err = idna.Lookup.ToASCII(tt.host)
				if err != nil {
					t.Fatal(err)
				}
			}
			r := NewParser().Parse(context.Background(), tt.input, 7)
			if len(r.Issues) != 0 || r.Target == nil {
				t.Fatalf("解析失敗：%v", r)
			}
			if r.Target.Host != tt.host || r.Target.ASCIIHost != tt.ascii || r.Target.Port != tt.port || r.Target.InputIndex != 7 {
				t.Fatalf("錯誤目標：%v", r.Target)
			}
			assertNoSecrets(t, r)
		})
	}
	for _, value := range []string{"https://user:password@example.com:bad/path?token=secret#fragment", "https://user:password@/path?token=secret#fragment", "https:/user:password@example.com/path?token=secret#fragment", "http://user:password@example.com/path?token=secret#fragment", "https://user:password@example.com/%zz?token=secret#fragment"} {
		r := NewParser().Parse(context.Background(), value, 1)
		if len(r.Issues) == 0 || r.Target != nil {
			t.Fatalf("無效 URL 被接受：%v", r)
		}
		assertNoSecrets(t, r)
	}
}

func assertNoSecrets(t *testing.T, r model.InputResult) {
	t.Helper()
	for _, output := range []string{fmt.Sprintf("%v", r), fmt.Sprintf("%+v", r), fmt.Sprintf("%#v", r)} {
		for _, secret := range []string{"password", "token=", "secret", "fragment", "/path"} {
			if strings.Contains(output, secret) {
				t.Fatalf("結果洩漏 URL 附加資料：%s", output)
			}
		}
	}
}

func TestValidatesIPsAndPorts(t *testing.T) {
	valid := map[string]string{"127.0.0.1": "127.0.0.1:443", "127.0.0.1:1": "127.0.0.1:1", "example.com:65535": "example.com:65535", "::1": "[::1]:443", "2001:db8::443": "[2001:db8::443]:443", "[::1]": "[::1]:443", "[::1]:8443": "[::1]:8443", "https://[::1]:8443/path": "[::1]:8443"}
	for value, want := range valid {
		t.Run(value, func(t *testing.T) {
			r := NewParser().Parse(context.Background(), value, 0)
			if r.Target == nil || len(r.Issues) != 0 || r.Target.String() != want {
				t.Fatalf("預期 %s，實際 %v", want, r)
			}
		})
	}
	for _, value := range []string{"", " ", "example.com:", "example.com:0", "example.com:65536", "example.com:-1", "example.com:+443", "example.com:４４３", "example.com:http", "https://example.com:", "https:/example.com", "[::1", "::gg", "[::1]:", "fe80::1%en0", "https://[fe80::1%25en0]/", "*.example.com", "bad_name.example", "-bad.example", "bad..example", "example.com\n", "999.999.999.999", strings.Repeat("a", 64) + ".com", "https://", "http://example.com", "example.com/path"} {
		t.Run(value, func(t *testing.T) {
			r := NewParser().Parse(context.Background(), value, 0)
			if len(r.Issues) == 0 || r.Target != nil {
				t.Fatalf("應拒絕：%q，結果 %v", value, r)
			}
		})
	}
}

func TestParsesCertificateAndKeyFormats(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		kind, format string
		der          []byte
	}{
		{"CERTIFICATE", "X.509", certDER(t)},
		{"RSA PRIVATE KEY", "PKCS#1", x509.MarshalPKCS1PrivateKey(rsaKey)},
		{"EC PRIVATE KEY", "SEC1", ecDER},
	}
	for _, key := range []struct {
		name  string
		value crypto.Signer
	}{{"RSA", rsaKey}, {"ECDSA", ecKey}, {"Ed25519", edKey}} {
		der, err := x509.MarshalPKCS8PrivateKey(key.value)
		if err != nil {
			t.Fatal(err)
		}
		tests = append(tests, struct {
			kind, format string
			der          []byte
		}{"PRIVATE KEY", "PKCS#8", der})
	}
	for i, tt := range tests {
		for _, encoding := range []string{"PEM", "DER"} {
			t.Run(fmt.Sprintf("%d/%s", i, encoding), func(t *testing.T) {
				data := tt.der
				if encoding == "PEM" {
					data = pemData(tt.kind, data)
				}
				path := writeFile(t, "arbitrary.data", data)
				r := NewParser().Parse(context.Background(), path, 3)
				if len(r.Issues) != 0 {
					t.Fatalf("解析錯誤：%v", r.Issues)
				}
				var source model.SourceRef
				if tt.kind == "CERTIFICATE" {
					if len(r.Certificates) != 1 || !bytes.Equal(r.Certificates[0].Certificate.Raw, tt.der) {
						t.Fatal("憑證內容不同")
					}
					source = r.Certificates[0].Source
				} else {
					if len(r.Keys) != 1 || r.Keys[0].Format != tt.format || r.Keys[0].Signer() == nil {
						t.Fatal("金鑰格式錯誤")
					}
					expected := []crypto.Signer{nil, rsaKey, ecKey, rsaKey, ecKey, edKey}[i]
					want, err := x509.MarshalPKIXPublicKey(expected.Public())
					if err != nil {
						t.Fatal(err)
					}
					got, err := x509.MarshalPKIXPublicKey(r.Keys[0].Signer().Public())
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(want, got) {
						t.Fatal("解析後的金鑰公開部分不同")
					}
					source = r.Keys[0].Source
				}
				if source.Path != path || source.InputIndex != 3 || source.Encoding != encoding {
					t.Fatalf("來源錯誤：%v", source)
				}
				wantBlock := 0
				if encoding == "PEM" {
					wantBlock = 1
				}
				if source.Block != wantBlock {
					t.Fatal("區塊索引錯誤")
				}
			})
		}
	}
}

func TestPreservesValidPEMBlocksAroundErrors(t *testing.T) {
	cert := pemData("CERTIFICATE", certDER(t))
	cases := []struct {
		name   string
		middle []byte
		code   model.IssueCode
	}{
		{"未知區塊", pemData("PUBLIC KEY", []byte{1, 2, 3}), model.UnsupportedBlock},
		{"損壞內容", pemData("CERTIFICATE", []byte{1, 2, 3}), model.InvalidData},
		{"損壞編碼", []byte("-----BEGIN CERTIFICATE-----\n%%%\n-----END CERTIFICATE-----\n"), model.InvalidData},
		{"缺少結尾", []byte("-----BEGIN CERTIFICATE-----\nAAAA\n"), model.InvalidData},
		{"加密容器", pemData("ENCRYPTED PRIVATE KEY", []byte{1, 2, 3}), model.EncryptedKey},
		{"舊式加密", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-256-CBC,00"}, Bytes: []byte{1, 2, 3}}), model.EncryptedKey},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			data := append(append(append([]byte{}, cert...), tt.middle...), cert...)
			r := NewParser().Parse(context.Background(), writeFile(t, "mixed", data), 0)
			if len(r.Certificates) != 2 {
				t.Fatalf("未保留全部有效區塊：%v", r)
			}
			requireIssue(t, r, tt.code)
			if r.Certificates[0].Source.Block != 1 || r.Certificates[1].Source.Block != 3 {
				t.Fatalf("位置錯誤：%v", r.Certificates)
			}
		})
	}
	for _, noise := range []string{"未辨識內容\n", "\ntrailing-data"} {
		data := append([]byte(noise), cert...)
		r := NewParser().Parse(context.Background(), writeFile(t, "noise", data), 0)
		if len(r.Certificates) != 1 {
			t.Fatal("雜訊吞掉有效區塊")
		}
		requireIssue(t, r, model.InvalidData)
	}
	r := NewParser().Parse(context.Background(), writeFile(t, "trailing", append(cert, []byte("unexpected")...)), 0)
	requireIssue(t, r, model.InvalidData)
}

func TestRecognizesEncryptedDER(t *testing.T) {
	envelope := struct {
		Algorithm pkix.AlgorithmIdentifier
		Data      []byte
	}{pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}}, []byte{1, 2, 3}}
	der, err := asn1.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	r := NewParser().Parse(context.Background(), writeFile(t, "encrypted.der", der), 0)
	requireIssue(t, r, model.EncryptedKey)
	if len(r.Keys) != 0 {
		t.Fatal("加密內容不得當成已解析金鑰")
	}
}

func TestFileSizeLimitAndReadOnly(t *testing.T) {
	cert := pemData("CERTIFICATE", certDER(t))
	for _, extra := range []int{0, 1} {
		t.Run(fmt.Sprintf("上限加%d", extra), func(t *testing.T) {
			data := append([]byte{}, cert...)
			data = append(data, bytes.Repeat([]byte{'\n'}, MaxFileSize+extra-len(data))...)
			path := writeFile(t, "limit.data", data)
			before := sha256.Sum256(data)
			if err := os.Chmod(path, 0400); err != nil {
				t.Fatal(err)
			}
			r := NewParser().Parse(context.Background(), path, 0)
			if extra == 0 {
				if len(r.Certificates) != 1 || len(r.Issues) != 0 {
					t.Fatalf("上限應可解析：%v", r.Issues)
				}
			} else {
				requireIssue(t, r, model.FileTooLarge)
				if len(r.Certificates) != 0 {
					t.Fatal("超限不應部分接受")
				}
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if before != sha256.Sum256(after) {
				t.Fatal("原檔遭修改")
			}
			entries, err := os.ReadDir(filepath.Dir(path))
			if err != nil || len(entries) != 1 {
				t.Fatal("產生未要求的檔案")
			}
		})
	}
}

func TestCanceledInputDoesNotProcess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := NewParser().Parse(ctx, "example.com", 0)
	requireIssue(t, r, model.Canceled)
}

func TestPrivateKeyTrailingDataIsNotIgnored(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, encoding := range []string{"DER", "PEM"} {
		t.Run(encoding, func(t *testing.T) {
			data := append(append([]byte{}, der...), []byte("unrecognized-tail")...)
			if encoding == "PEM" {
				data = pemData("PRIVATE KEY", data)
			}
			r := NewParser().Parse(context.Background(), writeFile(t, "key", data), 0)
			requireIssue(t, r, model.InvalidData)
		})
	}
}

func TestUnsupportedPKCS8Algorithm(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{der, pemData("PRIVATE KEY", der)} {
		r := NewParser().Parse(context.Background(), writeFile(t, "key", data), 0)
		requireIssue(t, r, model.UnsupportedKey)
	}
}

func TestSharedParserDoesNotMixSources(t *testing.T) {
	p := NewParser()
	for i := range 8 {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			t.Parallel()
			r := p.Parse(context.Background(), "example.com:8443", i)
			if r.Target == nil || r.Target.InputIndex != i || r.InputIndex != i {
				t.Fatal("並行解析來源混用")
			}
		})
	}
}
