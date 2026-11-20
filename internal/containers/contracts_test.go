package containers

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/vincent119/tlscheck/internal/testutil"
)

func fixture(t testing.TB, name string) []byte { t.Helper(); return testutil.ContainerFixture(t, name) }
func der(t testing.TB, value interface{}) []byte {
	t.Helper()
	data, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal("合成DER失敗", err)
	}
	return data
}

type testBag struct {
	Id    asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"explicit,tag:0"`
}

func testCertBag(t testing.TB, cert *x509.Certificate) testBag {
	t.Helper()
	data := der(t, struct {
		Id   asn1.ObjectIdentifier
		Data []byte `asn1:"explicit,tag:0"`
	}{oidCertTypeX509Certificate, cert.Raw})
	return testBag{oidCertBag, asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: data}}
}
func testKeyBag(t testing.TB, key crypto.Signer) testBag {
	t.Helper()
	data, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return testBag{oidKeyBag, asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: data}}
}

// 只供記憶體fixture簽MAC，不寫入明文私鑰或提供產品encoder。
func signTestPFX(t testing.TB, bags []testBag, password string) []byte {
	t.Helper()
	contents := der(t, bags)
	auth := der(t, []contentInfo{{oidDataContentType, asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: der(t, contents)}}})
	p := pfxPdu{Version: 3, AuthSafe: contentInfo{oidDataContentType, asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: der(t, auth)}}}
	return signedOuter(t, p, password, auth)
}
func signedOuter(t testing.TB, p pfxPdu, password string, auth []byte) []byte {
	t.Helper()
	p.MacData = macData{Mac: digestInfo{Algorithm: pkix.AlgorithmIdentifier{Algorithm: oidSHA256}}, MacSalt: bytes.Repeat([]byte{1}, 16), Iterations: 10}
	encoded, err := bmpStringZeroTerminated(password)
	if err != nil {
		t.Fatal(err)
	}
	key := pbkdf(sha256Sum, 32, 64, p.MacData.MacSalt, encoded, 10, 3, 32)
	mac := hmac.New(sha256.New, key)
	mac.Write(auth)
	p.MacData.Mac.Digest = mac.Sum(nil)
	clear(encoded)
	clear(key)
	return der(t, p)
}
func TestAtomicContainerContracts(t *testing.T) {
	for _, tc := range []struct{ name, password string }{{"modern.pfx", "S12_SYNTHETIC_PASSWORD_CANARY"}, {"empty.pfx", ""}, {"unicode.pfx", " 測試密碼 "}, {"cert-only.pfx", ""}} {
		t.Run(tc.name, func(t *testing.T) {
			data := fixture(t, tc.name)
			r, err := Decode(t.Context(), data, []byte(tc.password))
			if err != nil || len(r.Certificates()) != 2 {
				t.Fatal("容器解碼不完整", err)
			}
			if tc.name == "cert-only.pfx" && r.Signer() != nil {
				t.Fatal("純憑證捏造私鑰")
			}
			encoded, err := json.Marshal(r)
			if err != nil || string(encoded) != "{}" || strings.Contains(fmt.Sprintf("%#v", r), "PrivateKey") {
				t.Fatal("容器反射洩漏秘密")
			}
			if _, err := Decode(t.Context(), data, []byte("wrong")); !errors.Is(err, ErrIntegrity) {
				t.Fatal("錯誤密碼未安全拒絕", err)
			}
		})
	}
	id := testutil.Issue(t, testutil.Template(1, "synthetic", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), false), nil, nil)
	valid := fixture(t, "empty.pfx")
	var missing pfxPdu
	if unmarshal(valid, &missing) != nil {
		t.Fatal("fixture無效")
	}
	missing.MacData = macData{}
	bad := map[string][]byte{"缺MAC": der(t, missing), "多私鑰": signTestPFX(t, []testBag{testCertBag(t, id.Cert), testKeyBag(t, id.Key), testKeyBag(t, id.Key)}, ""), "未知bag": signTestPFX(t, []testBag{testCertBag(t, id.Cert), {asn1.ObjectIdentifier{1, 2, 3}, asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: []byte{5, 0}}}}, ""), "空容器": signTestPFX(t, nil, ""), "僅私鑰": signTestPFX(t, []testBag{testKeyBag(t, id.Key)}, ""), "尾端資料": append(append([]byte{}, valid...), 0)}
	corrupt := append([]byte{}, valid...)
	corrupt[len(corrupt)-1] ^= 1
	bad["破壞MAC"] = corrupt
	for name, data := range bad {
		t.Run(name, func(t *testing.T) {
			r, err := Decode(t.Context(), data, nil)
			if err == nil || len(r.Certificates()) != 0 || r.Signer() != nil {
				t.Fatal("失敗容器部分交付", name)
			}
		})
	}
	for _, kind := range []string{"ECDSA", "RSA"} {
		t.Run(kind, func(t *testing.T) {
			var k crypto.Signer
			var err error
			if kind == "RSA" {
				k, err = rsa.GenerateKey(rand.Reader, 2048)
			} else {
				k, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			}
			if err != nil {
				t.Fatal(err)
			}
			identity := testutil.Issue(t, testutil.Template(2, "synthetic", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), false), nil, k)
			r, err := Decode(t.Context(), signTestPFX(t, []testBag{testCertBag(t, identity.Cert), testKeyBag(t, k)}, ""), nil)
			if err != nil || r.Signer() == nil {
				t.Fatal("支援演算法被拒絕", err)
			}
		})
	}
}
func TestContainerBudgetsAndPasswordBoundary(t *testing.T) {
	l := proposedLimits()
	if l.depth != 32 {
		t.Fatal("深度未採核准的32層")
	}
	b := budget{ctx: t.Context(), limits: l}
	for i := 0; i < 3; i++ {
		if b.charge(1000000, 32, 32) != nil {
			t.Fatal("上限內被拒絕")
		}
	}
	if b.charge(1, 32, 32) == nil || b.observed.calls != 3 {
		t.Fatal("累計超限仍運算")
	}
	for _, n := range []int{-1, 0, 1000001, math.MaxInt} {
		b := budget{ctx: t.Context(), limits: l}
		if b.charge(n, 32, 32) == nil || b.observed.calls != 0 {
			t.Fatal("單次超限未先拒絕")
		}
	}
	data := fixture(t, "empty.pfx")
	limited := l
	limited.work = 10
	r, stats, err := controlledDecode(t.Context(), data, "", limited)
	if !errors.Is(err, ErrLimit) || len(r.certs) != 0 || r.key != nil || stats.calls != 1 || stats.decrypted != 0 {
		t.Fatal("內層工作超限後仍解密", err, stats)
	}
	for _, password := range [][]byte{[]byte("a\x00b"), []byte("\U0001F600"), {0xff}, bytes.Repeat([]byte{1}, 4097)} {
		if PasswordSupported(password) {
			t.Fatal("不支援密碼被接受")
		}
		if r, err := Decode(t.Context(), data, password); !errors.Is(err, ErrUnsupported) || r.Signer() != nil || len(r.Certificates()) != 0 {
			t.Fatal("解碼入口未拒絕不支援密碼", err)
		}
	}
	if !PasswordSupported([]byte(" 測試密碼 ")) {
		t.Fatal("BMP或空白被錯誤拒絕")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := Decode(ctx, data, nil); !errors.Is(err, context.Canceled) {
		t.Fatal("取消仍解碼", err)
	}
}

func TestContainerRejectsEachResourceLimitAtomically(t *testing.T) {
	data := fixture(t, "modern.pfx")
	for _, name := range []string{"input", "decrypted", "certificates", "bags", "depth", "password", "iterations", "work"} {
		t.Run(name, func(t *testing.T) {
			l := proposedLimits()
			switch name {
			case "input":
				l.input = len(data) - 1
			case "decrypted":
				l.decrypted = 1
			case "certificates":
				l.certificates = 1
			case "bags":
				l.bags = 1
			case "depth":
				l.depth = 16
			case "password":
				l.password = 1
			case "iterations":
				l.iterations = 9
			case "work":
				l.work = 10
			}
			r, _, err := controlledDecode(t.Context(), data, "S12_SYNTHETIC_PASSWORD_CANARY", l)
			if !errors.Is(err, ErrLimit) || r.key != nil || len(r.certs) != 0 {
				t.Fatal("資源超限仍交付部分物件", err)
			}
		})
	}
	data = []byte{5, 0}
	for depth := 1; depth <= 33; depth++ {
		data = der(t, asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: data})
		b := budget{ctx: t.Context(), limits: proposedLimits()}
		err := b.inspect(data, 1)
		if (depth <= 32 && err != nil) || (depth == 33 && !errors.Is(err, ErrLimit)) {
			t.Fatal("32層邊界不符契約", depth, err)
		}
	}
}
func TestP7BPartialAndSourceBoundaries(t *testing.T) {
	data := fixture(t, "chain.p7b")
	certs, issues, err := DecodeP7B(t.Context(), data)
	if err != nil || len(certs) != 2 || len(issues) != 0 {
		t.Fatal("P7B契約失敗", err)
	}
	var outer contentInfo
	if unmarshal(data, &outer) != nil {
		t.Fatal("fixture無效")
	}
	b := budget{ctx: t.Context(), limits: proposedLimits()}
	parts, err := b.elements(outer.Content.Bytes, 3, 6)
	if err != nil {
		t.Fatal(err)
	}
	parts[3].Bytes = append(append([]byte{}, parts[3].Bytes...), []byte{0x81, 1, 0}...)
	parts[3].FullBytes = nil
	parts[3] = asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: parts[3].Bytes}
	var body []byte
	for _, v := range parts {
		body = append(body, der(t, v)...)
	}
	outer.Content = asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: der(t, asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: body})}
	mixed := der(t, outer)
	certs, issues, err = DecodeP7B(t.Context(), mixed)
	if err != nil || len(certs) != 2 || len(issues) != 1 {
		t.Fatal("有效憑證被部分失敗吞掉", err, issues)
	}
	for _, input := range [][]byte{data[:len(data)-1], append(append([]byte{}, data...), 0)} {
		cs, _, err := DecodeP7B(t.Context(), input)
		if err == nil || len(cs) != 0 {
			t.Fatal("壞容器邊界交付資料")
		}
	}
}
