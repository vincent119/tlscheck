package check

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vincent119/tlscheck/internal/input"
	"github.com/vincent119/tlscheck/internal/model"
	"github.com/vincent119/tlscheck/internal/testutil"
)

func TestPairAllLocalKeysAndCertificates(t *testing.T) {
	first := testutil.Issue(t, testutil.Template(11, "第一站台", fixedNow(), false), nil, nil)
	second := testutil.Issue(t, testutil.Template(12, "第二站台", fixedNow(), false), nil, nil)
	renewed := testutil.Issue(t, testutil.Template(13, "相同公開金鑰續期", fixedNow(), false), nil, first.Key)
	ca := testutil.Issue(t, testutil.Template(14, "可選 CA", fixedNow(), true), nil, nil)
	keys := []model.ParsedKey{keyInput(first.Key, "PKCS#8", 0), keyInput(second.Key, "PKCS#8", 1), keyInput(first.Key, "PKCS#8", 2)}
	certs := []model.ParsedCertificate{parsed(second.Cert, 3), parsed(ca.Cert, 4), parsed(first.Cert, 5), parsed(renewed.Cert, 6), parsed(first.Cert, 7)}
	result := PairLocal(t.Context(), keys, certs)
	if result.Failure() != NoFailure || result.Pairing.Status != Passed || len(result.Keys) != 3 || len(result.Certificates) != 4 || len(result.Pairs) != 5 {
		t.Fatalf("多對多配對錯誤：%+v", result)
	}
	if len(result.Certificates[2].Sources) != 2 || result.Certificates[2].Sources[1].InputIndex != 7 || len(result.Keys[0].MatchingCertificates) != 2 {
		t.Fatal("去重遺失來源或續期憑證配對")
	}
	if result.Certificates[1].Pairing.Status != NotPerformed || !result.Certificates[1].IsCA {
		t.Fatal("CA 不要求私鑰")
	}
	for _, pair := range result.Pairs {
		if result.Keys[pair.KeyIndex].Pairing.Status != Passed || result.Certificates[pair.CertificateIndex].Pairing.Status != Passed {
			t.Fatal("配對索引與狀態不一致")
		}
	}
}

func TestPairUnmatchedKeysAndSitesFail(t *testing.T) {
	first := testutil.Issue(t, testutil.Template(1, "站台", fixedNow(), false), nil, nil)
	other := testutil.Issue(t, testutil.Template(2, "另一站台", fixedNow(), false), nil, nil)
	for _, scenario := range []string{"私鑰未配對", "站台未配對", "同位數不同 key"} {
		t.Run(scenario, func(t *testing.T) {
			keys := []model.ParsedKey{keyInput(first.Key, "PKCS#8", 0)}
			certs := []model.ParsedCertificate{parsed(first.Cert, 1)}
			switch scenario {
			case "私鑰未配對":
				keys = append(keys, keyInput(other.Key, "PKCS#8", 2))
			case "站台未配對":
				certs = append(certs, parsed(other.Cert, 2))
			case "同位數不同 key":
				certs = []model.ParsedCertificate{parsed(other.Cert, 1)}
			}
			result := PairLocal(t.Context(), keys, certs)
			if result.Failure() != VerificationFailure || result.Pairing.Status != Failed {
				t.Fatalf("未配對項目未失敗：%+v", result)
			}
		})
	}
}

func TestPairMissingCounterpartIsNotPerformed(t *testing.T) {
	ca := testutil.Issue(t, testutil.Template(1, "CA", fixedNow(), true), nil, nil)
	site := testutil.Issue(t, testutil.Template(2, "站台", fixedNow(), false), nil, nil)
	for _, scenario := range []string{"只有 key", "只有 cert", "只有 CA", "CA 與不同 key", "CA 與配對 key", "完全空白"} {
		t.Run(scenario, func(t *testing.T) {
			var keys []model.ParsedKey
			var certs []model.ParsedCertificate
			switch scenario {
			case "只有 key":
				keys = []model.ParsedKey{keyInput(site.Key, "PKCS#8", 0)}
			case "只有 cert":
				certs = []model.ParsedCertificate{parsed(site.Cert, 0)}
			case "只有 CA":
				certs = []model.ParsedCertificate{parsed(ca.Cert, 0)}
			case "CA 與不同 key":
				keys = []model.ParsedKey{keyInput(site.Key, "PKCS#8", 0)}
				certs = []model.ParsedCertificate{parsed(ca.Cert, 1)}
			case "CA 與配對 key":
				keys = []model.ParsedKey{keyInput(ca.Key, "PKCS#8", 0)}
				certs = []model.ParsedCertificate{parsed(ca.Cert, 1)}
			}
			result := PairLocal(t.Context(), keys, certs)
			if result.Failure() != NoFailure || result.Pairing.Status != NotPerformed {
				t.Fatalf("缺少種類不應虛構配對失敗：%+v", result)
			}
			if scenario == "CA 與配對 key" && len(result.Pairs) != 1 {
				t.Fatal("可選 CA 配對關係遺失")
			}
		})
	}
}

func TestPairInvalidKeyCannotMasqueradeAsPublicMatch(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	site := testutil.Issue(t, testutil.Template(1, "站台", fixedNow(), false), nil, key)
	bad := append(ed25519.PrivateKey(nil), key...)
	bad[0] ^= 1
	result := PairLocal(t.Context(), []model.ParsedKey{keyInput(key, "PKCS#8", 0), keyInput(bad, "PKCS#8", 1)}, []model.ParsedCertificate{parsed(site.Cert, 2)})
	if result.Failure() != VerificationFailure || len(result.Pairs) != 1 || len(result.Keys) != 2 || result.Keys[1].Validation.Status != Failed || result.Keys[1].Pairing.Status == Passed {
		t.Fatalf("不能把同公開部分的無效私鑰合併或算成功：%+v", result)
	}
}

func TestPairNormalizesRSAAndECDSAContainers(t *testing.T) {
	for _, key := range []struct {
		rsa *rsa.PrivateKey
		ec  *ecdsa.PrivateKey
	}{{rsa: rsaKeyForTest(t)}, {ec: ecKeyForTest(t, elliptic.P256())}} {
		var keys []model.ParsedKey
		var identity testutil.Identity
		if key.rsa != nil {
			keys = []model.ParsedKey{keyInput(key.rsa, "PKCS#1", 0), keyInput(key.rsa, "PKCS#8", 1)}
			identity = testutil.Issue(t, testutil.Template(1, "站台", fixedNow(), false), nil, key.rsa)
		} else {
			keys = []model.ParsedKey{keyInput(key.ec, "SEC1", 0), keyInput(key.ec, "PKCS#8", 1)}
			identity = testutil.Issue(t, testutil.Template(1, "站台", fixedNow(), false), nil, key.ec)
		}
		result := PairLocal(t.Context(), keys, []model.ParsedCertificate{parsed(identity.Cert, 2)})
		if result.Failure() != NoFailure || len(result.Pairs) != 2 || result.Keys[0].Info.PublicKeyFingerprintSHA256 != result.Keys[1].Info.PublicKeyFingerprintSHA256 {
			t.Fatal("容器不同不應造成失配")
		}
	}
}

func TestPairPEMDERAndInputErrorsRemainDistinct(t *testing.T) {
	key := testutil.NewKey(t)
	site := testutil.Issue(t, testutil.Template(1, "本機站台", fixedNow(), false), nil, key)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	files := map[string][]byte{"private.data": der, "certificate.data": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: site.Cert.Raw}), "encrypted.data": pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("合成加密內容")}), "broken.data": []byte("無法辨識資料")}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(directory, name), data, 0400); err != nil {
			t.Fatal(err)
		}
	}
	results := input.NewParser().ParseAll(t.Context(), []string{filepath.Join(directory, "private.data"), filepath.Join(directory, "certificate.data"), filepath.Join(directory, "encrypted.data"), filepath.Join(directory, "broken.data")})
	var keys []model.ParsedKey
	var certificates []model.ParsedCertificate
	for _, result := range results {
		keys = append(keys, result.Keys...)
		certificates = append(certificates, result.Certificates...)
	}
	result := PairLocal(t.Context(), keys, certificates)
	if result.Failure() != NoFailure || len(result.Pairs) != 1 {
		t.Fatal("有效本機物件應繼續配對")
	}
	if len(results[2].Issues) != 1 || results[2].Issues[0].Code != model.EncryptedKey || len(results[3].Issues) == 0 {
		t.Fatal("加密不支援與解析錯誤不可被有效配對掩蓋")
	}
	for name, before := range files {
		after, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("原檔被修改")
		}
	}
}

func TestPairSafeResultsAndInvalidInputs(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	site := testutil.Issue(t, testutil.Template(1, "站台", fixedNow(), false), nil, key)
	result := PairLocal(t.Context(), []model.ParsedKey{keyInput(key, "PKCS#8", 0)}, []model.ParsedCertificate{parsed(site.Cert, 1)})
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, output := range []string{string(encoded), fmt.Sprintf("%+v", result), fmt.Sprintf("%#v", result)} {
		for _, secret := range []string{"signer", "PrivateKey", fmt.Sprint([]byte(key)), strings.Repeat("42", 32)} {
			if strings.Contains(output, secret) {
				t.Fatal("配對結果含私密資料")
			}
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if r := PairLocal(ctx, []model.ParsedKey{keyInput(key, "PKCS#8", 0)}, nil); r.Failure() != ExecutionFailure {
		t.Fatal("取消不應繼續")
	}
	if r := PairLocal(t.Context(), []model.ParsedKey{keyInput(nil, "PKCS#8", 0)}, []model.ParsedCertificate{parsed(site.Cert, 1), {}}); r.Failure() != ExecutionFailure {
		t.Fatal("執行錯誤應優先於失配")
	}
}
