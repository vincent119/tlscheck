package check

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/vincent119/tlscheck/internal/input"
	"github.com/vincent119/tlscheck/internal/model"
	"github.com/vincent119/tlscheck/internal/testutil"
)

func rsaKeyForTest(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
func ecKeyForTest(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
func keyInput(key crypto.Signer, format string, index int) model.ParsedKey {
	return model.NewParsedKey(model.SourceRef{Path: "合成私鑰.key", InputIndex: index, Block: index + 1, Encoding: "PEM"}, format, key)
}

func assertKeyChecksPassed(t *testing.T, result KeyResult) {
	t.Helper()
	if result.Validation.Status != Passed || len(result.Checks) == 0 || result.Info.PublicKeyFingerprintSHA256 == "" || len(result.Limitations) == 0 {
		t.Fatalf("有效性或限制資訊不足：%+v", result)
	}
	for _, check := range result.Checks {
		if check.Status != Passed {
			t.Fatalf("適用檢查未通過：%+v", result)
		}
	}
}

func TestKeySupportedFormatsAndAlgorithms(t *testing.T) {
	rsaKey := rsaKeyForTest(t)
	ecKey := ecKeyForTest(t, elliptic.P256())
	edKey := testutil.NewKey(t)
	ecDER, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		label, format, algorithm string
		der                      []byte
		bits                     int
		curve                    string
	}{
		{"RSA PRIVATE KEY", "PKCS#1", "RSA", x509.MarshalPKCS1PrivateKey(rsaKey), 2048, ""},
		{"EC PRIVATE KEY", "SEC1", "ECDSA", ecDER, 256, "P-256"},
	}
	for _, key := range []struct {
		signer    crypto.Signer
		algorithm string
		bits      int
		curve     string
	}{{rsaKey, "RSA", 2048, ""}, {ecKey, "ECDSA", 256, "P-256"}, {edKey, "Ed25519", 256, ""}} {
		der, err := x509.MarshalPKCS8PrivateKey(key.signer)
		if err != nil {
			t.Fatal(err)
		}
		cases = append(cases, struct {
			label, format, algorithm string
			der                      []byte
			bits                     int
			curve                    string
		}{"PRIVATE KEY", "PKCS#8", key.algorithm, der, key.bits, key.curve})
	}
	for _, tt := range cases {
		for _, encoding := range []string{"PEM", "DER"} {
			t.Run(tt.algorithm+"/"+tt.format+"/"+encoding, func(t *testing.T) {
				data := tt.der
				if encoding == "PEM" {
					data = pem.EncodeToMemory(&pem.Block{Type: tt.label, Bytes: data})
				}
				path := filepath.Join(t.TempDir(), "key.data")
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
				parsed := input.NewParser().Parse(t.Context(), path, 4)
				if len(parsed.Keys) != 1 || len(parsed.Issues) != 0 {
					t.Fatalf("解析失敗：%v", parsed.Issues)
				}
				result := AnalyzeKey(t.Context(), parsed.Keys[0])
				assertKeyChecksPassed(t, result)
				if result.Info.Format != tt.format || result.Info.Algorithm != tt.algorithm || result.Info.Bits != tt.bits || result.Info.Curve != tt.curve || result.Info.Source.Path != path || result.Info.Source.Encoding != encoding {
					t.Fatal("公開資訊或來源錯誤")
				}
				public, err := x509.MarshalPKIXPublicKey(parsed.Keys[0].Signer().Public())
				if err != nil {
					t.Fatal(err)
				}
				hash := sha256.Sum256(public)
				if result.Info.PublicKeyFingerprintSHA256 != strings.ToUpper(hex.EncodeToString(hash[:])) {
					t.Fatal("公開指紋錯誤")
				}
				after, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(after, data) {
					t.Fatal("私鑰原檔被修改")
				}
			})
		}
	}
}

func TestKeyRSAInvalidMaterialIsNotValidated(t *testing.T) {
	original := rsaKeyForTest(t)
	der := x509.MarshalPKCS1PrivateKey(original)
	for _, scenario := range []string{"缺少 N", "負 N", "缺少 D", "負 D", "錯誤 D", "缺少質因數", "nil 質因數", "負質因數", "錯誤 E", "錯誤 CRT"} {
		t.Run(scenario, func(t *testing.T) {
			key, err := x509.ParsePKCS1PrivateKey(der)
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "缺少 N":
				key.N = nil
			case "負 N":
				key.N.Neg(key.N)
			case "缺少 D":
				key.D = nil
			case "負 D":
				key.D.Neg(key.D)
			case "錯誤 D":
				key.D.Add(key.D, big.NewInt(1))
			case "缺少質因數":
				key.Primes = nil
			case "nil 質因數":
				key.Primes[0] = nil
			case "負質因數":
				key.Primes[0].Neg(key.Primes[0])
			case "錯誤 E":
				key.E = 2
			case "錯誤 CRT":
				key.Precomputed.Dp.Add(key.Precomputed.Dp, big.NewInt(1))
			}
			result := AnalyzeKey(t.Context(), keyInput(key, "PKCS#1", 0))
			if result.Validation.Status != Failed || result.Validation.Class != VerificationFailure || result.Info.PublicKeyFingerprintSHA256 != "" {
				t.Fatalf("錯誤 RSA 未被拒絕：%+v", result)
			}
		})
	}
}

func TestKeyECDSAValidityAndConsistency(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P224(), elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			key := ecKeyForTest(t, curve)
			result := AnalyzeKey(t.Context(), keyInput(key, "SEC1", 0))
			assertKeyChecksPassed(t, result)
			if result.Info.Bits != curve.Params().BitSize || result.Info.Curve != curve.Params().Name {
				t.Fatal("曲線資訊錯誤")
			}
		})
	}
	for _, scenario := range []string{"D nil", "D 零", "D 負數", "D 超出階數", "X nil", "Y nil", "點不在曲線", "公開點不一致"} {
		t.Run(scenario, func(t *testing.T) {
			key := ecKeyForTest(t, elliptic.P256())
			switch scenario {
			case "D nil":
				key.D = nil
			case "D 零":
				key.D = big.NewInt(0)
			case "D 負數":
				key.D = big.NewInt(-1)
			case "D 超出階數":
				key.D = new(big.Int).Set(key.Curve.Params().N)
			case "X nil":
				key.X = nil
			case "Y nil":
				key.Y = nil
			case "點不在曲線":
				key.X = big.NewInt(1)
				key.Y = big.NewInt(1)
			case "公開點不一致":
				other := ecKeyForTest(t, elliptic.P256())
				key.X = other.X
				key.Y = other.Y
			}
			result := AnalyzeKey(t.Context(), keyInput(key, "SEC1", 0))
			if result.Validation.Status != Failed || result.Validation.Class != VerificationFailure {
				t.Fatalf("錯誤 EC 未被拒絕：%+v", result)
			}
		})
	}
}

func TestKeyEd25519LengthAndSeedConsistency(t *testing.T) {
	for _, length := range []int{0, 1, 31, 32, 63, 65} {
		t.Run(fmt.Sprint(length), func(t *testing.T) {
			key := ed25519.PrivateKey(make([]byte, length))
			result := AnalyzeKey(t.Context(), keyInput(key, "PKCS#8", 0))
			if result.Validation.Class != VerificationFailure {
				t.Fatalf("錯誤長度未被拒絕：%+v", result)
			}
		})
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	key[len(key)-1] ^= 1
	result := AnalyzeKey(t.Context(), keyInput(key, "PKCS#8", 0))
	if result.Validation.Class != VerificationFailure {
		t.Fatal("seed 與公開部分不一致未被拒絕")
	}
}

type unsupportedSigner struct{}

func (unsupportedSigner) Public() crypto.PublicKey { panic("不得呼叫未知 signer") }
func (unsupportedSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	panic("不得簽署")
}

func TestKeyInvalidInputsDoNotPanicOrInvokeUnknownSigner(t *testing.T) {
	var nilRSA *rsa.PrivateKey
	var nilEC *ecdsa.PrivateKey
	for _, parsed := range []model.ParsedKey{keyInput(nil, "PKCS#8", 0), keyInput(nilRSA, "PKCS#1", 0), keyInput(nilEC, "SEC1", 0), keyInput(unsupportedSigner{}, "PKCS#8", 0), keyInput(&ecdsa.PrivateKey{}, "SEC1", 0), keyInput(testutil.NewKey(t), "密碼不得回顯", 0), keyInput(testutil.NewKey(t), "SEC1", 0)} {
		result := AnalyzeKey(t.Context(), parsed)
		if result.Validation.Class != ExecutionFailure {
			t.Fatalf("不支援輸入應為執行錯誤：%+v", result)
		}
		if strings.Contains(fmt.Sprintf("%+v", result), "密碼不得回顯") {
			t.Fatal("回顯未驗證格式")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if r := AnalyzeKey(ctx, keyInput(testutil.NewKey(t), "PKCS#8", 0)); r.Validation.Class != ExecutionFailure {
		t.Fatal("取消後不應繼續驗證")
	}
}

func TestKeyResultsNeverExposePrivateMaterial(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	before := append([]byte(nil), key...)
	parsed := keyInput(key, "PKCS#8", 0)
	result := AnalyzeKey(t.Context(), parsed)
	assertKeyChecksPassed(t, result)
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, output := range []string{string(encoded), fmt.Sprintf("%v", result), fmt.Sprintf("%+v", result), fmt.Sprintf("%#v", result)} {
		for _, secret := range []string{hex.EncodeToString(key.Seed()), hex.EncodeToString(key), fmt.Sprint([]byte(key)), "signer", "PrivateKey", "seed:"} {
			if strings.Contains(output, secret) {
				t.Fatal("安全結果包含私密物件或內容")
			}
		}
	}
	if !bytes.Equal(key, before) {
		t.Fatal("檢查修改了原始私鑰")
	}
	for _, key := range []crypto.Signer{rsaKeyForTest(t), ecKeyForTest(t, elliptic.P256())} {
		before, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		result := AnalyzeKey(t.Context(), keyInput(key, "PKCS#8", 0))
		assertKeyChecksPassed(t, result)
		after, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil || !reflect.DeepEqual(before, after) {
			t.Fatal("檢查修改了私鑰物件")
		}
	}
}
