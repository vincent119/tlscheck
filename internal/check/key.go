package check

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"

	"github.com/vincent119/tlscheck/internal/model"
)

// KeyInfo 僅保存來源與公開中繼資訊，不保存 signer 或私密編碼。
type KeyInfo struct {
	Source                     model.SourceRef
	Format                     string
	Algorithm                  string
	Bits                       int
	Curve                      string
	PublicKeyFingerprintSHA256 string
}

// KeyResult 明列實際執行的檢查與限制，不宣稱所有安全屬性都已驗證。
type KeyResult struct {
	Info                 KeyInfo
	Checks               []Outcome
	Validation           Outcome
	Limitations          []string
	Pairing              Outcome
	MatchingCertificates []int
}

// AnalyzeKey 不簽署資料、不解密，也不讀取其他檔案。
func AnalyzeKey(ctx context.Context, parsed model.ParsedKey) KeyResult {
	result, _ := inspectKey(ctx, parsed)
	return result
}

func inspectKey(ctx context.Context, parsed model.ParsedKey) (KeyResult, []byte) {
	result := KeyResult{Info: KeyInfo{Source: parsed.Source}, Validation: skipped("key.not_checked"), Pairing: skipped("pairing.not_requested"), Limitations: []string{"key.randomness_not_checked", "key.security_strength_not_assessed", "key.parsed_representation_only"}}
	if ctx.Err() != nil {
		result.Validation = failed("key.canceled", ExecutionFailure)
		return result, nil
	}
	switch parsed.Format {
	case "PKCS#1", "PKCS#8", "SEC1":
		result.Info.Format = parsed.Format
	default:
		result.Validation = failed("key.unsupported_format", ExecutionFailure)
		return result, nil
	}
	var public crypto.PublicKey
	switch key := parsed.Signer().(type) {
	case *rsa.PrivateKey:
		result.Info.Algorithm = "RSA"
		if key == nil {
			result.Validation = failed("key.missing_value", ExecutionFailure)
			return result, nil
		}
		if parsed.Format == "SEC1" {
			result.Validation = failed("key.container_mismatch", ExecutionFailure)
			return result, nil
		}
		if key.N != nil {
			result.Info.Bits = key.N.BitLen()
		}
		structure := rsaStructureValid(key)
		if structure {
			result.Checks = append(result.Checks, passed("key.rsa_structure_valid"))
			if err := key.Validate(); err != nil {
				result.Checks = append(result.Checks, failed("key.rsa_standard_validation_failed", VerificationFailure))
			} else {
				result.Checks = append(result.Checks, passed("key.rsa_standard_validation_passed"))
			}
		} else {
			result.Checks = append(result.Checks, failed("key.rsa_structure_invalid", VerificationFailure), skipped("key.prerequisites_failed"))
		}
		public = &key.PublicKey
	case *ecdsa.PrivateKey:
		result.Info.Algorithm = "ECDSA"
		if key == nil {
			result.Validation = failed("key.missing_value", ExecutionFailure)
			return result, nil
		}
		if parsed.Format == "PKCS#1" {
			result.Validation = failed("key.container_mismatch", ExecutionFailure)
			return result, nil
		}
		if !supportedKeyCurve(key.Curve) {
			result.Validation = failed("key.unsupported_curve", ExecutionFailure)
			return result, nil
		}
		result.Info.Bits = key.Curve.Params().BitSize
		result.Info.Curve = key.Curve.Params().Name
		scalarValid := key.D != nil && key.D.Sign() > 0 && key.D.Cmp(key.Curve.Params().N) < 0
		pointValid := key.X != nil && key.Y != nil && key.X.Sign() >= 0 && key.Y.Sign() >= 0 && key.Curve.IsOnCurve(key.X, key.Y)
		if scalarValid {
			result.Checks = append(result.Checks, passed("key.ecdsa_scalar_valid"))
		} else {
			result.Checks = append(result.Checks, failed("key.ecdsa_scalar_invalid", VerificationFailure))
		}
		if pointValid {
			result.Checks = append(result.Checks, passed("key.ecdsa_point_valid"))
		} else {
			result.Checks = append(result.Checks, failed("key.ecdsa_point_invalid", VerificationFailure))
		}
		if scalarValid && pointValid {
			// 使用標準曲線導出公開點，避免私鑰內部快取掩蓋公開欄位遭替換。
			x, y := key.Curve.ScalarBaseMult(key.D.Bytes())
			if x.Cmp(key.X) != 0 || y.Cmp(key.Y) != 0 {
				result.Checks = append(result.Checks, failed("key.ecdsa_consistency_failed", VerificationFailure))
			} else {
				result.Checks = append(result.Checks, passed("key.ecdsa_consistency_passed"))
			}
		} else {
			result.Checks = append(result.Checks, skipped("key.prerequisites_failed"))
		}
		public = &key.PublicKey
	case ed25519.PrivateKey:
		result.Info.Algorithm = "Ed25519"
		if parsed.Format != "PKCS#8" {
			result.Validation = failed("key.container_mismatch", ExecutionFailure)
			return result, nil
		}
		if len(key) != ed25519.PrivateKeySize {
			result.Checks = append(result.Checks, failed("key.ed25519_length_invalid", VerificationFailure), skipped("key.prerequisites_failed"))
		} else {
			result.Info.Bits = ed25519.PublicKeySize * 8
			result.Checks = append(result.Checks, passed("key.ed25519_length_valid"))
			derived := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
			if subtle.ConstantTimeCompare(key, derived) != 1 {
				result.Checks = append(result.Checks, failed("key.ed25519_consistency_failed", VerificationFailure))
			} else {
				result.Checks = append(result.Checks, passed("key.ed25519_consistency_passed"))
			}
			public = key.Public()
		}
	default:
		result.Validation = failed("key.unsupported_algorithm", ExecutionFailure)
		return result, nil
	}
	result.Validation = passed("key.applicable_checks_passed")
	for _, check := range result.Checks {
		if check.Status == Failed {
			result.Validation = failed("key.applicable_checks_failed", check.Class)
		}
	}
	if ctx.Err() != nil {
		result.Validation = failed("key.canceled", ExecutionFailure)
		return result, nil
	}
	if result.Validation.Status != Passed {
		return result, nil
	}
	der, supported, err := marshalPairPublicKey(public)
	if err != nil || !supported {
		result.Validation = failed("key.public_encoding_failed", ExecutionFailure)
		return result, nil
	}
	hash := sha256.Sum256(der)
	result.Info.PublicKeyFingerprintSHA256 = strings.ToUpper(hex.EncodeToString(hash[:]))
	return result, der
}

func rsaStructureValid(key *rsa.PrivateKey) bool {
	if key.N == nil || key.D == nil || key.N.Sign() <= 0 || key.D.Sign() <= 0 || key.E < 3 || key.E%2 == 0 || len(key.Primes) < 2 {
		return false
	}
	for _, prime := range key.Primes {
		if prime == nil || prime.Cmp(big.NewInt(1)) <= 0 {
			return false
		}
	}
	// Validate 的快取一致性比較不代表正負號也已檢查，先拒絕負的 CRT 值。
	for _, value := range []*big.Int{key.Precomputed.Dp, key.Precomputed.Dq, key.Precomputed.Qinv} {
		if value != nil && value.Sign() <= 0 {
			return false
		}
	}
	return true
}

func supportedKeyCurve(curve elliptic.Curve) bool {
	switch curve {
	case elliptic.P224(), elliptic.P256(), elliptic.P384(), elliptic.P521():
		return true
	default:
		return false
	}
}

func marshalPairPublicKey(public crypto.PublicKey) ([]byte, bool, error) {
	switch key := public.(type) {
	case *rsa.PublicKey:
		if key == nil || key.N == nil || key.N.Sign() <= 0 {
			return nil, true, errors.New("RSA 公開部分不完整")
		}
	case *ecdsa.PublicKey:
		if key == nil || key.X == nil || key.Y == nil || !supportedKeyCurve(key.Curve) {
			return nil, true, errors.New("ECDSA 公開部分不完整")
		}
	case ed25519.PublicKey:
		if len(key) != ed25519.PublicKeySize {
			return nil, true, errors.New("Ed25519 公開部分長度錯誤")
		}
	default:
		return nil, false, nil
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	return der, true, err
}
