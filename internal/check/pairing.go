package check

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/vincent119/tlscheck/internal/model"
)

// PairingCertificate 的配對只表示公開金鑰相同，不代表憑證可信。
type PairingCertificate struct {
	FingerprintSHA256 string
	Sources           []model.SourceRef
	IsCA              bool
	Pairing           Outcome
	MatchingKeys      []int
}

// KeyCertificatePair 的索引從 0 起算，分別指向結果中的 key 與憑證。
type KeyCertificatePair struct {
	KeyIndex         int
	CertificateIndex int
}

// PairingResult 保留全部本機關係與未配對項目，不接受遠端結果。
type PairingResult struct {
	Keys         []KeyResult
	Certificates []PairingCertificate
	Pairs        []KeyCertificatePair
	Pairing      Outcome
	Issues       []Outcome
}

// Failure 不因缺少另一種輸入而宣告失敗。
func (r PairingResult) Failure() FailureClass {
	severity := r.Pairing.Class
	for _, key := range r.Keys {
		for _, outcome := range []Outcome{key.Validation, key.Pairing} {
			if outcome.Class > severity {
				severity = outcome.Class
			}
		}
	}
	for _, cert := range r.Certificates {
		if cert.Pairing.Class > severity {
			severity = cert.Pairing.Class
		}
	}
	for _, issue := range r.Issues {
		if issue.Class > severity {
			severity = issue.Class
		}
	}
	return severity
}

// PairLocal 只使用成功解析的本機物件；S01 的解析錯誤仍須由 S06 彙整。
func PairLocal(ctx context.Context, keys []model.ParsedKey, certificates []model.ParsedCertificate) PairingResult {
	result := PairingResult{Pairing: skipped("pairing.not_performed")}
	if ctx.Err() != nil {
		result.Issues = append(result.Issues, failed("pairing.canceled", ExecutionFailure))
		return result
	}
	keysByPublicDER := make(map[string][]int, len(keys))
	for _, key := range keys {
		if ctx.Err() != nil {
			result.Issues = append(result.Issues, failed("pairing.canceled", ExecutionFailure))
			return result
		}
		checked, der := inspectKey(ctx, key)
		index := len(result.Keys)
		result.Keys = append(result.Keys, checked)
		if checked.Validation.Status == Passed {
			keysByPublicDER[string(der)] = append(keysByPublicDER[string(der)], index)
		}
	}
	byRaw := make(map[string]int, len(certificates))
	hasSite := false
	for _, parsed := range certificates {
		if ctx.Err() != nil {
			result.Issues = append(result.Issues, failed("pairing.canceled", ExecutionFailure))
			return result
		}
		cert := parsed.Certificate
		if cert == nil || len(cert.Raw) == 0 {
			result.Issues = append(result.Issues, failed("pairing.invalid_certificate", ExecutionFailure))
			continue
		}
		if index, ok := byRaw[string(cert.Raw)]; ok {
			result.Certificates[index].Sources = append(result.Certificates[index].Sources, parsed.Source)
			continue
		}
		index := len(result.Certificates)
		byRaw[string(cert.Raw)] = index
		hash := sha256.Sum256(cert.Raw)
		item := PairingCertificate{FingerprintSHA256: strings.ToUpper(hex.EncodeToString(hash[:])), Sources: []model.SourceRef{parsed.Source}, IsCA: cert.IsCA, Pairing: skipped("pairing.not_performed")}
		if !cert.IsCA {
			hasSite = true
		}
		if len(keys) > 0 {
			der, supported, err := marshalPairPublicKey(cert.PublicKey)
			if err != nil {
				result.Issues = append(result.Issues, failed("pairing.invalid_certificate_public_key", ExecutionFailure))
			}
			if err == nil && supported {
				for _, keyIndex := range keysByPublicDER[string(der)] {
					item.MatchingKeys = append(item.MatchingKeys, keyIndex)
					result.Keys[keyIndex].MatchingCertificates = append(result.Keys[keyIndex].MatchingCertificates, index)
					result.Pairs = append(result.Pairs, KeyCertificatePair{KeyIndex: keyIndex, CertificateIndex: index})
				}
			}
		}
		result.Certificates = append(result.Certificates, item)
	}
	applicable := len(keys) > 0 && hasSite
	unmatched := false
	for index := range result.Keys {
		key := &result.Keys[index]
		if len(key.MatchingCertificates) > 0 {
			key.Pairing = passed("pairing.public_key_match")
			continue
		}
		if applicable {
			unmatched = true
		}
		switch {
		case key.Validation.Status != Passed:
			key.Pairing = skipped("pairing.key_invalid")
		case applicable:
			key.Pairing = failed("pairing.key_unmatched", VerificationFailure)
		case len(result.Certificates) == 0:
			key.Pairing = skipped("pairing.no_certificates")
		default:
			key.Pairing = skipped("pairing.no_site_certificates")
		}
	}
	for index := range result.Certificates {
		cert := &result.Certificates[index]
		switch {
		case len(cert.MatchingKeys) > 0:
			cert.Pairing = passed("pairing.public_key_match")
		case len(keys) == 0:
			cert.Pairing = skipped("pairing.no_private_keys")
		case cert.IsCA:
			cert.Pairing = skipped("pairing.ca_key_optional")
		case applicable:
			cert.Pairing = failed("pairing.certificate_unmatched", VerificationFailure)
			unmatched = true
		}
	}
	switch {
	case len(keys) == 0:
		result.Pairing = skipped("pairing.no_private_keys")
	case len(result.Certificates) == 0:
		result.Pairing = skipped("pairing.no_certificates")
	case !hasSite:
		result.Pairing = skipped("pairing.no_site_certificates")
	case unmatched:
		result.Pairing = failed("pairing.unmatched_objects", VerificationFailure)
	default:
		result.Pairing = passed("pairing.all_required_matched")
	}
	return result
}
