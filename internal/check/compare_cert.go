package check

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"slices"
	"strings"
	"time"
)

// CertificateDifference 保留穩定欄位名稱及公開原值，呈現層負責安全遮蔽。
type CertificateDifference struct {
	Field               string
	Candidate, Observed []string
}

// CertificateComparison 與信任結果獨立，不會把候選加入信任根。
type CertificateComparison struct {
	CandidateSource            string
	CandidateFingerprintSHA256 string
	ObservedFingerprintSHA256  string
	Outcome                    Outcome
	Differences                []CertificateDifference
}

func publicDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}
func comparisonSet(values []string) []string {
	values = slices.Clone(values)
	slices.Sort(values)
	return slices.Compact(values)
}

// WithCertificateComparison 只使用本次已觀測的leaf，不啟動額外握手或驗證。
func (r RemoteResult) WithCertificateComparison(path string, candidate *x509.Certificate) RemoteResult {
	result := &CertificateComparison{CandidateSource: path, Outcome: skipped("comparison.leaf_unavailable"), Differences: []CertificateDifference{}}
	r.Comparison = result
	if candidate == nil {
		result.Outcome = failed("input.compare_candidate_invalid", ExecutionFailure)
		return r
	}
	result.CandidateFingerprintSHA256 = publicDigest(candidate.Raw)
	if len(r.ServerChain) == 0 || r.ServerChain[0] == nil {
		return r
	}
	observed := r.ServerChain[0]
	result.ObservedFingerprintSHA256 = publicDigest(observed.Raw)
	if bytes.Equal(candidate.Raw, observed.Raw) {
		result.Outcome = passed("comparison.matched")
		return r
	}
	result.Outcome = failed("comparison.different", VerificationFailure)
	add := func(field string, left, right []string) {
		if !slices.Equal(left, right) {
			result.Differences = append(result.Differences, CertificateDifference{field, left, right})
		}
	}
	scalar := func(field, left, right string) { add(field, []string{left}, []string{right}) }
	scalar("subject", candidate.Subject.String(), observed.Subject.String())
	scalar("issuer", candidate.Issuer.String(), observed.Issuer.String())
	scalar("serial_number", candidate.SerialNumber.String(), observed.SerialNumber.String())
	add("dns_names", comparisonSet(candidate.DNSNames), comparisonSet(observed.DNSNames))
	ips := func(c *x509.Certificate) []string {
		var out []string
		for _, v := range c.IPAddresses {
			out = append(out, v.String())
		}
		return comparisonSet(out)
	}
	add("ip_addresses", ips(candidate), ips(observed))
	add("email_addresses", comparisonSet(candidate.EmailAddresses), comparisonSet(observed.EmailAddresses))
	uris := func(c *x509.Certificate) []string {
		var out []string
		for _, v := range c.URIs {
			if v != nil {
				out = append(out, v.String())
			}
		}
		return comparisonSet(out)
	}
	add("uris", uris(candidate), uris(observed))
	scalar("not_before", candidate.NotBefore.UTC().Format(time.RFC3339), observed.NotBefore.UTC().Format(time.RFC3339))
	scalar("not_after", candidate.NotAfter.UTC().Format(time.RFC3339), observed.NotAfter.UTC().Format(time.RFC3339))
	scalar("public_key_spki_sha256", publicDigest(candidate.RawSubjectPublicKeyInfo), publicDigest(observed.RawSubjectPublicKeyInfo))
	if len(result.Differences) == 0 {
		scalar("certificate_der", result.CandidateFingerprintSHA256, result.ObservedFingerprintSHA256)
	}
	return r
}
