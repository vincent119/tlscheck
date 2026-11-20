package report

import "github.com/vincent119/tlscheck/internal/check"

// Difference 只投影已清理的公開差異，不保存憑證原始DER。
type Difference struct {
	Field     string   `json:"field"`
	Candidate []string `json:"candidate"`
	Observed  []string `json:"observed"`
}

// Comparison 僅在顯式比對時提供，與信任結果獨立。
type Comparison struct {
	CandidateSource            string       `json:"candidate_source"`
	CandidateFingerprintSHA256 string       `json:"candidate_fingerprint_sha256"`
	ObservedFingerprintSHA256  *string      `json:"observed_fingerprint_sha256"`
	Result                     Result       `json:"result"`
	Differences                []Difference `json:"differences"`
}

func (b *builder) comparison(c *check.CertificateComparison) *Comparison {
	result := &Comparison{CandidateSource: Safe(c.CandidateSource), CandidateFingerprintSHA256: Safe(c.CandidateFingerprintSHA256), ObservedFingerprintSHA256: optional(c.ObservedFingerprintSHA256), Result: b.outcome(c.Outcome), Differences: []Difference{}}
	for _, diff := range c.Differences {
		item := Difference{Field: Safe(diff.Field), Candidate: []string{}, Observed: []string{}}
		sanitize := func(values []string) []string {
			out := make([]string, 0, len(values))
			for _, v := range values {
				if diff.Field == "uris" {
					v = safeURI(v, false)
				}
				out = append(out, Safe(v))
			}
			return out
		}
		item.Candidate = sanitize(diff.Candidate)
		item.Observed = sanitize(diff.Observed)
		result.Differences = append(result.Differences, item)
	}
	return result
}
