package report

import (
	"strconv"

	"github.com/vincent119/tlscheck/internal/check"
	"github.com/vincent119/tlscheck/internal/i18n"
)

// expiryPolicy沿用既有Check／Result欄位，參數只取typed公開政策，不改JSON schema。
func (b *builder) expiryPolicy(policy check.ExpiryPolicyResult) Check {
	result := b.outcome(policy.Outcome)
	result.Message = b.t.Text(policy.Outcome.Code, i18n.Params{"Index": strconv.Itoa(policy.CertificateIndex), "Fingerprint": Safe(policy.FingerprintSHA256), "Days": strconv.Itoa(policy.WarningDays)})
	return Check{Name: "expiry_policy", Result: result}
}
