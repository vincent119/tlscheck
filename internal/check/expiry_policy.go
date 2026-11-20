package check

// ExpiryWarningFailureCode 區分明確啟用的到期政策與原有有效期驗證。
const ExpiryWarningFailureCode = "policy.expiry_warning_failed"

// ExpiryPolicyResult 只保存可公開的憑證位置及門檻，不直接序列化為報告。
type ExpiryPolicyResult struct {
	CertificateIndex  int
	FingerprintSHA256 string
	WarningDays       int
	Outcome           Outcome
}

func expiryPolicy(info CertificateInfo, index, days int) *ExpiryPolicyResult {
	// 提醒已由原分析器按固定Now與門檻計算；不得以顯示天數重新取整判斷。
	if days <= 0 || !info.ExpiringSoon || info.Expired {
		return nil
	}
	return &ExpiryPolicyResult{CertificateIndex: index, FingerprintSHA256: info.FingerprintSHA256, WarningDays: days, Outcome: failed(ExpiryWarningFailureCode, VerificationFailure)}
}

// WithExpiryPolicy 以已驗證的提醒天數套用政策，保留本機去重與全部來源，不修改呼叫者的切片。
func (r LocalResult) WithExpiryPolicy(days int) LocalResult {
	r.Certificates = append([]CertificateResult(nil), r.Certificates...)
	for i := range r.Certificates {
		r.Certificates[i].ExpiryPolicy = expiryPolicy(r.Certificates[i].Info, i, days)
	}
	return r
}

// WithExpiryPolicy 逐觀測位置套用政策，不把同憑證在不同目標的觀測合併。
func (r RemoteResult) WithExpiryPolicy(days int) RemoteResult {
	r.ExpiryPolicies = nil
	for i, info := range r.Certificates {
		if p := expiryPolicy(info, i, days); p != nil {
			r.ExpiryPolicies = append(r.ExpiryPolicies, *p)
		}
	}
	return r
}
