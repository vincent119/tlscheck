package check

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/vincent119/tlscheck/internal/model"
)

// RootProvider 可注入測試根，不修改系統信任庫。
type RootProvider func(context.Context) (*x509.CertPool, error)

// Analyzer 保存固定時刻及可重用依賴，不保存 request context。
type Analyzer struct {
	now         time.Time
	roots       RootProvider
	systemRoots bool
	options     CertificateOptions
}

// LocalResult 保留每張獨立憑證及無法歸屬單張憑證的執行錯誤。
type LocalResult struct {
	Certificates []CertificateResult
	Issues       []Outcome
}

// Failure 返回本機結果最高失敗類別，提醒與未執行不造成失敗。
func (r LocalResult) Failure() FailureClass {
	var severity FailureClass
	add := func(outcome Outcome) {
		if outcome.Class > severity {
			severity = outcome.Class
		}
	}
	for _, issue := range r.Issues {
		add(issue)
	}
	for _, cert := range r.Certificates {
		if cert.ExpiryPolicy != nil {
			add(cert.ExpiryPolicy.Outcome)
		}
		for _, outcome := range []Outcome{cert.Parse, cert.Validity, cert.CAConstraints, cert.Linkage, cert.Trust.Outcome, cert.Trust.Hostname, cert.Trust.ServerUsage} {
			add(outcome)
		}
	}
	return severity
}

// NewAnalyzer 的 nil provider 表示真正系統根；now 由呼叫者固定。
func NewAnalyzer(now time.Time, provider RootProvider) *Analyzer {
	return NewAnalyzerWithOptions(now, provider, CertificateOptions{ExpiryWarningDays: 30})
}

// NewAnalyzerWithOptions 保持原系統信任語意，僅帶入提醒門檻。
func NewAnalyzerWithOptions(now time.Time, provider RootProvider, options CertificateOptions) *Analyzer {
	return &Analyzer{now: now, roots: provider, systemRoots: provider == nil, options: options}
}

// AnalyzeLocal 接收已解析憑證，系統 CA 驗證只允許已核准的平台唯讀例外。
func (a *Analyzer) AnalyzeLocal(ctx context.Context, certs []model.ParsedCertificate) LocalResult {
	var result LocalResult
	if len(certs) == 0 {
		return result
	}
	if ctx.Err() != nil {
		result.Issues = append(result.Issues, failed("trust.canceled", ExecutionFailure))
		return result
	}
	if a.now.IsZero() {
		result.Issues = append(result.Issues, failed("trust.invalid_time", ExecutionFailure))
		return result
	}
	unique := make([]*x509.Certificate, 0, len(certs))
	byRaw := make(map[string]int, len(certs))
	bySubject := make(map[string][]int, len(certs))
	for _, parsed := range certs {
		if ctx.Err() != nil {
			result.Issues = append(result.Issues, failed("trust.canceled", ExecutionFailure))
			return result
		}
		cert := parsed.Certificate
		info, err := AnalyzeCertificateWithOptions(cert, a.now, a.options)
		if err != nil {
			result.Issues = append(result.Issues, failed("certificate.invalid_input", ExecutionFailure))
			continue
		}
		key := string(cert.Raw)
		if index, ok := byRaw[key]; ok {
			result.Certificates[index].Sources = append(result.Certificates[index].Sources, parsed.Source)
			continue
		}
		index := len(unique)
		byRaw[key] = index
		unique = append(unique, cert)
		bySubject[string(cert.RawSubject)] = append(bySubject[string(cert.RawSubject)], index)
		role := Site
		constraints := skipped("certificate.not_applicable")
		if cert.IsCA {
			role = CA
			constraints = checkCAConstraints(cert)
		}
		result.Certificates = append(result.Certificates, CertificateResult{Info: info, Role: role, Sources: []model.SourceRef{parsed.Source}, Parse: passed("certificate.parsed"), Validity: checkValidity(cert, a.now), CAConstraints: constraints, Linkage: skipped("certificate.issuer_not_supplied"), Trust: TrustResult{Outcome: skipped("trust.not_performed"), Hostname: skipped("certificate.hostname_not_provided"), ServerUsage: skipped("trust.not_performed")}})
	}
	if len(unique) == 0 {
		return result
	}
	provider := a.roots
	if provider == nil {
		provider = SystemRoots
	}
	roots, rootErr := provider(ctx)
	intermediates := x509.NewCertPool()
	var intermediateCertificates []*x509.Certificate
	for _, cert := range unique {
		if cert.IsCA {
			intermediates.AddCert(cert)
			intermediateCertificates = append(intermediateCertificates, cert)
		}
	}
	for i, cert := range unique {
		if ctx.Err() != nil {
			result.Issues = append(result.Issues, failed("trust.canceled", ExecutionFailure))
			return result
		}
		item := &result.Certificates[i]
		item.Linkage = skipped("certificate.issuer_not_supplied")
		validLink := false
		for _, parentIndex := range bySubject[string(cert.RawIssuer)] {
			if ctx.Err() != nil {
				result.Issues = append(result.Issues, failed("trust.canceled", ExecutionFailure))
				return result
			}
			parent := unique[parentIndex]
			// 自簽需真的驗過簽章，不能只用 Subject 與 Issuer 相同推論。
			if parentIndex == i && !item.Info.SelfSigned {
				continue
			}
			valid := cert.CheckSignatureFrom(parent) == nil
			if parentIndex == i {
				// 自簽站台的自我簽章不要求 CA 權限；是否可信仍交由系統驗證。
				valid = item.Info.SelfSigned
			}
			item.Links = append(item.Links, IssuerLink{IssuerFingerprint: result.Certificates[parentIndex].Info.FingerprintSHA256, SignatureValid: valid})
			validLink = validLink || valid
		}
		if validLink {
			item.Linkage = passed("certificate.issuer_link_valid")
		} else if len(item.Links) > 0 {
			item.Linkage = failed("certificate.issuer_link_invalid", VerificationFailure)
		}
		purpose := ServerPurpose
		if item.Role == CA {
			purpose = CAPurpose
		}
		if rootErr != nil || roots == nil {
			item.Trust = TrustResult{Outcome: failed("trust.roots_unavailable", ExecutionFailure), Hostname: skipped("certificate.hostname_not_provided"), ServerUsage: skipped("trust.chain_unavailable")}
			if purpose == CAPurpose {
				item.Trust.ServerUsage = skipped("certificate.not_applicable")
			}
			continue
		}
		item.Trust = VerifyTrust(ctx, cert, TrustOptions{Roots: roots, Intermediates: intermediates, IntermediateCertificates: intermediateCertificates, Now: a.now, Purpose: purpose, SystemRoots: a.systemRoots})
	}
	return result
}

// SystemRoots 保留平台 trust handle，不用 Subjects 是否為空判斷可用性。
func SystemRoots(ctx context.Context) (*x509.CertPool, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return x509.SystemCertPool()
}
