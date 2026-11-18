package check

import (
	"context"
	"crypto/x509"
	"errors"
	"time"
)

// Purpose 將站台用途與 CA 路徑明確分開。
type Purpose uint8

const (
	ServerPurpose Purpose = iota
	CAPurpose
)

// TrustOptions 的 Roots 必須先成功取得，不能以 nil 靜默改變信任來源。
type TrustOptions struct {
	Roots                    *x509.CertPool
	Intermediates            *x509.CertPool
	IntermediateCertificates []*x509.Certificate
	Now                      time.Time
	DNSName                  string
	Purpose                  Purpose
	SystemRoots              bool
}

// TrustResult 的 Chains 只保存驗證成功的鏈，不捏造失敗後的鏈。
type TrustResult struct {
	Outcome     Outcome
	Hostname    Outcome
	ServerUsage Outcome
	Chains      [][]*x509.Certificate
}

// VerifyTrust 供本機與後續遠端共用明確的驗證契約。
func VerifyTrust(ctx context.Context, cert *x509.Certificate, opts TrustOptions) TrustResult {
	result := TrustResult{Hostname: skipped("certificate.hostname_not_provided"), ServerUsage: skipped("certificate.not_applicable")}
	if ctx.Err() != nil {
		result.Outcome = failed("trust.canceled", ExecutionFailure)
		return result
	}
	if cert == nil || len(cert.Raw) == 0 || opts.Now.IsZero() {
		result.Outcome = failed("trust.invalid_input", ExecutionFailure)
		return result
	}
	if opts.Roots == nil {
		result.Outcome = failed("trust.roots_unavailable", ExecutionFailure)
		return result
	}
	if opts.Purpose != ServerPurpose && opts.Purpose != CAPurpose {
		result.Outcome = failed("trust.invalid_purpose", ExecutionFailure)
		return result
	}
	if opts.Purpose == CAPurpose {
		if constraints := checkCAConstraints(cert); constraints.Status == Failed {
			result.Outcome = constraints
			return result
		}
	} else {
		result.ServerUsage = skipped("trust.chain_unavailable")
	}
	if validity := checkValidity(cert, opts.Now); validity.Status == Failed {
		result.Outcome = validity
		return result
	}
	verifyOpts := x509.VerifyOptions{Roots: opts.Roots, Intermediates: opts.Intermediates, CurrentTime: opts.Now, DNSName: opts.DNSName, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if opts.Purpose == CAPurpose {
		verifyOpts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
		verifyOpts.DNSName = ""
	}
	chains, err := verifyWithPlatform(ctx, cert, opts, verifyOpts)
	if ctx.Err() != nil {
		result.Outcome = failed("trust.canceled", ExecutionFailure)
		return result
	}
	if err != nil {
		result.Outcome = classifyTrustError(err, opts.Now)
		var invalid x509.CertificateInvalidError
		if opts.Purpose == ServerPurpose && errors.As(err, &invalid) && invalid.Reason == x509.IncompatibleUsage {
			result.ServerUsage = failed("trust.server_usage_invalid", VerificationFailure)
		}
		var hostname x509.HostnameError
		if opts.Purpose == ServerPurpose && opts.DNSName != "" && errors.As(err, &hostname) {
			result.Hostname = failed("trust.hostname_mismatch", VerificationFailure)
		}
		return result
	}
	if len(chains) == 0 {
		result.Outcome = failed("trust.empty_verified_chain", ExecutionFailure)
		return result
	}
	result.Outcome = passed("trust.verified")
	result.Chains = chains
	if opts.Purpose == ServerPurpose {
		result.ServerUsage = passed("trust.server_usage_valid")
		if opts.DNSName != "" {
			result.Hostname = passed("trust.hostname_valid")
		}
	}
	return result
}

// trustFailure 避免把平台診斷或暫存路徑帶進公開結果。
type trustFailure struct {
	code  string
	class FailureClass
}

func (e trustFailure) Error() string { return e.code }

func classifyTrustError(err error, now time.Time) Outcome {
	var platform trustFailure
	if errors.As(err, &platform) {
		return failed(platform.code, platform.class)
	}
	var roots x509.SystemRootsError
	if errors.As(err, &roots) {
		return failed("trust.roots_unavailable", ExecutionFailure)
	}
	var unknown x509.UnknownAuthorityError
	if errors.As(err, &unknown) {
		return failed("trust.unknown_authority", VerificationFailure)
	}
	var hostname x509.HostnameError
	if errors.As(err, &hostname) {
		return failed("trust.hostname_mismatch", VerificationFailure)
	}
	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) {
		switch invalid.Reason {
		case x509.Expired:
			if invalid.Cert != nil && now.Before(invalid.Cert.NotBefore) {
				return failed("trust.chain_not_yet_valid", VerificationFailure)
			}
			if invalid.Cert != nil && now.After(invalid.Cert.NotAfter) {
				return failed("trust.chain_expired", VerificationFailure)
			}
			return failed("trust.platform_time_policy", VerificationFailure)
		case x509.IncompatibleUsage:
			return failed("trust.server_usage_invalid", VerificationFailure)
		case x509.NotAuthorizedToSign:
			return failed("trust.issuer_not_authorized", VerificationFailure)
		case x509.CANotAuthorizedForThisName, x509.UnconstrainedName:
			return failed("trust.name_constraints_violated", VerificationFailure)
		case x509.TooManyIntermediates:
			return failed("trust.path_length_exceeded", VerificationFailure)
		case x509.NameMismatch:
			return failed("trust.issuer_name_mismatch", VerificationFailure)
		case x509.TooManyConstraints:
			return failed("trust.constraint_limit_exceeded", VerificationFailure)
		case x509.CANotAuthorizedForExtKeyUsage:
			return failed("trust.ca_usage_not_authorized", VerificationFailure)
		case x509.NoValidChains:
			return failed("trust.no_valid_chains", VerificationFailure)
		default:
			return failed("trust.constraints_failed", VerificationFailure)
		}
	}
	var critical x509.UnhandledCriticalExtension
	if errors.As(err, &critical) {
		return failed("trust.unhandled_critical_extension", VerificationFailure)
	}
	// 未知平台錯誤只說明已知驗證失敗，不捏造確切根因。
	return failed("trust.verification_failed", VerificationFailure)
}
