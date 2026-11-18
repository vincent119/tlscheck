//go:build !darwin

package check

import (
	"context"
	"crypto/x509"
)

func verifyWithPlatform(ctx context.Context, cert *x509.Certificate, opts TrustOptions, verifyOpts x509.VerifyOptions) ([][]*x509.Certificate, error) {
	if err := ctx.Err(); err != nil {
		return nil, trustFailure{code: "trust.canceled", class: ExecutionFailure}
	}
	return cert.Verify(verifyOpts)
}
