package input

import (
	"context"
	"errors"

	"github.com/vincent119/tlscheck/internal/containers"
	"github.com/vincent119/tlscheck/internal/model"
)

func containerCode(ctx context.Context, err error) model.IssueCode {
	switch {
	case ctx.Err() != nil:
		return model.Canceled
	case errors.Is(err, containers.ErrLimit):
		return model.ContainerLimit
	case errors.Is(err, containers.ErrIntegrity):
		return model.ContainerIntegrity
	case errors.Is(err, containers.ErrUnsupported):
		return model.ContainerUnsupported
	}
	return model.InvalidData
}
func parseP7BData(ctx context.Context, data []byte, source model.SourceRef, result *model.InputResult) {
	certs, issues, err := containers.DecodeP7B(ctx, data)
	if err != nil {
		addIssue(result, containerCode(ctx, err), source)
		return
	}
	for _, c := range certs {
		result.Certificates = append(result.Certificates, model.ParsedCertificate{Certificate: c, Source: source})
	}
	for _, problem := range issues {
		addIssue(result, containerCode(ctx, problem), source)
	}
}
func parsePFXData(ctx context.Context, data []byte, source model.SourceRef, result *model.InputResult, provider PasswordProvider) {
	var password []byte
	if provider != nil {
		var err error
		password, err = provider(ctx, source)
		if err != nil {
			clear(password)
			code := model.PasswordUnavailable
			if ctx.Err() != nil || errors.Is(err, context.Canceled) {
				code = model.Canceled
			}
			addIssue(result, code, source)
			return
		}
	}
	defer clear(password)
	if !containers.PasswordSupported(password) {
		addIssue(result, model.PasswordUnsupported, source)
		return
	}
	decoded, err := containers.Decode(ctx, data, password)
	if err != nil {
		addIssue(result, containerCode(ctx, err), source)
		return
	}
	for _, c := range decoded.Certificates() {
		result.Certificates = append(result.Certificates, model.ParsedCertificate{Certificate: c, Source: source})
	}
	if key := decoded.Signer(); key != nil {
		appendKey(result, source, "PKCS#12", key)
	}
}
