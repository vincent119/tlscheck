package containers

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
)

type p7bResult struct {
	certs  []*x509.Certificate
	issues []error
}

func parseP7B(ctx context.Context, data []byte, l limits) (p7bResult, error) {
	result := p7bResult{}
	if len(data) > l.input {
		return result, errLimit
	}
	if block, rest := pem.Decode(data); block != nil {
		if !bytes.HasPrefix(data, []byte("-----BEGIN PKCS7-----")) {
			return result, errStructure
		}
		if block.Type != "PKCS7" || len(block.Headers) != 0 || len(rest) != 0 {
			return result, errUnsupported
		}
		data = block.Bytes
	}
	b := &budget{ctx: ctx, limits: l}
	if err := b.inspect(data, 1); err != nil {
		return result, err
	}
	var ci contentInfo
	if unmarshal(data, &ci) != nil || !ci.ContentType.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}) {
		return result, errUnsupported
	}
	values, err := b.elements(ci.Content.Bytes, 3, 6)
	if err != nil {
		return result, err
	}
	if len(values) < 5 {
		return result, errStructure
	}
	var version int
	if unmarshal(values[0].FullBytes, &version) != nil || (version != 1 && version != 3 && version != 4 && version != 5) {
		return result, errUnsupported
	}
	if values[1].Tag != asn1.TagSet || len(values[1].Bytes) != 0 {
		return result, errUnsupported
	}
	var inner contentInfo
	if unmarshal(values[2].FullBytes, &inner) != nil || !inner.ContentType.Equal(oidDataContentType) || len(inner.Content.FullBytes) != 0 {
		return result, errUnsupported
	}
	certs := values[3]
	if certs.Class != 2 || certs.Tag != 0 || !certs.IsCompound {
		return result, errStructure
	}
	signers := values[len(values)-1]
	if signers.Class != 0 || signers.Tag != asn1.TagSet || len(signers.Bytes) != 0 {
		return result, errUnsupported
	}
	if len(values) == 6 {
		if values[4].Class != 2 || values[4].Tag != 1 {
			return result, errStructure
		}
		result.issues = append(result.issues, errUnsupported)
	}
	rest := certs.Bytes
	count := 0
	for len(rest) > 0 {
		if err := ctx.Err(); err != nil {
			return p7bResult{}, err
		}
		count++
		if count > l.certificates {
			return p7bResult{}, errLimit
		}
		var raw asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &raw)
		if err != nil {
			return p7bResult{}, errStructure
		}
		if raw.Class != 0 || raw.Tag != asn1.TagSequence {
			result.issues = append(result.issues, errUnsupported)
			continue
		}
		c, err := x509.ParseCertificate(raw.FullBytes)
		if err != nil {
			result.issues = append(result.issues, errStructure)
			continue
		}
		result.certs = append(result.certs, c)
	}
	if count == 0 {
		return result, errUnsupported
	}
	return result, nil
}
