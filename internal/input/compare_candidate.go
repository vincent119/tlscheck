package input

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"io"
	"unicode"

	"github.com/vincent119/tlscheck/internal/model"
)

// CompareCandidateInvalid 不回傳候選內容或底層檔案錯誤。
const CompareCandidateInvalid model.IssueCode = "input.compare_candidate_invalid"

// ReadCompareCandidate 僅解析公開憑證，不進入通用私鑰／容器／密碼流程。
func (p *Parser) ReadCompareCandidate(ctx context.Context, path string) (candidate *x509.Certificate, issue model.IssueCode) {
	if ctx.Err() != nil {
		return nil, CompareCandidateInvalid
	}
	f, err := p.open(path)
	if err != nil {
		return nil, CompareCandidateInvalid
	}
	defer func() {
		if f.Close() != nil {
			candidate = nil
			issue = CompareCandidateInvalid
		}
	}()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, CompareCandidateInvalid
	}
	data, err := io.ReadAll(io.LimitReader(contextReader{ctx: ctx, reader: f}, MaxFileSize+1))
	defer clear(data)
	if err != nil || len(data) > MaxFileSize || ctx.Err() != nil {
		return nil, CompareCandidateInvalid
	}
	return selectCompareCandidate(ctx, data)
}

func selectCompareCandidate(ctx context.Context, data []byte) (*x509.Certificate, model.IssueCode) {
	var leaf *x509.Certificate
	accept := func(der []byte) bool {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return false
		}
		if cert.IsCA {
			return true
		}
		if leaf != nil {
			return bytes.Equal(leaf.Raw, cert.Raw)
		}
		// 複製選中DER，避免保留整份候選鏈的底層緩衝區。
		leaf, err = x509.ParseCertificate(bytes.Clone(cert.Raw))
		return err == nil
	}
	if bytes.Contains(data, []byte("-----BEGIN ")) {
		const marker = "-----BEGIN "
		for {
			data = bytes.TrimLeftFunc(data, unicode.IsSpace)
			if len(data) == 0 {
				break
			}
			if ctx.Err() != nil || !bytes.HasPrefix(data, []byte("-----BEGIN CERTIFICATE-----")) {
				return nil, CompareCandidateInvalid
			}
			end := len(data)
			if next := bytes.Index(data[len(marker):], []byte(marker)); next >= 0 {
				end = len(marker) + next
			}
			block, rest := pem.Decode(data[:end])
			if block == nil {
				return nil, CompareCandidateInvalid
			}
			valid := block.Type == "CERTIFICATE" && len(block.Headers) == 0 && len(bytes.TrimSpace(rest)) == 0 && accept(block.Bytes)
			clear(block.Bytes)
			if !valid {
				return nil, CompareCandidateInvalid
			}
			data = data[end:]
		}
	} else if !accept(data) {
		return nil, CompareCandidateInvalid
	}
	if leaf == nil || ctx.Err() != nil {
		return nil, CompareCandidateInvalid
	}
	return leaf, ""
}
