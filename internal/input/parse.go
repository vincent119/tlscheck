package input

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"strings"
	"unicode"

	"github.com/vincent119/tlscheck/internal/model"
)

func parseData(ctx context.Context, data []byte, source model.SourceRef, result *model.InputResult) {
	if bytes.Contains(data, []byte("-----BEGIN ")) {
		source.Encoding = "PEM"
		parsePEM(ctx, data, source, result)
		return
	}
	source.Encoding = "DER"
	parseDER(data, "", source, result)
}

func parsePEM(ctx context.Context, data []byte, source model.SourceRef, result *model.InputResult) {
	const marker = "-----BEGIN "
	blockIndex := 0
	for {
		data = bytes.TrimLeftFunc(data, unicode.IsSpace)
		if len(data) == 0 {
			return
		}
		if ctx.Err() != nil {
			addIssue(result, model.Canceled, source)
			return
		}
		start := bytes.Index(data, []byte(marker))
		if start < 0 {
			addIssue(result, model.InvalidData, source)
			return
		}
		if len(bytes.TrimSpace(data[:start])) != 0 {
			addIssue(result, model.InvalidData, source)
		}
		data = data[start:]
		blockIndex++
		source.Block = blockIndex
		// 先隔離到下一個 BEGIN，不讓 pem.Decode 略過損壞區塊後回傳別張憑證。
		next := bytes.Index(data[len(marker):], []byte(marker))
		end := len(data)
		if next >= 0 {
			end = len(marker) + next
		}
		candidate := data[:end]
		data = data[end:]
		block, rest := pem.Decode(candidate)
		if block == nil {
			addIssue(result, model.InvalidData, source)
			continue
		}
		if encryptedPEM(block) {
			addIssue(result, model.EncryptedKey, source)
		} else {
			switch block.Type {
			case "CERTIFICATE", "RSA PRIVATE KEY", "EC PRIVATE KEY", "PRIVATE KEY":
				parseDER(block.Bytes, block.Type, source, result)
			default:
				addIssue(result, model.UnsupportedBlock, source)
			}
		}
		if len(bytes.TrimSpace(rest)) != 0 {
			addIssue(result, model.InvalidData, source)
		}
	}
}

func encryptedPEM(block *pem.Block) bool {
	if block.Type == "ENCRYPTED PRIVATE KEY" {
		return true
	}
	if !strings.Contains(block.Type, "PRIVATE KEY") {
		return false
	}
	for name, value := range block.Headers {
		if strings.EqualFold(name, "DEK-Info") || (strings.EqualFold(name, "Proc-Type") && strings.Contains(strings.ToUpper(value), "ENCRYPTED")) {
			return true
		}
	}
	return false
}

func parseDER(data []byte, kind string, source model.SourceRef, result *model.InputResult) {
	// 部分 x509 私鑰 parser 會略過尾端資料，必須先保存此解析錯誤。
	var object asn1.RawValue
	rest, err := asn1.Unmarshal(data, &object)
	if err != nil {
		addIssue(result, model.InvalidData, source)
		return
	}
	if len(rest) != 0 {
		addIssue(result, model.InvalidData, source)
		data = object.FullBytes
	}
	if kind == "" || kind == "CERTIFICATE" {
		if cert, err := x509.ParseCertificate(data); err == nil {
			result.Certificates = append(result.Certificates, model.ParsedCertificate{Certificate: cert, Source: source})
			return
		}
	}
	if kind == "" || kind == "RSA PRIVATE KEY" {
		if key, err := x509.ParsePKCS1PrivateKey(data); err == nil {
			appendKey(result, source, "PKCS#1", key)
			return
		}
	}
	if kind == "" || kind == "EC PRIVATE KEY" {
		if key, err := x509.ParseECPrivateKey(data); err == nil {
			appendKey(result, source, "SEC1", key)
			return
		}
	}
	if kind == "" || kind == "PRIVATE KEY" {
		if key, err := x509.ParsePKCS8PrivateKey(data); err == nil {
			switch key := key.(type) {
			case *rsa.PrivateKey:
				appendKey(result, source, "PKCS#8", key)
			case *ecdsa.PrivateKey:
				appendKey(result, source, "PKCS#8", key)
			case ed25519.PrivateKey:
				appendKey(result, source, "PKCS#8", key)
			default:
				addIssue(result, model.UnsupportedKey, source)
			}
			return
		}
	}
	if kind == "" && encryptedDER(data) {
		addIssue(result, model.EncryptedKey, source)
		return
	}
	addIssue(result, model.InvalidData, source)
}

func appendKey(result *model.InputResult, source model.SourceRef, format string, key crypto.Signer) {
	result.Keys = append(result.Keys, model.NewParsedKey(source, format, key))
}

func encryptedDER(data []byte) bool {
	var envelope struct {
		Algorithm pkix.AlgorithmIdentifier
		Data      []byte
	}
	rest, err := asn1.Unmarshal(data, &envelope)
	return err == nil && len(rest) == 0 && len(envelope.Algorithm.Algorithm) > 0 && len(envelope.Data) > 0
}
