package containers

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"unicode/utf8"
)

var errLimit = errors.New("容器資源超限")
var errUnsupported = errors.New("容器內容不支援")
var errIntegrity = errors.New("容器完整性或解密失敗")
var errStructure = errors.New("容器結構無效")

type limits struct{ input, decrypted, certificates, bags, depth, password, iterations, work int }

func proposedLimits() limits {
	return limits{10 << 20, 16 << 20, 256, 512, 32, 4 << 10, 1000000, 3000000}
}

type observations struct{ calls, work, decrypted, certs, bags, depth int }
type budget struct {
	ctx      context.Context
	limits   limits
	observed observations
}

func (b *budget) check() error { return b.ctx.Err() }
func (b *budget) charge(iterations, output, hashBytes int) error {
	if err := b.check(); err != nil {
		return err
	}
	if iterations <= 0 || iterations > b.limits.iterations || output <= 0 || hashBytes <= 0 || output > 64 {
		return errLimit
	}
	blocks := (output-1)/hashBytes + 1
	if b.observed.work > b.limits.work || iterations > (b.limits.work-b.observed.work)/blocks {
		return errLimit
	}
	b.observed.work += iterations * blocks
	b.observed.calls++
	return nil
}

// 包含各次解包／解密的繼承深度；密文與憑證 OCTET STRING 在容器層視為葉節點。
func (b *budget) inspect(data []byte, depth int) error {
	if err := b.check(); err != nil {
		return err
	}
	rest := data
	for len(rest) > 0 {
		var v asn1.RawValue
		next, err := asn1.Unmarshal(rest, &v)
		if err != nil {
			return errStructure
		}
		if v.IsCompound {
			if depth > b.limits.depth {
				return errLimit
			}
			b.observed.depth = max(b.observed.depth, depth)
			if err := b.inspect(v.Bytes, depth+1); err != nil {
				return err
			}
		}
		rest = next
	}
	return nil
}
func (b *budget) elements(data []byte, depth, maximum int) ([]asn1.RawValue, error) {
	if err := b.inspect(data, depth); err != nil {
		return nil, err
	}
	var root asn1.RawValue
	rest, err := asn1.Unmarshal(data, &root)
	if err != nil || len(rest) != 0 || root.Tag != asn1.TagSequence || root.Class != 0 || !root.IsCompound {
		return nil, errStructure
	}
	children := []asn1.RawValue{}
	rest = root.Bytes
	for len(rest) > 0 {
		if len(children) >= maximum {
			return nil, errLimit
		}
		var v asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &v)
		if err != nil {
			return nil, errStructure
		}
		children = append(children, v)
	}
	return children, nil
}
func nullOrAbsent(v asn1.RawValue) bool {
	return len(v.FullBytes) == 0 || (v.Class == 0 && v.Tag == asn1.TagNull && !v.IsCompound && len(v.Bytes) == 0)
}
func (b *budget) decrypt(info decryptable, password []byte) ([]byte, error) {
	alg := info.Algorithm()
	if !alg.Algorithm.Equal(oidPBES2) {
		return nil, errUnsupported
	}
	var params pbes2Params
	if unmarshal(alg.Parameters.FullBytes, &params) != nil || !params.Kdf.Algorithm.Equal(oidPBKDF2) || !params.EncryptionScheme.Algorithm.Equal(oidAES256CBC) {
		return nil, errUnsupported
	}
	var k pbkdf2Params
	if unmarshal(params.Kdf.Parameters.FullBytes, &k) != nil {
		return nil, errStructure
	}
	if k.Salt.Class != 0 || k.Salt.Tag != asn1.TagOctetString || k.Salt.IsCompound || len(k.Salt.Bytes) == 0 || len(k.Salt.Bytes) > 64 || !k.Prf.Algorithm.Equal(oidHmacWithSHA256) || !nullOrAbsent(k.Prf.Parameters) || (k.KeyLength != 0 && k.KeyLength != 32) {
		return nil, errUnsupported
	}
	iv := params.EncryptionScheme.Parameters
	if iv.Class != 0 || iv.Tag != asn1.TagOctetString || iv.IsCompound || len(iv.Bytes) != 16 {
		return nil, errStructure
	}
	cipher := info.Data()
	if len(cipher) == 0 || len(cipher)%16 != 0 {
		return nil, errStructure
	}
	// CBC 配置上限以密文長度保守預留，避免在配置後才發現超限。
	if b.observed.decrypted > b.limits.decrypted || len(cipher) > b.limits.decrypted-b.observed.decrypted {
		return nil, errLimit
	}
	if err := b.charge(k.Iterations, 32, 32); err != nil {
		return nil, err
	}
	data, err := pbDecrypt(info, password)
	if err != nil {
		return nil, errIntegrity
	}
	b.observed.decrypted += len(data)
	return data, nil
}

// 結果不含名稱屬性或可序列化私鑰；失敗一律交付空物件集合。
type controlledResult struct {
	certs []*x509.Certificate
	key   crypto.Signer
}
type wireBag struct {
	Id         asn1.ObjectIdentifier
	Value      asn1.RawValue `asn1:"explicit,tag:0"`
	Attributes asn1.RawValue `asn1:"optional"`
}

func controlledDecode(ctx context.Context, data []byte, password string, l limits) (controlledResult, observations, error) {
	b := &budget{ctx: ctx, limits: l}
	result, err := decodeControlled(b, data, password)
	if err != nil {
		return controlledResult{}, b.observed, err
	}
	return result, b.observed, nil
}
func decodeControlled(b *budget, data []byte, password string) (controlledResult, error) {
	result := controlledResult{}
	if len(data) > b.limits.input || len(password) > b.limits.password {
		return result, errLimit
	}
	if !utf8.ValidString(password) {
		return result, errUnsupported
	}
	if err := b.inspect(data, 1); err != nil {
		return result, err
	}
	var outer asn1.RawValue
	rest, err := asn1.Unmarshal(data, &outer)
	if err != nil || len(rest) != 0 {
		return result, errStructure
	}
	var pfx pfxPdu
	if unmarshal(data, &pfx) != nil || pfx.Version != 3 || !pfx.AuthSafe.ContentType.Equal(oidDataContentType) {
		return result, errUnsupported
	}
	var authenticated []byte
	if unmarshal(pfx.AuthSafe.Content.Bytes, &authenticated) != nil {
		return result, errStructure
	}
	m := pfx.MacData
	if !m.Mac.Algorithm.Algorithm.Equal(oidSHA256) || !nullOrAbsent(m.Mac.Algorithm.Parameters) || len(m.Mac.Digest) != 32 || len(m.MacSalt) == 0 || len(m.MacSalt) > 64 {
		return result, errUnsupported
	}
	encoded, err := bmpStringZeroTerminated(password)
	if err != nil {
		return result, errUnsupported
	}
	defer clear(encoded)
	if err := b.charge(m.Iterations, 32, 32); err != nil {
		return result, err
	}
	if verifyMac(&m, authenticated, encoded) != nil {
		return result, errIntegrity
	}
	// PFX → ContentInfo → [0] → OCTET STRING → AuthenticatedSafe，不能歸零計深度。
	infos, err := b.elements(authenticated, 5, b.limits.bags)
	if err != nil {
		return result, err
	}
	for _, raw := range infos {
		if err := b.check(); err != nil {
			return result, err
		}
		var ci contentInfo
		if unmarshal(raw.FullBytes, &ci) != nil {
			return result, errStructure
		}
		var contents []byte
		depth := 9
		confidential := false
		switch {
		case ci.ContentType.Equal(oidDataContentType):
			if unmarshal(ci.Content.Bytes, &contents) != nil {
				return result, errStructure
			}
		case ci.ContentType.Equal(oidEncryptedDataContentType):
			var ed encryptedData
			if unmarshal(ci.Content.Bytes, &ed) != nil || ed.Version != 0 || !ed.EncryptedContentInfo.ContentType.Equal(oidDataContentType) {
				return result, errStructure
			}
			contents, err = b.decrypt(ed.EncryptedContentInfo, encoded)
			if err != nil {
				return result, err
			}
			depth = 11
			confidential = true
		default:
			return result, errUnsupported
		}
		err = readBags(b, contents, depth, encoded, &result)
		if confidential {
			clear(contents)
		}
		if err != nil {
			return result, err
		}
	}
	if len(result.certs) == 0 {
		return result, errUnsupported
	}
	return result, nil
}
func readBags(b *budget, data []byte, depth int, password []byte, result *controlledResult) error {
	children, err := b.elements(data, depth, b.limits.bags-b.observed.bags)
	if err != nil {
		return err
	}
	for _, raw := range children {
		if err := b.check(); err != nil {
			return err
		}
		b.observed.bags++
		var bag wireBag
		if unmarshal(raw.FullBytes, &bag) != nil {
			return errStructure
		}
		switch {
		case bag.Id.Equal(oidCertBag):
			if b.observed.certs >= b.limits.certificates {
				return errLimit
			}
			certData, err := decodeCertBag(bag.Value.Bytes)
			if err != nil {
				return errUnsupported
			}
			cert, err := x509.ParseCertificate(certData)
			if err != nil {
				return errStructure
			}
			b.observed.certs++
			result.certs = append(result.certs, cert)
		case bag.Id.Equal(oidKeyBag), bag.Id.Equal(oidPKCS8ShroundedKeyBag):
			if result.key != nil {
				return errUnsupported
			}
			private := bag.Value.Bytes
			if bag.Id.Equal(oidPKCS8ShroundedKeyBag) {
				var key encryptedPrivateKeyInfo
				if unmarshal(private, &key) != nil {
					return errStructure
				}
				private, err = b.decrypt(key, password)
				if err != nil {
					return err
				}
				if err := b.inspect(private, depth+4); err != nil {
					clear(private)
					return err
				}
				parsed, parseErr := x509.ParsePKCS8PrivateKey(private)
				clear(private)
				if parseErr != nil {
					return errStructure
				}
				result.key, err = acceptedKey(parsed)
			} else {
				parsed, parseErr := x509.ParsePKCS8PrivateKey(private)
				if parseErr != nil {
					return errStructure
				}
				result.key, err = acceptedKey(parsed)
			}
			if err != nil {
				return err
			}
		default:
			return errUnsupported
		}
	}
	return nil
}
func acceptedKey(key interface{}) (crypto.Signer, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return k, nil
	case *ecdsa.PrivateKey:
		return k, nil
	case ed25519.PrivateKey:
		return k, nil
	}
	return nil, errUnsupported
}
