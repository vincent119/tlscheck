// Copyright 2015, 2018, 2019 Opsmate, Inc. All rights reserved.
// Copyright 2015 The Go Authors. All rights reserved.
// 原始授權見 LICENSE；只保留本專案白名單解碼需要的資料結構與原語。
package containers

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
)

var (
	oidDataContentType          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidEncryptedDataContentType = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}
	oidPBES2                    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2                   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidHmacWithSHA256           = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidAES256CBC                = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidSHA256                   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidCertBag                  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 3}
	oidKeyBag                   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 1}
	oidPKCS8ShroundedKeyBag     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 2}
	oidCertTypeX509Certificate  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 1}
)

type pfxPdu struct {
	Version  int
	AuthSafe contentInfo
	MacData  macData `asn1:"optional"`
}
type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0,optional"`
}
type encryptedData struct {
	Version              int
	EncryptedContentInfo encryptedContentInfo
}
type encryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           []byte `asn1:"tag:0,optional"`
}

func (i encryptedContentInfo) Algorithm() pkix.AlgorithmIdentifier {
	return i.ContentEncryptionAlgorithm
}
func (i encryptedContentInfo) Data() []byte { return i.EncryptedContent }

type encryptedPrivateKeyInfo struct {
	AlgorithmIdentifier pkix.AlgorithmIdentifier
	EncryptedData       []byte
}

func (i encryptedPrivateKeyInfo) Algorithm() pkix.AlgorithmIdentifier { return i.AlgorithmIdentifier }
func (i encryptedPrivateKeyInfo) Data() []byte                        { return i.EncryptedData }

type decryptable interface {
	Algorithm() pkix.AlgorithmIdentifier
	Data() []byte
}
type pbes2Params struct {
	Kdf              pkix.AlgorithmIdentifier
	EncryptionScheme pkix.AlgorithmIdentifier
}
type pbkdf2Params struct {
	Salt       asn1.RawValue
	Iterations int
	KeyLength  int                      `asn1:"optional"`
	Prf        pkix.AlgorithmIdentifier `asn1:"optional"`
}
type digestInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	Digest    []byte
}
type macData struct {
	Mac        digestInfo
	MacSalt    []byte
	Iterations int `asn1:"optional,default:1"`
}

func unmarshal(data []byte, out interface{}) error {
	rest, err := asn1.Unmarshal(data, out)
	if err != nil || len(rest) != 0 {
		return errStructure
	}
	return nil
}
func decodeCertBag(data []byte) ([]byte, error) {
	var bag struct {
		Id   asn1.ObjectIdentifier
		Data []byte `asn1:"explicit,tag:0"`
	}
	if unmarshal(data, &bag) != nil || !bag.Id.Equal(oidCertTypeX509Certificate) {
		return nil, errUnsupported
	}
	return bag.Data, nil
}
func verifyMac(m *macData, message, password []byte) error {
	key := pbkdf(sha256Sum, 32, 64, m.MacSalt, password, m.Iterations, 3, 32)
	defer clear(key)
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	if !hmac.Equal(m.Mac.Digest, mac.Sum(nil)) {
		return errIntegrity
	}
	return nil
}

// 呼叫前由受控入口驗證白名單、參數與預算；不對外暴露未受限的解密入口。
func pbDecrypt(info decryptable, password []byte) ([]byte, error) {
	var params pbes2Params
	if unmarshal(info.Algorithm().Parameters.FullBytes, &params) != nil {
		return nil, errStructure
	}
	var k pbkdf2Params
	if unmarshal(params.Kdf.Parameters.FullBytes, &k) != nil {
		return nil, errStructure
	}
	decoded, err := decodeBMPString(password)
	if err != nil {
		return nil, errUnsupported
	}
	key, err := pbkdf2.Key(sha256.New, decoded, k.Salt.Bytes, k.Iterations, 32)
	if err != nil {
		return nil, errUnsupported
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errUnsupported
	}
	encrypted := info.Data()
	out := make([]byte, len(encrypted))
	cipher.NewCBCDecrypter(block, params.EncryptionScheme.Parameters.Bytes).CryptBlocks(out, encrypted)
	n := int(out[len(out)-1])
	if n == 0 || n > aes.BlockSize || len(out) < n || !bytes.Equal(out[len(out)-n:], bytes.Repeat([]byte{byte(n)}, n)) {
		clear(out)
		return nil, errIntegrity
	}
	return out[:len(out)-n], nil
}
