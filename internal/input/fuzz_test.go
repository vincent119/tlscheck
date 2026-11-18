package input

import (
	"context"
	"testing"

	"github.com/vincent119/tlscheck/internal/model"
)

func FuzzParseData(f *testing.F) {
	for _, data := range [][]byte{nil, []byte("-----BEGIN CERTIFICATE-----\n%%%\n-----END CERTIFICATE-----\n"), []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n"), {0x30, 0x03, 0x02, 0x01, 0x00}} {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxFileSize {
			return
		}
		result := model.InputResult{InputIndex: 2}
		parseData(context.Background(), data, model.SourceRef{Path: "合成資料", InputIndex: 2}, &result)
		for _, cert := range result.Certificates {
			if cert.Certificate == nil || cert.Source.InputIndex != 2 {
				t.Fatal("憑證解析來源或物件遺失")
			}
		}
		for _, key := range result.Keys {
			if key.Signer() == nil || key.Source.InputIndex != 2 {
				t.Fatal("金鑰解析來源或物件遺失")
			}
		}
	})
}

func FuzzParseTarget(f *testing.F) {
	for _, value := range []string{"example.com", "https://user:password@example.com:8443/path?token=secret#fragment", "https:/example.com", "[::1]:443", "例子.測試", "bad..name"} {
		f.Add(value)
	}
	f.Fuzz(func(t *testing.T, value string) {
		target, err := parseTarget(value, 4)
		if err != nil {
			if target != nil {
				t.Fatal("錯誤目標仍被回傳")
			}
			return
		}
		if target == nil || target.ASCIIHost == "" || target.Port == 0 || target.InputIndex != 4 {
			t.Fatal("接受不完整目標")
		}
	})
}
