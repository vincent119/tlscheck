package input

import (
	"bytes"
	"context"
	"encoding/pem"
	"testing"
	"time"

	"github.com/vincent119/tlscheck/internal/model"
	"github.com/vincent119/tlscheck/internal/testutil"
)

func TestCompareCandidateRequiresOneDistinctLeaf(t *testing.T) {
	leaf := certDER(t)
	other := certDER(t)
	ca := testutil.Issue(t, testutil.Template(21, "candidate-ca", time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC), true), nil, nil)
	encoded := pemData("CERTIFICATE", leaf)
	for _, tc := range []struct {
		name  string
		data  []byte
		valid bool
	}{
		{"DER", leaf, true}, {"PEM", encoded, true}, {"重複同張", append(bytes.Clone(encoded), encoded...), true},
		{"含CA鏈", append(pemData("CERTIFICATE", ca.Cert.Raw), encoded...), true},
		{"多葉", append(bytes.Clone(encoded), pemData("CERTIFICATE", other)...), false},
		{"純CA", pemData("CERTIFICATE", ca.Cert.Raw), false}, {"空檔", nil, false},
		{"私鑰混合", append(bytes.Clone(encoded), pemData("PRIVATE KEY", []byte("PRIVATE-CANARY"))...), false},
		{"損壞前段", append([]byte("-----BEGIN CERTIFICATE-----\nbroken\n"), encoded...), false},
		{"尾端雜訊", append(bytes.Clone(encoded), []byte("junk")...), false},
		{"DER尾端", append(bytes.Clone(leaf), 0), false},
		{"容器", testutil.ContainerFixture(t, "modern.pfx"), false},
		{"PEM容器", pemData("PKCS7", leaf), false},
		{"額外標頭", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"X": "Y"}, Bytes: leaf}), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeFile(t, "候選 = 檔.pem", tc.data)
			p := NewParserWithPasswordProvider(func(_ context.Context, _ model.SourceRef) ([]byte, error) {
				t.Fatal("候選不得讀密碼")
				return nil, nil
			})
			cert, issue := p.ReadCompareCandidate(t.Context(), path)
			if (issue == "") != tc.valid || (cert != nil) != tc.valid {
				t.Fatal("候選原子性或選取不符", issue)
			}
			if cert != nil && !bytes.Equal(cert.Raw, leaf) {
				t.Fatal("選錯葉憑證")
			}
		})
	}
}

func TestCompareCandidateReadLimitsAndCancellation(t *testing.T) {
	der := certDER(t)
	for _, size := range []int{MaxFileSize, MaxFileSize + 1} {
		data := append(pemData("CERTIFICATE", der), bytes.Repeat([]byte(" "), size-len(pemData("CERTIFICATE", der)))...)
		cert, issue := NewParser().ReadCompareCandidate(t.Context(), writeFile(t, "large.pem", data))
		if (issue == "") != (size == MaxFileSize) || (cert != nil) != (size == MaxFileSize) {
			t.Fatal("10MiB邊界不符", size)
		}
	}
	for _, path := range []string{t.TempDir(), "不存在.pem"} {
		if cert, issue := NewParser().ReadCompareCandidate(t.Context(), path); cert != nil || issue == "" {
			t.Fatal("非regular候選未拒絕")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if cert, issue := NewParser().ReadCompareCandidate(ctx, writeFile(t, "cancel.pem", der)); cert != nil || issue == "" {
		t.Fatal("取消後仍接受候選")
	}
}
