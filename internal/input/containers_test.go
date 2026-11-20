package input

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/vincent119/tlscheck/internal/model"
	"github.com/vincent119/tlscheck/internal/testutil"
)

func TestContainerRoutingAndOnePasswordPerOccurrence(t *testing.T) {
	root := t.TempDir()
	calls := 0
	p := NewParserWithPasswordProvider(func(ctx context.Context, source model.SourceRef) ([]byte, error) {
		calls++
		if source.InputIndex != 4 {
			t.Fatal("密碼綁定索引錯誤")
		}
		return []byte("S12_SYNTHETIC_PASSWORD_CANARY"), nil
	})
	path := filepath.Join(root, "identity.any-extension")
	if err := os.WriteFile(path, testutil.ContainerFixture(t, "modern.pfx"), 0600); err != nil {
		t.Fatal(err)
	}
	r := p.ParseSpec(t.Context(), model.InputSpec{Kind: model.LocalInput, Index: 4, Value: path})
	if calls != 1 || len(r.Keys) != 1 || len(r.Certificates) != 2 || len(r.Issues) != 0 || r.Keys[0].Format != "PKCS#12" || r.Keys[0].Source.Block != 0 || r.Keys[0].Source.Encoding != "DER" {
		t.Fatal("PFX辨識或來源錯誤", calls, len(r.Issues))
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "PKCS7", Bytes: testutil.ContainerFixture(t, "chain.p7b")})
	data = append(data, []byte("-----BEGIN UNSUPPORTED-----\nAQ==\n-----END UNSUPPORTED-----\n")...)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	r = p.ParseSpec(t.Context(), model.InputSpec{Kind: model.LocalInput, Index: 4, Value: path})
	if calls != 1 || len(r.Certificates) != 2 || len(r.Issues) != 1 || r.Certificates[0].Source.Block != 1 || r.Certificates[0].Source.Encoding != "PEM" {
		t.Fatal("P7B混合區塊或來源處理錯誤", len(r.Certificates), len(r.Issues))
	}
}
func TestPFXFailureClearsPasswordAndDoesNotExposeObjects(t *testing.T) {
	data := testutil.ContainerFixture(t, "modern.pfx")
	password := []byte("wrong-canary")
	var r model.InputResult
	parseDataWithPassword(t.Context(), data, model.SourceRef{}, &r, func(context.Context, model.SourceRef) ([]byte, error) { return password, nil })
	if len(r.Keys) != 0 || len(r.Certificates) != 0 || len(r.Issues) != 1 || r.Issues[0].Code != model.ContainerIntegrity || !bytes.Equal(password, make([]byte, len(password))) {
		t.Fatal("失敗解析或密碼生命週期不符")
	}
	r = model.InputResult{}
	parseDataWithPassword(t.Context(), data, model.SourceRef{}, &r, func(context.Context, model.SourceRef) ([]byte, error) {
		return []byte("secret"), errors.New("不應對外顯示的底層錯誤")
	})
	if len(r.Issues) != 1 || r.Issues[0].Code != model.PasswordUnavailable {
		t.Fatal("密碼錯誤未安全分類")
	}
}
func TestPasswordFileBoundariesAndAliases(t *testing.T) {
	for _, value := range []string{"", "  測試密碼  ", "  測試密碼  \r\n"} {
		path := testutil.PasswordFile(t, []byte(value))
		got, err := ReadPasswordFile(t.Context(), path, nil)
		want := bytes.TrimSuffix([]byte(value), []byte("\r\n"))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("密碼空白或編碼被改寫", err)
		}
		clear(got)
		if _, err := ReadPasswordFile(t.Context(), path, []string{path}); err == nil {
			t.Fatal("輸入別名未拒絕")
		}
	}
	for _, value := range [][]byte{bytes.Repeat([]byte("a"), 4097), []byte("a\nb"), []byte("a\x00b"), {0xff}, {0xef, 0xbb, 0xbf, 'a'}} {
		path := testutil.PasswordFile(t, value)
		if _, err := ReadPasswordFile(t.Context(), path, nil); err == nil {
			t.Fatal("不安全密碼檔被接受")
		}
	}
	path := testutil.PasswordFile(t, []byte("secret"))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := ReadPasswordFile(ctx, path, nil); err == nil {
		t.Fatal("取消仍讀取密碼")
	}
}
