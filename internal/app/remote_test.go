package app

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vincent119/tlscheck/internal/config"
)

func TestCLIActualTLSAndFailureContinuation(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("診斷不應送 HTTP") }))
	defer server.Close()
	a := New()
	a.Load = func(context.Context) config.Result { return config.Result{Config: config.Config{Language: "en"}} }
	var out, diag bytes.Buffer
	code := a.Run(context.Background(), []string{server.URL + "/private?secret=hidden", server.URL}, &out, &diag)
	if code != 1 {
		t.Fatal(code, out.String(), diag.String())
	}
	if strings.Count(out.String(), "The TLS handshake completed") != 2 || strings.Contains(out.String(), "hidden") {
		t.Fatal(out.String())
	}
	if diag.Len() != 0 {
		t.Fatal("信任失敗不得當執行診斷")
	}
}
