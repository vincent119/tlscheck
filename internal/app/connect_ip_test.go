package app

import (
	"bytes"
	"context"
	"encoding/json"
	"html"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vincent119/tlscheck/internal/check"
	"github.com/vincent119/tlscheck/internal/config"
	"github.com/vincent119/tlscheck/internal/model"
	"github.com/vincent119/tlscheck/internal/report"
)

func TestConnectIPRejectsInvalidBindingsBeforeSideEffects(t *testing.T) {
	for _, binding := range []string{"", "0", "=127.0.0.1", "-1=127.0.0.1", "+0=127.0.0.1", "1=127.0.0.1", "999999999999999999999=127.0.0.1", "0=localhost", "0=[::1]", "0=fe80::1%eth0", "0=127.0.0.1:443", "0=https://127.0.0.1", "0=", "0=127.0.0.1=extra"} {
		t.Run(binding, func(t *testing.T) {
			a := New()
			a.Load = func(context.Context) config.Result { t.Fatal("無效映射不得讀設定"); return config.Result{} }
			a.Parse = func(context.Context, []string) []model.InputResult {
				t.Fatal("無效映射不得解析內容")
				return nil
			}
			var out, diag bytes.Buffer
			if code := a.Run(t.Context(), []string{"-r", "example.invalid", "--connect-ip", binding}, &out, &diag); code != 2 || out.Len() != 0 {
				t.Fatal("無效映射未拒絕", code)
			}
		})
	}
	local := filepath.Join(t.TempDir(), "local.pem")
	if err := os.WriteFile(local, []byte("非憑證"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"-r", "example.invalid", "--connect-ip", "0=127.0.0.1", "--connect-ip", "00=::1"},
		{"--local", local, "--connect-ip", "0=127.0.0.1"},
		{local, "--connect-ip", "0=127.0.0.1"},
		{"-r", "bad input", "--connect-ip", "0=127.0.0.1"},
		{"--help", "--connect-ip", "0=127.0.0.1"},
	} {
		var out, diag bytes.Buffer
		if code := New().Run(t.Context(), args, &out, &diag); code != 2 {
			t.Fatal("衝突映射未拒絕", args, code)
		}
	}
}

func TestConnectIPBatchMappingsUseExpandedIndices(t *testing.T) {
	path := batchFile(t, "bad input\nexample.invalid\nexample.invalid\n")
	var ordinary atomic.Int32
	a := batchApp(&ordinary)
	var mapped atomic.Int32
	a.RemoteWithIP = func(_ context.Context, target model.Target, ip netip.Addr, _ time.Time) check.RemoteResult {
		want := map[int]string{2: "192.0.2.10", 3: "2001:db8::10"}
		if ip.String() != want[target.InputIndex] || target.ASCIIHost != "example.invalid" {
			t.Error("映射索引或驗證身分不符", target, ip)
		}
		mapped.Add(1)
		return check.RemoteResult{Target: target, ConnectionInfo: &check.ConnectionInfo{RequestedIP: ip}}
	}
	var out, diag bytes.Buffer
	code := a.Run(t.Context(), []string{"direct.invalid", "--targets-file", path, "--connect-ip", "2=192.0.2.10", "--connect-ip", "3=2001:db8::10", "--concurrency", "3", "-f", "json", "-L", "en"}, &out, &diag)
	var d report.Document
	if code != 2 || mapped.Load() != 2 || ordinary.Load() != 1 || json.Unmarshal(out.Bytes(), &d) != nil || len(d.Remote) != 3 {
		t.Fatal("批次映射或退出碼不符", code, out.String(), diag.String())
	}
	if d.Remote[0].Connection != nil || d.Remote[1].Connection.RequestedIP != "192.0.2.10" || d.Remote[2].Connection.RequestedIP != "2001:db8::10" {
		t.Fatal("同域名不同索引遭合併")
	}
}

func TestConnectIPReportsOnlyObservedConnectionInFourFormats(t *testing.T) {
	for _, lang := range []string{"en", "zh-TW", "zh-CN"} {
		for _, format := range []string{"json", "table", "html", "markdown"} {
			for _, detail := range []string{"summary", "full"} {
				var calls atomic.Int32
				a := batchApp(&calls)
				a.RemoteWithIP = func(_ context.Context, target model.Target, ip netip.Addr, _ time.Time) check.RemoteResult {
					return check.RemoteResult{Target: target, ConnectionInfo: &check.ConnectionInfo{RequestedIP: ip, Connected: true, PeerAddress: netip.MustParseAddrPort("192.0.2.20:9443")}}
				}
				var out, diag bytes.Buffer
				code := a.Run(t.Context(), []string{"-r", "https://user:SECRET-CANARY@example.invalid/private?q=QUERY-CANARY", "--connect-ip", "0=192.0.2.10", "-f", format, "-L", lang, "--detail", detail}, &out, &diag)
				if code != 0 || diag.Len() != 0 {
					t.Fatal("映射報告失敗", format, lang, code, diag.String())
				}
				for _, value := range []string{"192.0.2.10", "192.0.2.20:9443", "example.invalid"} {
					if !strings.Contains(html.UnescapeString(out.String()), value) {
						t.Fatal("要求或觀測事實遺失", format, detail, value)
					}
				}
				for _, secret := range []string{"SECRET-CANARY", "QUERY-CANARY", "/private"} {
					if strings.Contains(out.String()+diag.String(), secret) {
						t.Fatal("URL秘密洩漏", format)
					}
				}
				if format == "json" {
					var d report.Document
					if json.Unmarshal(out.Bytes(), &d) != nil || d.SchemaVersion != 1 || !d.Remote[0].Connection.Connected || *d.Remote[0].Connection.PeerAddress != "192.0.2.20:9443" {
						t.Fatal("JSON連線事實不符")
					}
				}
			}
		}
	}
}

func TestConnectIPUnscheduledTargetHasNoAssumedPeer(t *testing.T) {
	var calls atomic.Int32
	a := batchApp(&calls)
	a.RemoteWithIP = func(context.Context, model.Target, netip.Addr, time.Time) check.RemoteResult {
		t.Fatal("取消後不得排程")
		return check.RemoteResult{}
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	a.Local = func(context.Context, []model.ParsedCertificate, time.Time) check.LocalResult {
		cancel()
		return check.LocalResult{}
	}
	var out, diag bytes.Buffer
	code := a.Run(ctx, []string{"-r", "example.invalid", "--connect-ip", "0=192.0.2.10", "-f", "json", "-L", "en"}, &out, &diag)
	var d report.Document
	if code != 2 || json.Unmarshal(out.Bytes(), &d) != nil || len(d.Remote) != 1 {
		t.Fatal("未排程報告不符", code, out.String(), diag.String())
	}
	c := d.Remote[0].Connection
	if c == nil || c.RequestedIP != "192.0.2.10" || c.Connected || c.PeerAddress != nil || !strings.Contains(out.String(), `"peer_address": null`) {
		t.Fatal("未排程不應虛構peer")
	}
}

func TestConnectIPCompletionHasNoSideEffects(t *testing.T) {
	a := New()
	a.Load = func(context.Context) config.Result { t.Fatal("補全不得讀設定"); return config.Result{} }
	a.Parse = func(context.Context, []string) []model.InputResult { t.Fatal("補全不得解析內容"); return nil }
	var out, diag bytes.Buffer
	if code := a.Run(t.Context(), []string{"__complete", "--connect-ip", ""}, &out, &diag); code != 0 || out.String() != ":4\n" {
		t.Fatal("映射補全不得回退檔名", code, out.String())
	}
}

func TestConnectIPRechecksActualClassification(t *testing.T) {
	bindings := map[int]netip.Addr{0: netip.MustParseAddr("127.0.0.1")}
	if connectTargetsStillRemote(bindings, []model.InputResult{{InputIndex: 0}}) {
		t.Fatal("分類改成本機仍接受映射")
	}
}

func TestConnectIPPreservesFailureExitCodesAndNullPeer(t *testing.T) {
	for _, failure := range []check.FailureClass{check.VerificationFailure, check.ExecutionFailure} {
		var calls atomic.Int32
		a := batchApp(&calls)
		a.RemoteWithIP = func(_ context.Context, target model.Target, ip netip.Addr, _ time.Time) check.RemoteResult {
			return check.RemoteResult{Target: target, ConnectionInfo: &check.ConnectionInfo{RequestedIP: ip}, Issues: []check.Outcome{{Status: check.Failed, Code: "remote.connect_failed", Class: failure}}}
		}
		var out, diag bytes.Buffer
		code := a.Run(t.Context(), []string{"-r", "example.invalid", "--connect-ip", "0=192.0.2.10", "-f", "json", "-L", "en"}, &out, &diag)
		var d report.Document
		if code != int(failure) || json.Unmarshal(out.Bytes(), &d) != nil || len(d.Remote) != 1 || d.Remote[0].Connection.Connected || d.Remote[0].Connection.PeerAddress != nil {
			t.Fatal("映射變更失敗結束碼或偽造peer", code)
		}
	}
}
