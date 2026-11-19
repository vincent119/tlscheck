package check

import (
	"context"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/vincent119/tlscheck/internal/model"
	"github.com/vincent119/tlscheck/internal/testutil"
)

func TestExpiryWarningOptionsPreserveExpiryVerification(t *testing.T) {
	now := time.Now().UTC()
	template := testutil.Template(901, "合成提醒", now, false)
	template.NotAfter = now.Add(40 * 24 * time.Hour)
	cert := testutil.Issue(t, template, nil, nil).Cert
	for _, tc := range []struct {
		days int
		want bool
	}{{0, false}, {30, false}, {40, true}, {36500, true}} {
		info, err := AnalyzeCertificateWithOptions(cert, now, CertificateOptions{ExpiryWarningDays: tc.days})
		if err != nil || info.ExpiringSoon != tc.want {
			t.Fatal(tc, info, err)
		}
	}
	cert.NotAfter = now.Add(-time.Second)
	a := NewAnalyzerWithOptions(now, nil, CertificateOptions{ExpiryWarningDays: 0})
	r := a.AnalyzeLocal(context.Background(), []model.ParsedCertificate{{Certificate: cert}})
	if len(r.Certificates) != 1 || r.Certificates[0].Validity.Status != Failed {
		t.Fatal(r)
	}
}
func TestRemoteTimeoutOptionUsesSharedDeadline(t *testing.T) {
	for _, tc := range []struct {
		name    string
		timeout time.Duration
	}{{"最小期限", time.Millisecond}, {"自訂期限", 37 * time.Millisecond}} {
		t.Run(tc.name, func(t *testing.T) {
			// 虛擬時鐘只在阻塞時推進，避免 race 排程在 DNS 開始前耗盡 1ms。
			synctest.Test(t, func(t *testing.T) {
				start := time.Now()
				c := NewRemoteCheckerWithOptions(start, nil, RemoteOptions{Timeout: tc.timeout, ExpiryWarningDays: 0})
				resolved := false
				c.resolver = remoteResolverFunc(func(ctx context.Context, _ string) ([]net.IPAddr, error) {
					resolved = true
					deadline, ok := ctx.Deadline()
					if !ok || !deadline.Equal(start.Add(tc.timeout)) || ctx.Err() != nil {
						t.Fatalf("DNS 未取得設定的共用期限：%v，錯誤：%v", deadline, ctx.Err())
					}
					<-ctx.Done()
					if ctx.Err() != context.DeadlineExceeded || !time.Now().Equal(deadline) {
						t.Fatal("DNS 必須在共用期限到達時收到逾時")
					}
					return nil, ctx.Err()
				})
				c.dial = func(context.Context, string, string) (net.Conn, error) {
					t.Fatal("DNS 失敗仍連線")
					return nil, nil
				}
				result := c.Check(t.Context(), model.Target{ASCIIHost: "example.test", Host: "example.test", Port: 443})
				if !resolved || result.Stage != "dns" || result.DNS.Status != Failed || result.DNS.Code != "remote.dns_timeout" || result.Failure() != ExecutionFailure || int(result.Failure()) != 2 {
					t.Fatalf("DNS 逾時與結束碼契約錯誤：%+v", result)
				}
			})
		})
	}
}

func TestRemoteTimeoutBeforeDNSKeepsExecutionFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), time.Millisecond)
		defer cancel()
		time.Sleep(time.Millisecond)
		synctest.Wait()
		if ctx.Err() != context.DeadlineExceeded {
			t.Fatal("前置期限必須已到期")
		}
		c := NewRemoteCheckerWithOptions(time.Now(), nil, RemoteOptions{Timeout: 37 * time.Millisecond})
		c.resolver = remoteResolverFunc(func(context.Context, string) ([]net.IPAddr, error) {
			t.Fatal("期限已到仍執行 DNS")
			return nil, nil
		})
		c.dial = func(context.Context, string, string) (net.Conn, error) {
			t.Fatal("期限已到仍連線")
			return nil, nil
		}
		result := c.Check(ctx, model.Target{ASCIIHost: "example.test", Host: "example.test", Port: 443})
		if result.Stage != "input" || result.DNS.Status != NotPerformed || result.DNS.Code != "remote.not_started" || result.Connection.Status != NotPerformed || result.Handshake.Status != NotPerformed {
			t.Fatalf("期限先到不應宣稱網路階段已執行：%+v", result)
		}
		if len(result.Issues) != 1 || result.Issues[0].Code != "remote.connect_timeout" || result.Issues[0].Status != Failed || result.Issues[0].Class != ExecutionFailure || result.Failure() != ExecutionFailure || int(result.Failure()) != 2 {
			t.Fatalf("DNS 前逾時仍須回報執行錯誤與結束碼 2：%+v", result)
		}
	})
}
