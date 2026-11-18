package check

import (
	"context"
	"net"
	"testing"
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
	c := NewRemoteCheckerWithOptions(time.Now(), nil, RemoteOptions{Timeout: time.Millisecond, ExpiryWarningDays: 0})
	c.resolver = remoteResolverFunc(func(ctx context.Context, _ string) ([]net.IPAddr, error) {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("DNS 無共用期限")
		}
		<-ctx.Done()
		return nil, ctx.Err()
	})
	c.dial = func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("DNS 失敗仍連線")
		return nil, nil
	}
	result := c.Check(t.Context(), model.Target{ASCIIHost: "example.test", Host: "example.test", Port: 443})
	if result.DNS.Status != Failed || result.DNS.Code != "remote.dns_timeout" || result.Failure() != ExecutionFailure {
		t.Fatal(result.DNS)
	}
}
