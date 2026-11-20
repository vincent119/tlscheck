package check

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/vincent119/tlscheck/internal/model"
)

func TestConnectIPKeepsOriginalSNIAndVerificationName(t *testing.T) {
	for _, scenario := range []string{"正確DNS", "錯誤DNS", "IP身分", "UnicodeDNS"} {
		t.Run(scenario, func(t *testing.T) {
			root, ca, leaf := remoteIdentity(t, func(template *x509.Certificate) {
				if scenario == "UnicodeDNS" {
					template.DNSNames = []string{"xn--bcher-kva.example"}
				}
			})
			target, observed := remoteServer(t, remoteTLSConfig(leaf, ca))
			expectedSNI := "example.test"
			want := NoFailure
			switch scenario {
			case "錯誤DNS":
				target.Host = "wrong.test"
				target.ASCIIHost = "wrong.test"
				expectedSNI = "wrong.test"
				want = VerificationFailure
			case "IP身分":
				target.Host = "127.0.0.1"
				target.ASCIIHost = "127.0.0.1"
				expectedSNI = ""
			case "UnicodeDNS":
				target.Host = "bücher.example"
				target.ASCIIHost = "xn--bcher-kva.example"
				expectedSNI = target.ASCIIHost
			}
			checker := checkerForLocalServer(root.Cert)
			checker.resolver = remoteResolverFunc(func(context.Context, string) ([]net.IPAddr, error) { t.Fatal("IP覆寫不得查DNS"); return nil, nil })
			actual := checker.CheckWithIP(t.Context(), target, netip.MustParseAddr("127.0.0.1"))
			if actual.Failure() != want || actual.Target != target || !actual.HandshakeComplete || actual.ConnectionInfo == nil || !actual.ConnectionInfo.Connected || actual.ConnectionInfo.PeerAddress.Addr() != netip.MustParseAddr("127.0.0.1") || actual.ConnectionInfo.PeerAddress.Port() != target.Port || actual.DNS.Code != "remote.dns_overridden" {
				t.Fatal("覆寫改變驗證身分或連線事實", scenario, actual.Failure())
			}
			state := <-observed
			if state.state.ServerName != expectedSNI || state.applicationBytes != 0 || len(state.state.PeerCertificates) != 0 {
				t.Fatal("SNI／client certificate／應用資料不符")
			}
		})
	}
}
func TestConnectIPDoesNotResolveOrFallback(t *testing.T) {
	for _, literal := range []string{"192.0.2.10", "2001:db8::10"} {
		t.Run(literal, func(t *testing.T) {
			checker := NewRemoteChecker(fixedNow(), nil)
			checker.resolver = nil
			calls := 0
			checker.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
				calls++
				ip := netip.MustParseAddr(literal)
				want := netip.AddrPortFrom(ip, 8443).String()
				if network != "tcp" || address != want {
					t.Fatal("撥號地址或port不符", address, want)
				}
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("遺失共用deadline")
				}
				return nil, errors.New("合成撥號失敗")
			}
			target := modelTargetForIPTest()
			actual := checker.CheckWithIP(t.Context(), target, netip.MustParseAddr(literal))
			if calls != 1 || actual.Failure() != ExecutionFailure || actual.ConnectionInfo == nil || actual.ConnectionInfo.Connected || actual.ConnectionInfo.PeerAddress.IsValid() {
				t.Fatal("失敗發生回退或虛構peer", calls)
			}
		})
	}
}
func TestConnectIPRetainsOnlyObservedPeerAndSharedDeadline(t *testing.T) {
	checker := NewRemoteChecker(fixedNow(), nil)
	checker.resolver = nil
	client, server := net.Pipe()
	t.Cleanup(func() { _ = server.Close() })
	tracked := &remoteTrackedConn{Conn: client, deadlineError: errors.New("合成deadline設定失敗")}
	var dialDeadline time.Time
	checker.dial = func(ctx context.Context, _ string, _ string) (net.Conn, error) {
		dialDeadline, _ = ctx.Deadline()
		return tracked, nil
	}
	actual := checker.CheckWithIP(t.Context(), modelTargetForIPTest(), netip.MustParseAddr("192.0.2.10"))
	if actual.ConnectionInfo == nil || !actual.ConnectionInfo.Connected || actual.ConnectionInfo.PeerAddress.IsValid() || actual.Handshake.Code != "remote.deadline_failed" || tracked.closes.Load() != 1 || !tracked.deadline.Equal(dialDeadline) {
		t.Fatal("非IP peer被偽造、共用deadline遺失或連線未釋放")
	}
}

func modelTargetForIPTest() model.Target {
	return model.Target{Host: "example.test", ASCIIHost: "example.test", Port: 8443, InputIndex: 0}
}
