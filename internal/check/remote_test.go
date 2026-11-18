package check

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vincent119/tlscheck/internal/input"
	"github.com/vincent119/tlscheck/internal/model"
	"github.com/vincent119/tlscheck/internal/testutil"
)

type remoteResolverFunc func(context.Context, string) ([]net.IPAddr, error)

func (f remoteResolverFunc) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return f(ctx, host)
}

type remoteObservation struct {
	state            tls.ConnectionState
	applicationBytes int
	err              error
}

func remoteServer(t *testing.T, config *tls.Config) (model.Target, <-chan remoteObservation) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	observed := make(chan remoteObservation, 1)
	t.Cleanup(func() {
		cancel()
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Error(err)
		}
		<-done
	})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			observed <- remoteObservation{err: err}
			return
		}
		server := tls.Server(conn, config)
		err = server.HandshakeContext(ctx)
		observation := remoteObservation{state: server.ConnectionState(), err: err}
		if err == nil {
			var data [1]byte
			observation.applicationBytes, observation.err = server.Read(data[:])
		}
		observed <- observation
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	return model.Target{Host: "example.test", ASCIIHost: "example.test", Port: uint16(port), InputIndex: 4}, observed
}

func remoteIdentity(t *testing.T, change func(*x509.Certificate)) (testutil.Identity, testutil.Identity, testutil.Identity) {
	t.Helper()
	root, ca, _ := chain(t)
	template := testutil.Template(3, "TLS 站台", fixedNow(), false)
	template.DNSNames = []string{"example.test"}
	template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	if change != nil {
		change(template)
	}
	return root, ca, testutil.Issue(t, template, &ca, nil)
}

func remoteTLSConfig(leaf, ca testutil.Identity) *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.Cert.Raw, ca.Cert.Raw}, PrivateKey: leaf.Key}}}
}

func checkerForLocalServer(root *x509.Certificate) *RemoteChecker {
	checker := NewRemoteChecker(fixedNow(), rootsProvider(root))
	checker.resolver = remoteResolverFunc(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	})
	return checker
}

func TestRemotePreservesSentAndVerifiedChains(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(tls.VersionName(version), func(t *testing.T) {
			root, ca, leaf := remoteIdentity(t, nil)
			config := remoteTLSConfig(leaf, ca)
			config.MinVersion = version
			config.MaxVersion = version
			config.ClientAuth = tls.RequestClientCert
			target, observed := remoteServer(t, config)
			checker := checkerForLocalServer(root.Cert)
			result := checker.Check(t.Context(), target)
			if result.Failure() != NoFailure || !result.HandshakeComplete || result.Handshake.Status != Passed || result.Trust.Outcome.Status != Passed {
				t.Fatalf("正常 TLS 失敗：%+v", result)
			}
			if len(result.ServerChain) != 2 || len(result.Certificates) != 2 || len(result.Trust.Chains) != 1 || len(result.Trust.Chains[0]) != 3 {
				t.Fatalf("送出鏈與信任鏈未區分：%+v", result)
			}
			if !bytes.Equal(result.ServerChain[0].Raw, leaf.Cert.Raw) || !bytes.Equal(result.ServerChain[1].Raw, ca.Cert.Raw) || !bytes.Equal(result.Trust.Chains[0][2].Raw, root.Cert.Raw) {
				t.Fatal("鏈順序或內容錯誤")
			}
			if result.TLSVersion != version || result.TLSVersionName != tls.VersionName(version) || result.CipherSuite == 0 || result.CipherSuiteName != tls.CipherSuiteName(result.CipherSuite) {
				t.Fatal("未呈現實際協商資料")
			}
			if result.Trust.Hostname.Status != Passed || result.Trust.ServerUsage.Status != Passed || result.Revocation.Status != NotPerformed || result.AIARetrieval.Status != NotPerformed || result.PlatformPolicy == "" {
				t.Fatal("驗證或限制狀態錯誤")
			}
			observation := <-observed
			if observation.state.ServerName != "example.test" || len(observation.state.PeerCertificates) != 0 || observation.applicationBytes != 0 {
				t.Fatal("SNI 不正確、傳送 client certificate 或應用資料")
			}
		})
	}
}

func TestRemoteInvalidCertificatesRemainVisible(t *testing.T) {
	for _, scenario := range []string{"過期", "未生效", "名稱不符", "未知根", "缺中繼", "錯誤用途"} {
		t.Run(scenario, func(t *testing.T) {
			root, ca, leaf := remoteIdentity(t, func(template *x509.Certificate) {
				switch scenario {
				case "過期":
					template.NotAfter = fixedNow().Add(-time.Second)
				case "未生效":
					template.NotBefore = fixedNow().Add(time.Second)
				case "名稱不符":
					template.DNSNames = []string{"wrong.test"}
				case "錯誤用途":
					template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
				}
			})
			config := remoteTLSConfig(leaf, ca)
			if scenario == "缺中繼" {
				config.Certificates[0].Certificate = config.Certificates[0].Certificate[:1]
			}
			target, _ := remoteServer(t, config)
			checker := checkerForLocalServer(root.Cert)
			if scenario == "未知根" {
				checker.analyzer = NewAnalyzer(fixedNow(), rootsProvider())
			}
			result := checker.Check(t.Context(), target)
			if !result.HandshakeComplete || result.Failure() != VerificationFailure || result.Trust.Outcome.Status != Failed || len(result.Certificates) == 0 || len(result.Trust.Chains) != 0 {
				t.Fatalf("驗證失敗應保留實際憑證：%+v", result)
			}
			if result.Certificates[0].FingerprintSHA256 == "" || result.Certificates[0].Subject != leaf.Cert.Subject.String() {
				t.Fatal("公開資訊遺失")
			}
			if scenario == "名稱不符" && result.Trust.Hostname.Status != Failed {
				t.Fatal("名稱不符未呈現")
			}
			if scenario != "名稱不符" && result.Trust.Hostname.Status != Passed {
				t.Fatal("獨立執行的名稱比對事實未呈現")
			}
		})
	}
}

func TestRemoteIPIdentityDoesNotGuessSNI(t *testing.T) {
	for _, scenario := range []string{"IP 相符", "只有 DNS", "IP 不符"} {
		t.Run(scenario, func(t *testing.T) {
			root, ca, leaf := remoteIdentity(t, func(template *x509.Certificate) {
				if scenario == "只有 DNS" {
					template.IPAddresses = nil
				}
				if scenario == "IP 不符" {
					template.IPAddresses = []net.IP{net.ParseIP("192.0.2.1")}
				}
			})
			target, observed := remoteServer(t, remoteTLSConfig(leaf, ca))
			target.Host = "127.0.0.1"
			target.ASCIIHost = target.Host
			checker := checkerForLocalServer(root.Cert)
			checker.resolver = remoteResolverFunc(func(context.Context, string) ([]net.IPAddr, error) { t.Fatal("IP 不應查 DNS"); return nil, nil })
			result := checker.Check(t.Context(), target)
			want := NoFailure
			if scenario != "IP 相符" {
				want = VerificationFailure
			}
			if !result.HandshakeComplete || result.Failure() != want || result.DNS.Status != NotPerformed {
				t.Fatalf("IP 身分結果錯誤：%+v", result)
			}
			if observation := <-observed; observation.state.ServerName != "" {
				t.Fatal("不應從 SAN 猜測 SNI")
			}
		})
	}
}

func TestRemoteUsesNormalizedIDNFromURL(t *testing.T) {
	root, ca, leaf := remoteIdentity(t, func(template *x509.Certificate) { template.DNSNames = []string{"xn--bcher-kva.example"} })
	target, observed := remoteServer(t, remoteTLSConfig(leaf, ca))
	value := "https://user:password@bücher.example:" + strconv.Itoa(int(target.Port)) + "/private?token=secret#fragment"
	parsed := input.NewParser().Parse(t.Context(), value, 1)
	if parsed.Target == nil {
		t.Fatal("IDN URL 解析失敗")
	}
	checker := checkerForLocalServer(root.Cert)
	checker.resolver = remoteResolverFunc(func(_ context.Context, host string) ([]net.IPAddr, error) {
		if host != "xn--bcher-kva.example" {
			t.Fatal("DNS 未使用 ASCII 主機")
		}
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	})
	result := checker.Check(t.Context(), *parsed.Target)
	if result.Failure() != NoFailure || result.Target.Host != "bücher.example" {
		t.Fatal("IDN 驗證失敗")
	}
	if observation := <-observed; observation.state.ServerName != "xn--bcher-kva.example" {
		t.Fatal("SNI 未正規化")
	}
	for _, secret := range []string{"password", "token=", "secret", "fragment", "/private"} {
		if strings.Contains(fmt.Sprintf("%+v", result), secret) {
			t.Fatal("結果洩漏 URL 附加資料")
		}
	}
}

func TestRemoteDNSAndConnectFailuresAreExecutionErrors(t *testing.T) {
	for _, scenario := range []string{"DNS 不存在", "DNS 無地址", "DNS 逾時", "連線失敗", "連線逾時"} {
		t.Run(scenario, func(t *testing.T) {
			checker := NewRemoteChecker(fixedNow(), rootsProvider())
			checker.timeout = 30 * time.Millisecond
			checker.resolver = remoteResolverFunc(func(ctx context.Context, _ string) ([]net.IPAddr, error) {
				switch scenario {
				case "DNS 不存在":
					return nil, &net.DNSError{IsNotFound: true, Name: "不得顯示的機密"}
				case "DNS 無地址":
					return nil, nil
				case "DNS 逾時":
					<-ctx.Done()
					return nil, ctx.Err()
				}
				return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
			})
			var dialCalls atomic.Int32
			checker.dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
				dialCalls.Add(1)
				if scenario == "連線逾時" {
					<-ctx.Done()
					return nil, ctx.Err()
				}
				return nil, errors.New("不得顯示的機密")
			}
			result := checker.Check(t.Context(), model.Target{Host: "example.test", ASCIIHost: "example.test", Port: 443})
			if result.Failure() != ExecutionFailure || result.HandshakeComplete || len(result.ServerChain) != 0 || result.TLSVersion != 0 || result.CipherSuite != 0 {
				t.Fatalf("不能捏造失敗握手資訊：%+v", result)
			}
			if strings.HasPrefix(scenario, "DNS") && dialCalls.Load() != 0 {
				t.Fatal("DNS 失敗後不應撥號")
			}
			if strings.Contains(fmt.Sprintf("%+v", result), "不得顯示的機密") {
				t.Fatal("底層錯誤洩漏")
			}
		})
	}
}

func TestRemoteHandshakeTimeoutClosesConnection(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	checker := NewRemoteChecker(fixedNow(), rootsProvider())
	checker.timeout = 30 * time.Millisecond
	checker.dial = func(context.Context, string, string) (net.Conn, error) { return client, nil }
	result := checker.Check(t.Context(), model.Target{Host: "127.0.0.1", ASCIIHost: "127.0.0.1", Port: 443})
	if result.Failure() != ExecutionFailure || result.Stage != "handshake" || result.Handshake.Code != "remote.handshake_timeout" || result.TLSVersion != 0 || len(result.Trust.Chains) != 0 {
		t.Fatalf("握手逾時結果錯誤：%+v", result)
	}
	if _, err := server.Write([]byte{1}); err == nil {
		t.Fatal("逾時後未關閉連線")
	}
}

func TestRemoteAlreadyCanceledDoesNotDial(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	checker := NewRemoteChecker(fixedNow(), rootsProvider())
	checker.dial = func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("取消後不可撥號")
		return nil, nil
	}
	result := checker.Check(ctx, model.Target{Host: "127.0.0.1", ASCIIHost: "127.0.0.1", Port: 443})
	if result.Failure() != ExecutionFailure || result.HandshakeComplete {
		t.Fatal("取消不應成功")
	}
}

func TestRemoteRootLoadingFailureKeepsHandshakeFacts(t *testing.T) {
	_, ca, leaf := remoteIdentity(t, nil)
	target, _ := remoteServer(t, remoteTLSConfig(leaf, ca))
	checker := checkerForLocalServer(ca.Cert)
	checker.analyzer = NewAnalyzer(fixedNow(), func(context.Context) (*x509.CertPool, error) {
		return nil, errors.New("不得顯示的根載入錯誤")
	})
	result := checker.Check(t.Context(), target)
	if result.Failure() != ExecutionFailure || !result.HandshakeComplete || len(result.ServerChain) != 2 || result.Trust.Outcome.Code != "trust.roots_unavailable" {
		t.Fatal("根失敗仍應呈現握手事實")
	}
}

type remoteTrackedConn struct {
	net.Conn
	closes        atomic.Int32
	deadline      time.Time
	deadlineError error
	closeError    error
}

func (c *remoteTrackedConn) Close() error {
	c.closes.Add(1)
	err := c.Conn.Close()
	if c.closeError != nil {
		return c.closeError
	}
	return err
}
func (c *remoteTrackedConn) SetDeadline(deadline time.Time) error {
	c.deadline = deadline
	if c.deadlineError != nil {
		return c.deadlineError
	}
	return c.Conn.SetDeadline(deadline)
}

func TestRemoteIncompleteHandshakeRetainsOnlyConfirmedCertificates(t *testing.T) {
	root, ca, leaf := remoteIdentity(t, nil)
	config := remoteTLSConfig(leaf, ca)
	config.MinVersion = tls.VersionTLS12
	config.MaxVersion = tls.VersionTLS12
	config.ClientAuth = tls.RequireAnyClientCert
	target, _ := remoteServer(t, config)
	result := checkerForLocalServer(root.Cert).Check(t.Context(), target)
	if result.Failure() != ExecutionFailure || result.HandshakeComplete || result.Handshake.Status != Failed || result.Trust.Outcome.Status != NotPerformed {
		t.Fatalf("握手失敗不應宣稱驗證成功：%+v", result)
	}
	if len(result.ServerChain) != 2 || len(result.Certificates) != 2 || result.TLSVersion != 0 || result.CipherSuite != 0 || len(result.Trust.Chains) != 0 {
		t.Fatal("應保留確實收到的憑證，但不捏造協商與信任結果")
	}
}

func TestRemoteRejectsPlaintextServiceWithoutInventingCertificates(t *testing.T) {
	client, server := net.Pipe()
	done := make(chan struct{})
	t.Cleanup(func() { server.Close(); <-done })
	go func() {
		defer close(done)
		defer server.Close()
		if err := server.SetDeadline(time.Now().Add(time.Second)); err != nil {
			return
		}
		var hello [8192]byte
		if _, err := server.Read(hello[:]); err != nil {
			return
		}
		server.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
	}()
	checker := NewRemoteChecker(fixedNow(), rootsProvider())
	checker.dial = func(context.Context, string, string) (net.Conn, error) { return client, nil }
	result := checker.Check(t.Context(), model.Target{Host: "127.0.0.1", ASCIIHost: "127.0.0.1", Port: 443})
	if result.Failure() != ExecutionFailure || result.Handshake.Code != "remote.not_tls" || len(result.ServerChain) != 0 || len(result.Certificates) != 0 || result.TLSVersion != 0 {
		t.Fatalf("非 TLS 服務結果錯誤：%+v", result)
	}
}

func TestRemoteSharesOneDeadlineAcrossNetworkStages(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	tracked := &remoteTrackedConn{Conn: client}
	checker := NewRemoteChecker(fixedNow(), rootsProvider())
	checker.timeout = 40 * time.Millisecond
	var dnsDeadline, dialDeadline time.Time
	checker.resolver = remoteResolverFunc(func(ctx context.Context, _ string) ([]net.IPAddr, error) {
		var ok bool
		dnsDeadline, ok = ctx.Deadline()
		if !ok {
			t.Fatal("DNS 缺少期限")
		}
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	})
	checker.dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		dialDeadline, _ = ctx.Deadline()
		return tracked, nil
	}
	result := checker.Check(t.Context(), model.Target{Host: "example.test", ASCIIHost: "example.test", Port: 443})
	if !dnsDeadline.Equal(dialDeadline) || !dnsDeadline.Equal(tracked.deadline) {
		t.Fatal("DNS、TCP 與握手不可各自重設總期限")
	}
	if result.Handshake.Code != "remote.handshake_timeout" || tracked.closes.Load() == 0 {
		t.Fatal("共用期限應終止握手並清理")
	}
	if NewRemoteChecker(fixedNow(), nil).timeout != 10*time.Second {
		t.Fatal("正式預設總期限應為 10 秒")
	}
}

func TestRemoteRetriesAddressesAndClosesFailedAttempt(t *testing.T) {
	root, ca, leaf := remoteIdentity(t, nil)
	target, _ := remoteServer(t, remoteTLSConfig(leaf, ca))
	client, server := net.Pipe()
	defer server.Close()
	failedConn := &remoteTrackedConn{Conn: client}
	checker := checkerForLocalServer(root.Cert)
	checker.resolver = remoteResolverFunc(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("192.0.2.1")}, {IP: net.ParseIP("127.0.0.1")}}, nil
	})
	var calls int
	var firstDeadline, secondDeadline time.Time
	checker.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		calls++
		if calls == 1 {
			firstDeadline, _ = ctx.Deadline()
			return failedConn, errors.New("合成第一地址失敗")
		}
		secondDeadline, _ = ctx.Deadline()
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	result := checker.Check(t.Context(), target)
	if result.Failure() != NoFailure || calls != 2 || failedConn.closes.Load() != 1 || !firstDeadline.Before(secondDeadline) {
		t.Fatalf("未正確保留替代地址與清理：%+v", result)
	}
}

func TestRemoteCheckerKeepsTargetsIndependent(t *testing.T) {
	root, ca, leaf := remoteIdentity(t, nil)
	target, _ := remoteServer(t, remoteTLSConfig(leaf, ca))
	checker := checkerForLocalServer(root.Cert)
	calls := 0
	checker.resolver = remoteResolverFunc(func(ctx context.Context, _ string) ([]net.IPAddr, error) {
		calls++
		if calls == 1 {
			return nil, &net.DNSError{IsNotFound: true}
		}
		if ctx.Err() != nil {
			t.Fatal("前一目標取消污染後續")
		}
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	})
	target.InputIndex = 1
	first := checker.Check(t.Context(), target)
	target.InputIndex = 2
	second := checker.Check(t.Context(), target)
	if first.Failure() != ExecutionFailure || second.Failure() != NoFailure || first.Target.InputIndex != 1 || second.Target.InputIndex != 2 || len(first.ServerChain) != 0 || len(second.ServerChain) != 2 {
		t.Fatal("失敗後未繼續，或混用目標資料")
	}
}

func TestRemoteCancellationDuringDNSAndDial(t *testing.T) {
	for _, stage := range []string{"dns", "connect"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			checker := NewRemoteChecker(fixedNow(), rootsProvider())
			checker.resolver = remoteResolverFunc(func(ctx context.Context, _ string) ([]net.IPAddr, error) {
				if stage == "dns" {
					cancel()
					return nil, ctx.Err()
				}
				return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
			})
			checker.dial = func(ctx context.Context, _, _ string) (net.Conn, error) { cancel(); return nil, ctx.Err() }
			result := checker.Check(ctx, model.Target{Host: "example.test", ASCIIHost: "example.test", Port: 443})
			if result.Failure() != ExecutionFailure || result.Stage != stage {
				t.Fatalf("取消階段不正確：%+v", result)
			}
		})
	}
}

func TestRemoteHandshakeCancellationClosesSocket(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	client, server := net.Pipe()
	done := make(chan struct{})
	t.Cleanup(func() { server.Close(); <-done })
	go func() { defer close(done); var hello [8192]byte; server.Read(hello[:]); cancel() }()
	tracked := &remoteTrackedConn{Conn: client}
	checker := NewRemoteChecker(fixedNow(), rootsProvider())
	checker.dial = func(context.Context, string, string) (net.Conn, error) { return tracked, nil }
	result := checker.Check(ctx, model.Target{Host: "127.0.0.1", ASCIIHost: "127.0.0.1", Port: 443})
	if result.Handshake.Code != "remote.canceled" || result.Failure() != ExecutionFailure || tracked.closes.Load() == 0 {
		t.Fatal("握手取消未清理")
	}
}

func TestRemoteDeadlineSetupAndCloseFailures(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	tracked := &remoteTrackedConn{Conn: client, deadlineError: errors.New("不得顯示的 deadline 錯誤")}
	checker := NewRemoteChecker(fixedNow(), rootsProvider())
	checker.dial = func(context.Context, string, string) (net.Conn, error) { return tracked, nil }
	result := checker.Check(t.Context(), model.Target{Host: "127.0.0.1", ASCIIHost: "127.0.0.1", Port: 443})
	if result.Handshake.Code != "remote.deadline_failed" || result.Failure() != ExecutionFailure || tracked.closes.Load() != 1 {
		t.Fatal("設定期限失敗應清理連線")
	}
	root, ca, leaf := remoteIdentity(t, nil)
	target, _ := remoteServer(t, remoteTLSConfig(leaf, ca))
	checker = checkerForLocalServer(root.Cert)
	checker.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return &remoteTrackedConn{Conn: conn, closeError: errors.New("不得顯示的 Close 錯誤")}, nil
	}
	result = checker.Check(t.Context(), target)
	if result.Failure() != ExecutionFailure || !result.HandshakeComplete || result.Trust.Outcome.Status != Passed || len(result.Issues) != 1 || result.Issues[0].Code != "remote.close_failed" {
		t.Fatal("關閉錯誤應保留已取得的診斷")
	}
}

func TestRemoteRejectsMalformedTypedTargetsBeforeNetwork(t *testing.T) {
	checker := NewRemoteChecker(fixedNow(), rootsProvider())
	checker.resolver = remoteResolverFunc(func(context.Context, string) ([]net.IPAddr, error) {
		t.Fatal("無效目標不應查詢")
		return nil, nil
	})
	checker.dial = func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("無效目標不應撥號")
		return nil, nil
	}
	for _, host := range []string{"", "user:password@example.test", "https://example.test/path?secret=yes", "example.test\n", "bad..name", "bad_name.test", "-bad.test", "999.999.999.999", "fe80::1%en0", strings.Repeat("a", 64) + ".test"} {
		result := checker.Check(t.Context(), model.Target{Host: host, ASCIIHost: host, Port: 443})
		if result.Failure() != ExecutionFailure || result.Target.Host != "" {
			t.Fatal("無效目標未拒絕或回顯原始值")
		}
	}
	if result := checker.Check(t.Context(), model.Target{Host: "example.test", ASCIIHost: "example.test"}); result.Failure() != ExecutionFailure {
		t.Fatal("埠 0 不應接受")
	}
	if result := NewRemoteChecker(time.Time{}, nil).Check(t.Context(), model.Target{Host: "example.test", ASCIIHost: "example.test", Port: 443}); result.Failure() != ExecutionFailure {
		t.Fatal("缺少固定時間不應連線")
	}
}

func TestRemoteNoActiveRevocationOrApplicationRequests(t *testing.T) {
	root, ca, leaf := remoteIdentity(t, func(template *x509.Certificate) {
		template.OCSPServer = []string{"http://127.0.0.1:9/ocsp"}
		template.IssuingCertificateURL = []string{"http://127.0.0.1:9/ca"}
	})
	config := remoteTLSConfig(leaf, ca)
	config.Certificates[0].OCSPStaple = []byte("合成未驗證的 staple")
	target, observed := remoteServer(t, config)
	result := checkerForLocalServer(root.Cert).Check(t.Context(), target)
	if result.Failure() != NoFailure || result.Revocation.Status != NotPerformed || result.AIARetrieval.Status != NotPerformed {
		t.Fatal("不得把收到 staple 當成撤銷檢查成功")
	}
	if observation := <-observed; observation.applicationBytes != 0 {
		t.Fatal("不得傳送 HTTP 或其他應用資料")
	}
}

func TestRemoteIPv6IdentityAndAddressFormatting(t *testing.T) {
	for _, match := range []bool{true, false} {
		t.Run(fmt.Sprint(match), func(t *testing.T) {
			root, ca, leaf := remoteIdentity(t, func(template *x509.Certificate) {
				if !match {
					template.IPAddresses = []net.IP{net.ParseIP("::2")}
				}
			})
			target, observed := remoteServer(t, remoteTLSConfig(leaf, ca))
			localAddress := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(target.Port)))
			target.Host = "::1"
			target.ASCIIHost = "::1"
			checker := checkerForLocalServer(root.Cert)
			checker.resolver = remoteResolverFunc(func(context.Context, string) ([]net.IPAddr, error) { t.Fatal("IPv6 不應查 DNS"); return nil, nil })
			checker.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
				if address != target.String() {
					t.Fatal("IPv6 位址缺少括號或埠錯誤")
				}
				return (&net.Dialer{}).DialContext(ctx, network, localAddress)
			}
			result := checker.Check(t.Context(), target)
			want := NoFailure
			if !match {
				want = VerificationFailure
			}
			if !result.HandshakeComplete || result.Failure() != want {
				t.Fatalf("IPv6 名稱比對錯誤：%+v", result)
			}
			if observation := <-observed; observation.state.ServerName != "" {
				t.Fatal("IPv6 不應轉成 DNS SNI")
			}
		})
	}
}

func TestRemoteVerificationCancellationKeepsFactsAndClearsTrust(t *testing.T) {
	root, ca, leaf := remoteIdentity(t, nil)
	target, _ := remoteServer(t, remoteTLSConfig(leaf, ca))
	checker := checkerForLocalServer(root.Cert)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	pool := x509.NewCertPool()
	pool.AddCert(root.Cert)
	checker.analyzer = NewAnalyzer(fixedNow(), func(ctx context.Context) (*x509.CertPool, error) { cancel(); return pool, nil })
	result := checker.Check(ctx, target)
	if result.Failure() != ExecutionFailure || !result.HandshakeComplete || len(result.ServerChain) != 2 || len(result.Trust.Chains) != 0 || result.Trust.Outcome.Code != "remote.canceled" {
		t.Fatal("取消不能清掉握手事實或宣稱已有信任鏈")
	}
}

func TestRemoteDefaultSystemTrustDoesNotAcceptGeneratedCA(t *testing.T) {
	_, ca, leaf := remoteIdentity(t, nil)
	target, _ := remoteServer(t, remoteTLSConfig(leaf, ca))
	checker := NewRemoteChecker(fixedNow(), nil)
	checker.resolver = remoteResolverFunc(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	})
	result := checker.Check(t.Context(), target)
	if !result.HandshakeComplete || result.Failure() != VerificationFailure || result.Trust.Outcome.Status != Failed || len(result.Trust.Chains) != 0 {
		t.Fatalf("系統根不可自動信任剛產生的 CA：%+v", result)
	}
}

func TestRemoteExpiryWarningDoesNotFailVerification(t *testing.T) {
	root, ca, leaf := remoteIdentity(t, func(template *x509.Certificate) { template.NotAfter = fixedNow().Add(20 * 24 * time.Hour) })
	target, _ := remoteServer(t, remoteTLSConfig(leaf, ca))
	result := checkerForLocalServer(root.Cert).Check(t.Context(), target)
	if result.Failure() != NoFailure || len(result.Certificates) == 0 || !result.Certificates[0].ExpiringSoon || result.Certificates[0].RemainingDays != 20 {
		t.Fatal("單純到期提醒不得造成失敗")
	}
}
