package check

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/vincent119/tlscheck/internal/model"
)

// RemoteTimeout 為每個目標的 DNS、TCP 與握手共用上限。
const RemoteTimeout = 10 * time.Second

type remoteResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

// RemoteChecker 只保存可重用依賴，不接受本機憑證或私鑰。
type RemoteChecker struct {
	analyzer *Analyzer
	resolver remoteResolver
	dial     func(context.Context, string, string) (net.Conn, error)
	timeout  time.Duration
}

// RemoteResult 區分實際送出鏈、已驗證鏈及未完成握手的事實。
type RemoteResult struct {
	Target            model.Target
	Stage             string
	DNS               Outcome
	Connection        Outcome
	Handshake         Outcome
	HandshakeComplete bool
	ServerChain       []*x509.Certificate
	Certificates      []CertificateInfo
	TLSVersion        uint16
	TLSVersionName    string
	CipherSuite       uint16
	CipherSuiteName   string
	Trust             TrustResult
	Revocation        Outcome
	AIARetrieval      Outcome
	PlatformPolicy    string
	Issues            []Outcome
}

// Failure 不把到期提醒或未執行狀態算成失敗。
func (r RemoteResult) Failure() FailureClass {
	var severity FailureClass
	outcomes := []Outcome{r.DNS, r.Connection, r.Handshake, r.Trust.Outcome, r.Trust.Hostname, r.Trust.ServerUsage}
	outcomes = append(outcomes, r.Issues...)
	for _, outcome := range outcomes {
		if outcome.Class > severity {
			severity = outcome.Class
		}
	}
	return severity
}

// RemoteOptions 保留每目標的總期限與提醒門檻。
type RemoteOptions struct {
	Timeout           time.Duration
	ExpiryWarningDays int
}

// NewRemoteChecker 的 nil provider 使用系統信任，不自動搜尋 client key。
func NewRemoteChecker(now time.Time, provider RootProvider) *RemoteChecker {
	return NewRemoteCheckerWithOptions(now, provider, RemoteOptions{Timeout: RemoteTimeout, ExpiryWarningDays: 30})
}

// NewRemoteCheckerWithOptions 不加入重試或額外網路請求。
func NewRemoteCheckerWithOptions(now time.Time, provider RootProvider, options RemoteOptions) *RemoteChecker {
	return &RemoteChecker{analyzer: NewAnalyzerWithOptions(now, provider, CertificateOptions{ExpiryWarningDays: options.ExpiryWarningDays}), resolver: &net.Resolver{}, dial: (&net.Dialer{}).DialContext, timeout: options.Timeout}
}

// Check 僅檢查一個已正規化目標；每次呼叫都有獨立期限。
func (c *RemoteChecker) Check(ctx context.Context, target model.Target) (result RemoteResult) {
	result = RemoteResult{Stage: "input", DNS: skipped("remote.not_started"), Connection: skipped("remote.not_started"), Handshake: skipped("remote.not_started"), Trust: TrustResult{Outcome: skipped("remote.handshake_incomplete"), Hostname: skipped("remote.handshake_incomplete"), ServerUsage: skipped("remote.handshake_incomplete")}, Revocation: skipped("remote.revocation_not_checked"), AIARetrieval: skipped("remote.aia_not_requested"), PlatformPolicy: "trust.platform_policy_may_apply"}
	if c.analyzer == nil || c.analyzer.now.IsZero() || c.resolver == nil || c.dial == nil || c.timeout <= 0 {
		result.Issues = append(result.Issues, failed("remote.invalid_configuration", ExecutionFailure))
		return result
	}
	if !validRemoteTarget(target) {
		result.Issues = append(result.Issues, failed("remote.invalid_target", ExecutionFailure))
		return result
	}
	result.Target = target
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	if ctx.Err() != nil {
		result.Issues = append(result.Issues, remoteNetworkError(ctx, "connect", ctx.Err()))
		return result
	}
	result.Stage = "dns"
	addresses := []net.IPAddr{}
	if address, err := netip.ParseAddr(target.ASCIIHost); err == nil {
		addresses = append(addresses, net.IPAddr{IP: net.IP(address.AsSlice())})
		result.DNS = skipped("remote.dns_not_needed")
	} else {
		resolved, err := c.resolver.LookupIPAddr(ctx, target.ASCIIHost)
		if err != nil {
			result.DNS = remoteNetworkError(ctx, "dns", err)
			return result
		}
		for _, address := range resolved {
			if address.IP.To16() != nil && address.Zone == "" {
				addresses = append(addresses, address)
			}
		}
		if len(addresses) == 0 {
			result.DNS = failed("remote.dns_no_addresses", ExecutionFailure)
			return result
		}
		result.DNS = passed("remote.dns_resolved")
	}
	result.Stage = "connect"
	conn, err := c.dialResolved(ctx, addresses, target.Port, &result)
	if err != nil {
		result.Connection = remoteNetworkError(ctx, "connect", err)
		return result
	}
	result.Connection = passed("remote.connected")
	closeConnection := func() {
		if conn == nil {
			return
		}
		err := conn.Close()
		conn = nil
		if err != nil && !errors.Is(err, net.ErrClosed) {
			result.Issues = append(result.Issues, failed("remote.close_failed", ExecutionFailure))
		}
	}
	defer closeConnection()
	result.Stage = "handshake"
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		result.Handshake = failed("remote.deadline_failed", ExecutionFailure)
		return result
	}
	serverName := target.ASCIIHost
	if _, err := netip.ParseAddr(serverName); err == nil {
		serverName = ""
	}
	// 只為保留失敗憑證而略過內建驗證；下方必須以 S02 執行完整驗證。
	connection := tls.Client(conn, &tls.Config{ServerName: serverName, InsecureSkipVerify: true})
	err = connection.HandshakeContext(ctx)
	state := connection.ConnectionState()
	// 不發送應用資料，完成診斷便釋放 TCP，不等待可能阻塞的 close_notify。
	closeConnection()
	result.ServerChain = append([]*x509.Certificate(nil), state.PeerCertificates...)
	for _, certificate := range result.ServerChain {
		info, analysisErr := AnalyzeCertificateWithOptions(certificate, c.analyzer.now, c.analyzer.options)
		if analysisErr != nil {
			result.Issues = append(result.Issues, failed("remote.invalid_certificate", ExecutionFailure))
			continue
		}
		result.Certificates = append(result.Certificates, info)
	}
	if err != nil {
		result.Handshake = remoteNetworkError(ctx, "handshake", err)
		return result
	}
	if !state.HandshakeComplete || len(result.ServerChain) == 0 {
		result.Handshake = failed("remote.incomplete_handshake", ExecutionFailure)
		return result
	}
	result.HandshakeComplete = true
	result.Handshake = passed("remote.handshake_complete")
	result.TLSVersion = state.Version
	result.TLSVersionName = tls.VersionName(state.Version)
	result.CipherSuite = state.CipherSuite
	result.CipherSuiteName = tls.CipherSuiteName(state.CipherSuite)
	result.Stage = "verify"
	provider := c.analyzer.roots
	if provider == nil {
		provider = SystemRoots
	}
	roots, rootErr := provider(ctx)
	if rootErr != nil {
		roots = nil
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range result.ServerChain[1:] {
		intermediates.AddCert(certificate)
	}
	result.Trust = VerifyTrust(ctx, result.ServerChain[0], TrustOptions{Roots: roots, Intermediates: intermediates, IntermediateCertificates: result.ServerChain[1:], Now: c.analyzer.now, DNSName: target.ASCIIHost, Purpose: ServerPurpose, SystemRoots: c.analyzer.systemRoots})
	// 名稱比對獨立保留事實，避免信任或時間先失敗時誤寫成未提供名稱。
	if err := result.ServerChain[0].VerifyHostname(target.ASCIIHost); err != nil {
		result.Trust.Hostname = failed("trust.hostname_mismatch", VerificationFailure)
	} else {
		result.Trust.Hostname = passed("trust.hostname_valid")
	}
	if ctx.Err() != nil {
		result.Trust.Outcome = remoteNetworkError(ctx, "verification", ctx.Err())
		result.Trust.Chains = nil
		result.Trust.ServerUsage = skipped("remote.verification_incomplete")
	}
	if result.Failure() == NoFailure {
		result.Stage = "complete"
	}
	return result
}

func (c *RemoteChecker) dialResolved(ctx context.Context, addresses []net.IPAddr, port uint16, result *RemoteResult) (net.Conn, error) {
	var lastErr error
	for index, address := range addresses {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		deadline, _ := ctx.Deadline()
		// 第一個地址不能吃掉全部預算，保留後續 IPv4／IPv6 地址的嘗試機會。
		attemptCtx, cancel := context.WithTimeout(ctx, time.Until(deadline)/time.Duration(len(addresses)-index))
		conn, err := c.dial(attemptCtx, "tcp", net.JoinHostPort(address.IP.String(), strconv.Itoa(int(port))))
		cancel()
		if err == nil && conn != nil {
			return conn, nil
		}
		if conn != nil {
			if closeErr := conn.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
				result.Issues = append(result.Issues, failed("remote.close_failed", ExecutionFailure))
			}
		}
		if err == nil {
			err = errors.New("撥號未回傳連線")
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("沒有可用的連線地址")
	}
	return nil, lastErr
}

func remoteNetworkError(ctx context.Context, stage string, err error) Outcome {
	if errors.Is(ctx.Err(), context.Canceled) || errors.Is(err, context.Canceled) {
		return failed("remote.canceled", ExecutionFailure)
	}
	var network net.Error
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &network) && network.Timeout()) {
		return failed("remote."+stage+"_timeout", ExecutionFailure)
	}
	var dns *net.DNSError
	if stage == "dns" && errors.As(err, &dns) && dns.IsNotFound {
		return failed("remote.dns_not_found", ExecutionFailure)
	}
	if stage == "connect" && errors.Is(err, syscall.ECONNREFUSED) {
		return failed("remote.connection_refused", ExecutionFailure)
	}
	var record tls.RecordHeaderError
	if stage == "handshake" && errors.As(err, &record) {
		return failed("remote.not_tls", ExecutionFailure)
	}
	if stage == "handshake" && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)) {
		return failed("remote.handshake_closed", ExecutionFailure)
	}
	return failed("remote."+stage+"_failed", ExecutionFailure)
}

func validRemoteTarget(target model.Target) bool {
	if target.Port == 0 || target.ASCIIHost == "" || target.Host == "" || strings.ContainsAny(target.Host, "/?#@%\\") || strings.IndexFunc(target.Host, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return false
	}
	if strings.Contains(target.Host, ":") {
		if ip, err := netip.ParseAddr(target.Host); err != nil || ip.Zone() != "" {
			return false
		}
	}
	if ip, err := netip.ParseAddr(target.ASCIIHost); err == nil {
		return ip.Zone() == ""
	}
	if len(target.ASCIIHost) > 253 || strings.Contains(target.ASCIIHost, ".") && strings.Trim(target.ASCIIHost, "0123456789.") == "" {
		return false
	}
	for _, label := range strings.Split(target.ASCIIHost, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}
