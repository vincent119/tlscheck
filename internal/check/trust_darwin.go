package check

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"
)

func verifyWithPlatform(ctx context.Context, cert *x509.Certificate, opts TrustOptions, verifyOpts x509.VerifyOptions) ([][]*x509.Certificate, error) {
	if opts.SystemRoots && opts.Purpose == CAPurpose {
		return verifyDarwinCA(ctx, cert, opts, verifyOpts, runSecurity)
	}
	return cert.Verify(verifyOpts)
}

type securityRunner func(context.Context, []string) ([]byte, error)

func verifyDarwinCA(ctx context.Context, cert *x509.Certificate, opts TrustOptions, verifyOpts x509.VerifyOptions, run securityRunner) (chains [][]*x509.Certificate, err error) {
	// 原生工具不能無限等待；更短的上層 deadline 仍優先。
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	directory, err := os.MkdirTemp("", "tlscheck-ca-*")
	if err != nil {
		return nil, trustFailure{code: "trust.temporary_file_failed", class: ExecutionFailure}
	}
	defer func() {
		if cleanupErr := os.RemoveAll(directory); cleanupErr != nil {
			chains = nil
			err = trustFailure{code: "trust.temporary_cleanup_failed", class: ExecutionFailure}
		}
	}()
	args := []string{"verify-cert", "-l", "-p", "basic", "-L", "-P", "-q", "-d", opts.Now.UTC().Format("2006-01-02-15:04:05")}
	certs := []*x509.Certificate{cert}
	// CertPool 不提供憑證列舉；呼叫端另外傳入唯讀的中繼憑證快照。
	certs = append(certs, opts.IntermediateCertificates...)
	for i, current := range certs {
		if current == nil || len(current.Raw) == 0 || (i > 0 && bytes.Equal(current.Raw, cert.Raw)) {
			continue
		}
		path := filepath.Join(directory, strconv.Itoa(i)+".pem")
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: current.Raw}), 0600); err != nil {
			return nil, trustFailure{code: "trust.temporary_file_failed", class: ExecutionFailure}
		}
		args = append(args, "-c", path)
	}
	output, err := run(ctx, args)
	if ctx.Err() != nil {
		return nil, trustFailure{code: "trust.native_verifier_timeout", class: ExecutionFailure}
	}
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return nil, trustFailure{code: "trust.platform_rejected", class: VerificationFailure}
		}
		return nil, trustFailure{code: "trust.native_verifier_failed", class: ExecutionFailure}
	}
	// security 使用 NUL 分隔各張 PEM，先轉成合法的行結尾再解碼。
	output = bytes.ReplaceAll(output, []byte{0}, []byte{'\n'})
	var nativeChain []*x509.Certificate
	// security -P 仍有鏈說明前綴，並以 NUL 結尾；只解出成功輸出的憑證區塊。
	for len(bytes.Trim(output, " \t\r\n\x00")) > 0 {
		output = bytes.Trim(output, " \t\r\n\x00")
		block, rest := pem.Decode(output)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, trustFailure{code: "trust.native_chain_invalid", class: ExecutionFailure}
		}
		parsed, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			return nil, trustFailure{code: "trust.native_chain_invalid", class: ExecutionFailure}
		}
		nativeChain = append(nativeChain, parsed)
		output = rest
	}
	if len(nativeChain) == 0 || !bytes.Equal(nativeChain[0].Raw, cert.Raw) {
		return nil, trustFailure{code: "trust.native_chain_invalid", class: ExecutionFailure}
	}
	// 僅原生系統驗證成功選出的錨點可用於這次交叉驗證，絕不提升任意輸入根。
	confirmedRoots := x509.NewCertPool()
	confirmedRoots.AddCert(nativeChain[len(nativeChain)-1])
	confirmedIntermediates := x509.NewCertPool()
	if opts.Intermediates != nil {
		confirmedIntermediates = opts.Intermediates.Clone()
	}
	for _, intermediate := range nativeChain[1:] {
		confirmedIntermediates.AddCert(intermediate)
	}
	verifyOpts.Roots = confirmedRoots
	verifyOpts.Intermediates = confirmedIntermediates
	return cert.Verify(verifyOpts)
}

const maxNativeOutput = 10 * 1024 * 1024

type boundedOutput struct{ buffer bytes.Buffer }

func (w *boundedOutput) Write(data []byte) (int, error) {
	if len(data) > maxNativeOutput-w.buffer.Len() {
		return 0, errors.New("原生驗證輸出超過上限")
	}
	return w.buffer.Write(data)
}

func runSecurity(ctx context.Context, args []string) ([]byte, error) {
	command := exec.CommandContext(ctx, "/usr/bin/security", args...)
	var stdout boundedOutput
	command.Stdout = &stdout
	// 不保留原生 stderr，避免將憑證內容或路徑夾入診斷。
	command.Stderr = io.Discard
	command.WaitDelay = time.Second
	if err := command.Run(); err != nil {
		return nil, err
	}
	return stdout.buffer.Bytes(), nil
}
