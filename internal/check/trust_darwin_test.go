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
	"strings"
	"testing"
)

func chainPEM(certs ...*x509.Certificate) []byte {
	var data []byte
	for _, cert := range certs {
		data = append(data, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}
	return data
}

func TestDarwinCAUsesBasicPolicyAndProtectedTemporaryFiles(t *testing.T) {
	root, ca, _ := chain(t)
	pool := x509.NewCertPool()
	pool.AddCert(root.Cert)
	opts := TrustOptions{Now: fixedNow(), Purpose: CAPurpose, Roots: pool, IntermediateCertificates: []*x509.Certificate{root.Cert}}
	verifyOpts := x509.VerifyOptions{CurrentTime: fixedNow(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}
	var directory string
	runner := func(ctx context.Context, args []string) ([]byte, error) {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("原生工具缺少 deadline")
		}
		joined := strings.Join(args, " ")
		for _, required := range []string{"verify-cert -l -p basic -L -P -q -d", "2026-11-18-00:00:00"} {
			if !strings.Contains(joined, required) {
				t.Fatalf("缺少安全政策：%s", joined)
			}
		}
		if strings.Contains(joined, " -r ") || strings.Contains(joined, " -n ") {
			t.Fatal("不能提升輸入根或強制主機名稱")
		}
		count := 0
		for i, arg := range args {
			if arg != "-c" {
				continue
			}
			path := args[i+1]
			directory = filepath.Dir(path)
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0600 {
				t.Fatal("暫存憑證權限不正確")
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode(data)
			if block == nil || block.Type != "CERTIFICATE" {
				t.Fatal("不應寫入私鑰或其他資料")
			}
			count++
		}
		info, err := os.Stat(directory)
		if err != nil || info.Mode().Perm() != 0700 {
			t.Fatal("暫存目錄權限不正確")
		}
		if count != 2 {
			t.Fatal("缺少目標或中繼憑證")
		}
		data := append([]byte("---\nCertificate chain\n"), bytes.TrimRight(chainPEM(ca.Cert), "\r\n")...)
		data = append(data, 0)
		data = append(data, bytes.TrimRight(chainPEM(root.Cert), "\r\n")...)
		return append(data, 0), nil
	}
	chains, err := verifyDarwinCA(t.Context(), ca.Cert, opts, verifyOpts, runner)
	if err != nil || len(chains) != 1 || len(chains[0]) != 2 {
		t.Fatalf("原生成功後交叉驗證失敗：%v", err)
	}
	if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("暫存目錄未清除")
	}
}

func TestDarwinCARejectsMalformedOrUnverifiedOutput(t *testing.T) {
	root, ca, _ := chain(t)
	opts := TrustOptions{Now: fixedNow(), Purpose: CAPurpose}
	verifyOpts := x509.VerifyOptions{CurrentTime: fixedNow(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}
	for _, tt := range []struct {
		name  string
		data  []byte
		err   error
		class FailureClass
	}{
		{"空輸出", nil, nil, ExecutionFailure},
		{"未知輸出", []byte("不應回顯的診斷"), nil, ExecutionFailure},
		{"錯誤 leaf", chainPEM(root.Cert), nil, ExecutionFailure},
		{"損壞 DER", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2}}), nil, ExecutionFailure},
		{"失敗仍有鏈", chainPEM(ca.Cert, root.Cert), &exec.ExitError{}, VerificationFailure},
		{"無法執行", nil, errors.New("敏感錯誤"), ExecutionFailure},
		{"錯誤區塊", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2}}), nil, ExecutionFailure},
	} {
		t.Run(tt.name, func(t *testing.T) {
			chains, err := verifyDarwinCA(t.Context(), ca.Cert, opts, verifyOpts, func(context.Context, []string) ([]byte, error) { return tt.data, tt.err })
			if err == nil || len(chains) != 0 || classifyTrustError(err, fixedNow()).Class != tt.class {
				t.Fatalf("未拒絕不可靠原生結果：%v", err)
			}
		})
	}
}

func TestDarwinNativeChainMustPassGoSignatureValidation(t *testing.T) {
	_, ca, _ := chain(t)
	wrongRoot, _, _ := chain(t)
	_, err := verifyDarwinCA(t.Context(), ca.Cert, TrustOptions{Now: fixedNow()}, x509.VerifyOptions{CurrentTime: fixedNow(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}, func(context.Context, []string) ([]byte, error) { return chainPEM(ca.Cert, wrongRoot.Cert), nil })
	if err == nil {
		t.Fatal("不能只因原生回傳成功就略過 crypto/x509")
	}
}

func TestDarwinOutputLimitCannotBeBypassed(t *testing.T) {
	var output boundedOutput
	_, err := io.Copy(&output, bytes.NewReader(bytes.Repeat([]byte{'x'}, maxNativeOutput+1)))
	if err == nil || output.buffer.Len() > maxNativeOutput {
		t.Fatal("原生輸出限制失效")
	}
}

func TestDarwinRunnerHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := runSecurity(ctx, []string{"verify-cert"}); err == nil {
		t.Fatal("取消後不應成功執行工具")
	}
}

func TestDarwinCancellationCleansTemporaryFiles(t *testing.T) {
	_, ca, _ := chain(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var directory string
	_, err := verifyDarwinCA(ctx, ca.Cert, TrustOptions{Now: fixedNow()}, x509.VerifyOptions{}, func(ctx context.Context, args []string) ([]byte, error) {
		for i, arg := range args {
			if arg == "-c" {
				directory = filepath.Dir(args[i+1])
				break
			}
		}
		cancel()
		return nil, context.Canceled
	})
	if err == nil || classifyTrustError(err, fixedNow()).Class != ExecutionFailure {
		t.Fatal("取消應回報執行錯誤")
	}
	if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("取消後暫存目錄未清理")
	}
}
