package app

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vincent119/tlscheck/internal/check"
	"github.com/vincent119/tlscheck/internal/config"
	"github.com/vincent119/tlscheck/internal/model"
	"github.com/vincent119/tlscheck/internal/report"
)

// 同時保留無效行與本機位置，避免只在純遠端清單驗證索引而漏掉跨來源錯綁。
func TestBatchMappingsAcrossListsLocalAndDuplicateTargets(t *testing.T) {
	first := batchFile(t, "# first\r\n\r\nexample.invalid\r\nbad input\r\nexample.invalid\r\n")
	second := batchFile(t, "\n# second\nexample.invalid:9443\nbad input\nexample.invalid\n")
	aCert, bCert, localCert := comparisonIdentity(t, 501), comparisonIdentity(t, 502), comparisonIdentity(t, 503)
	candidateA := comparisonFile(t, "候選 a=1.pem", aCert.Cert.Raw)
	candidateB := comparisonFile(t, "候選 b=2.pem", bCert.Cert.Raw)
	local := comparisonFile(t, "本機 憑證=3.pem", localCert.Cert.Raw)
	ips := map[int]netip.Addr{1: netip.MustParseAddr("192.0.2.10"), 3: netip.MustParseAddr("2001:db8::20"), 5: netip.MustParseAddr("192.0.2.30")}
	candidates := map[int]string{1: candidateA, 3: candidateB, 5: candidateA, 8: candidateB}
	leaves := map[int]*x509.Certificate{1: aCert.Cert, 3: bCert.Cert, 5: aCert.Cert, 8: bCert.Cert}
	hosts := map[int]string{0: "direct.invalid:443", 1: "example.invalid:443", 3: "example.invalid:443", 5: "example.invalid:9443", 7: "example.invalid:443", 8: "tail.invalid:443"}
	sources := map[int]report.ListSource{1: {Path: first, Line: 3}, 2: {Path: first, Line: 4}, 3: {Path: first, Line: 5}, 5: {Path: second, Line: 3}, 6: {Path: second, Line: 4}, 7: {Path: second, Line: 5}}
	base := []string{"-r", "direct.invalid", "--targets-file", first, "--local", local, "--targets-file", second, "-r", "tail.invalid", "--connect-ip", "1=192.0.2.10", "--connect-ip", "3=2001:db8::20", "--connect-ip", "5=192.0.2.30", "--compare-cert", "1=" + candidateA, "--compare-cert", "3=" + candidateB, "--compare-cert", "5=" + candidateA, "--compare-cert", "8=" + candidateB, "-L", "en", "-f", "json"}
	var sequential []byte
	for _, mode := range []string{"預設循序", "顯式並行"} {
		t.Run(mode, func(t *testing.T) {
			type call struct {
				index  int
				target string
				ip     netip.Addr
			}
			var mu sync.Mutex
			calls := []call{}
			a := New()
			a.Now = func() time.Time { return time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC) }
			result := func(target model.Target, ip netip.Addr) check.RemoteResult {
				mu.Lock()
				calls = append(calls, call{target.InputIndex, target.String(), ip})
				mu.Unlock()
				r := check.RemoteResult{Target: target}
				if leaf := leaves[target.InputIndex]; leaf != nil {
					r.ServerChain = []*x509.Certificate{leaf}
				}
				if ip.IsValid() {
					r.ConnectionInfo = &check.ConnectionInfo{RequestedIP: ip}
				}
				return r
			}
			a.Remote = func(_ context.Context, target model.Target, _ time.Time) check.RemoteResult {
				return result(target, netip.Addr{})
			}
			a.RemoteWithIP = func(_ context.Context, target model.Target, ip netip.Addr, _ time.Time) check.RemoteResult {
				return result(target, ip)
			}
			localCalls := 0
			a.Local = func(_ context.Context, certs []model.ParsedCertificate, _ time.Time) check.LocalResult {
				localCalls++
				if len(certs) != 1 || !bytes.Equal(certs[0].Certificate.Raw, localCert.Cert.Raw) || certs[0].Source.InputIndex != 4 || certs[0].Source.Path != local {
					t.Fatal("本機憑證索引錯誤或候選滲入本機分析")
				}
				return check.LocalResult{}
			}
			args := append([]string(nil), base...)
			if mode == "顯式並行" {
				args = append(args, "--concurrency", "3")
			}
			var out, diag bytes.Buffer
			code := a.Run(t.Context(), args, &out, &diag)
			if code != 2 || localCalls != 1 {
				t.Fatal("無效行未維持退出2或本機未執行", code, localCalls)
			}
			var d report.Document
			if err := json.Unmarshal(out.Bytes(), &d); err != nil {
				t.Fatal("無法解析組合報告", err, diag.String())
			}
			if d.SchemaVersion != 1 || len(d.Inputs) != 9 || len(d.Remote) != 6 || d.Summary.CheckExitCode != 2 {
				t.Fatal("輸入或結果筆數不符")
			}
			for i, input := range d.Inputs {
				if input.Index != i {
					t.Fatal("全域索引不連續", i, input.Index)
				}
				want, listed := sources[i]
				if listed {
					if input.ListSource == nil || *input.ListSource != want {
						t.Fatal("清單來源或行號錯綁", i, input.ListSource)
					}
				} else if input.ListSource != nil {
					t.Fatal("直接輸入或本機誤標清單來源", i)
				}
				if i == 2 || i == 6 {
					if input.Target != nil || input.LocalSource != nil {
						t.Fatal("無效行被誤判為目標或本機", i)
					}
				}
			}
			if d.Inputs[4].LocalSource == nil || *d.Inputs[4].LocalSource != local {
				t.Fatal("本機來源遺失")
			}
			seen := map[int]int{}
			for _, c := range calls {
				seen[c.index]++
				if c.target != hosts[c.index] || c.ip != ips[c.index] {
					t.Fatal("撥號目標或IP跨occurrence錯綁", c)
				}
			}
			if len(calls) != 6 || !reflect.DeepEqual(seen, map[int]int{0: 1, 1: 1, 3: 1, 5: 1, 7: 1, 8: 1}) {
				t.Fatal("有效遠端漏跑、重跑或無效行被排程", seen)
			}
			if mode == "預設循序" {
				order := []int{}
				for _, c := range calls {
					order = append(order, c.index)
				}
				if !reflect.DeepEqual(order, []int{0, 1, 3, 5, 7, 8}) {
					t.Fatal("預設未依輸入循序執行", order)
				}
			}
			for i, r := range d.Remote {
				wantIndex := []int{0, 1, 3, 5, 7, 8}[i]
				if r.InputIndex != wantIndex || r.Target != hosts[wantIndex] {
					t.Fatal("完成順序改變報告順序", i, r.InputIndex)
				}
				if ip, mapped := ips[wantIndex]; mapped {
					if r.Connection == nil || r.Connection.RequestedIP != ip.String() {
						t.Fatal("連線IP事實錯綁", wantIndex)
					}
				} else if r.Connection != nil {
					t.Fatal("覆寫外溢到未映射目標", wantIndex)
				}
				if path, mapped := candidates[wantIndex]; mapped {
					c := r.Comparison
					if c == nil || c.CandidateSource != path || c.Result.Status != "passed" || c.ObservedFingerprintSHA256 == nil || c.CandidateFingerprintSHA256 != *c.ObservedFingerprintSHA256 {
						t.Fatal("候選憑證跨目標錯綁", wantIndex)
					}
				} else if r.Comparison != nil {
					t.Fatal("候選外溢到未映射目標", wantIndex)
				}
			}
			if d.Remote[1].Comparison.CandidateFingerprintSHA256 == d.Remote[2].Comparison.CandidateFingerprintSHA256 {
				t.Fatal("不同候選被錯誤合併")
			}
			if mode == "預設循序" {
				sequential = bytes.Clone(out.Bytes())
			} else if !bytes.Equal(sequential, out.Bytes()) {
				t.Fatal("顯式並行改變有序報告或映射內容")
			}
		})
	}
}

func TestBatchMappingsRejectInvalidExpandedIndicesBeforeScheduling(t *testing.T) {
	first := batchFile(t, "example.invalid\nbad input\n")
	second := batchFile(t, "example.invalid\n")
	local := comparisonFile(t, "本機.pem", comparisonIdentity(t, 511).Cert.Raw)
	candidate := comparisonFile(t, "候選=1.pem", comparisonIdentity(t, 512).Cert.Raw)
	// 展開順序為遠端0、無效1、本機2、遠端3，不可把清單旗標的位置當成索引。
	base := []string{"--targets-file", first, "--local", local, "--targets-file", second}
	for _, tc := range []struct {
		name  string
		extra []string
	}{
		{"IP錯綁本機", []string{"--connect-ip", "2=127.0.0.1"}},
		{"IP錯綁無效行", []string{"--connect-ip", "1=127.0.0.1"}},
		{"IP超界", []string{"--connect-ip", "4=127.0.0.1"}},
		{"IP重複", []string{"--connect-ip", "3=127.0.0.1", "--connect-ip", "03=::1"}},
		{"候選錯綁本機", []string{"--compare-cert", "2=" + candidate}},
		{"候選錯綁無效行", []string{"--compare-cert", "1=" + candidate}},
		{"候選超界", []string{"--compare-cert", "4=" + candidate}},
		{"候選重複", []string{"--compare-cert", "3=" + candidate, "--compare-cert", "03=" + candidate}},
		{"合法IP仍不得先排程", []string{"--connect-ip", "3=127.0.0.1", "--compare-cert", "2=" + candidate}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := New()
			a.Load = func(context.Context) config.Result {
				t.Fatal("非法映射不得讀設定或啟動後續流程")
				return config.Result{}
			}
			var out, diag bytes.Buffer
			args := append(append([]string(nil), base...), tc.extra...)
			if code := a.Run(t.Context(), args, &out, &diag); code != 2 || out.Len() != 0 || !strings.Contains(diag.String(), "Invalid arguments") {
				t.Fatal("非法展開索引未在前處理拒絕", code, diag.String())
			}
		})
	}
}
