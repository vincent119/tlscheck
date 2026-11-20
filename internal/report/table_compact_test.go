package report

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func compactFixture(lang string) Document {
	path := "synthetic-chain.pem"
	expiry := "2039-06-05T07:41:22Z"
	bits := 4096
	d := Document{Language: lang, SchemaVersion: 1, Inputs: []Input{{Index: 0, Kind: "local", LocalSource: &path}}, Summary: Summary{Passed: 3, NotPerformed: 4, HighestSeverity: "none"}}
	for i := 0; i < 3; i++ {
		d.Local.Certificates = append(d.Local.Certificates, Certificate{Info: PublicCertificate{ID: fmt.Sprint(i), Subject: fmt.Sprintf("CA-subject-%d", i), PublicKeyAlgorithm: "RSA", PublicKeyBits: &bits, NotAfter: &expiry, RemainingDays: 4580}, Role: "ca", Sources: []Source{{Path: path, InputIndex: 0, Block: i + 1, Encoding: "PEM"}}, Checks: []Check{{Name: "parse", Result: Result{Status: "passed", Severity: "none", Code: "certificate.parsed", Message: "parsed"}}, {Name: "pairing", Result: Result{Status: "not_performed", Severity: "none", Code: "pairing.no_private_keys", Message: "shared-limit-canary"}}}})
	}
	d.Local.Checks = []Check{{Name: "pairing", Result: Result{Status: "not_performed", Severity: "none", Code: "pairing.no_private_keys", Message: "shared-limit-canary"}}}
	return d
}

func TestCompactLocalSummaryRetainsFactsAndFullContract(t *testing.T) {
	for _, lang := range []string{"en", "zh-TW", "zh-CN"} {
		d := compactFixture(lang)
		before, _ := json.Marshal(d)
		var full bytes.Buffer
		if err := RenderWithOptions(&full, "table", d, RenderOptions{Detail: DetailFull}); err != nil {
			t.Fatal(err)
		}

		for _, width := range []int{40, 80, 120} {
			var out bytes.Buffer
			if err := renderTableDetail(&out, d, width, DetailSummary); err != nil {
				t.Fatal(err)
			}
			text := detailCanaryText(out.String())
			if !strings.Contains(text, "CA-subject-0;RSA4096") {
				t.Fatal("摘要欄位分隔遺失", lang, width)
			}
			if strings.Count(text, "shared-limit-canary") != 1 {
				t.Fatal("共用限制未集中一次", lang, width)
			}
			for i := 0; i < 3; i++ {
				if !strings.Contains(text, fmt.Sprintf("CA-subject-%d", i)) {
					t.Fatal("憑證列遺失")
				}
			}
			for _, line := range strings.Split(out.String(), "\n") {
				if tableDisplayWidth(line) > width {
					t.Fatal("表格超寬", lang, width)
				}
			}
			if width == 80 && len(strings.Split(out.String(), "\n")) > 100 {
				t.Fatal("三張CA摘要仍過長", lang)
			}
		}
		after, _ := json.Marshal(d)
		if !bytes.Equal(before, after) {
			t.Fatal("摘要變動Document與計數")
		}
	}
}

func TestCompactSummaryDoesNotMergeDistinctProblems(t *testing.T) {
	d := compactFixture("en")
	base := d.Local.Certificates[0].Checks[1]
	d.Local.Certificates[1].Checks[1].Result.Message = "different-reason-canary"
	d.Local.Certificates[2].Checks[1].Result.Severity = "warning"
	d.Local.Certificates[2].Checks[1].Result.Advice = &Message{Code: "advice-code-canary", Message: "advice-message-canary"}
	failed := base
	failed.Result.Status = "failed"
	failed.Result.Message = "failed-owner-canary"
	unknown := base
	unknown.Result.Status = "future"
	unknown.Result.Message = "unknown-owner-canary"
	d.Local.Certificates[0].Checks = append(d.Local.Certificates[0].Checks, failed, unknown)
	d.Local.Certificates[1].Checks = append(d.Local.Certificates[1].Checks, failed)
	d.Local.Certificates[0].Sources = append(d.Local.Certificates[0].Sources, Source{Path: "different-source-canary.pem", InputIndex: 9, Block: 2, Encoding: "DER"})
	d.Local.Certificates[0].Info.Expired = true
	d.Local.Certificates[1].Info.ExpiringSoon = true
	var out bytes.Buffer
	if err := RenderWithOptions(&out, "table", d, RenderOptions{}); err != nil {
		t.Fatal(err)
	}
	text := detailCanaryText(out.String())
	for _, want := range []string{"different-reason-canary", "advice-code-canary", "advice-message-canary", "unknown-owner-canary", "different-source-canary.pem"} {
		if !strings.Contains(text, want) {
			t.Fatal("問題／來源遺失", want)
		}
	}
	if strings.Count(text, "failed-owner-canary") != 2 {
		t.Fatal("失敗項目被合併")
	}
}

func TestCompactFullTableBaseline(t *testing.T) {
	for _, lang := range []string{"en", "zh-TW", "zh-CN"} {
		var out bytes.Buffer
		if err := RenderWithOptions(&out, "table", compactFixture(lang), RenderOptions{Detail: DetailFull}); err != nil {
			t.Fatal(err)
		}
		want := map[string]string{"en": "6b420e3d365d1093a13f4eeef57f08c1dc4d9f0e58bea7ed86d25539719c1187", "zh-TW": "eae526ad6c15f88cf6517bddaa4a7f71b49d3801634c68402d52cb2fea9f23d3", "zh-CN": "669154105f520b3094a256a118c15bd90514610ff38af28c76680b175066e1d7"}
		if fmt.Sprintf("%x", sha256.Sum256(out.Bytes())) != want[lang] {
			t.Fatal("完整模式輸出改變", lang)
		}
	}
}

func TestCompactSummaryKeepsDistinctCodesNamesAndOccurrences(t *testing.T) {
	for _, field := range []string{"code", "name", "severity", "advice", "duplicate"} {
		t.Run(field, func(t *testing.T) {
			d := compactFixture("en")
			c := &d.Local.Certificates[1].Checks[1]
			switch field {
			case "code":
				c.Result.Code = "different-code-canary"
			case "name":
				c.Name = "different-check-canary"
			case "severity":
				c.Result.Severity = "verification"
			case "advice":
				c.Result.Advice = &Message{Code: "another-advice-code", Message: "another-advice-message"}
			case "duplicate":
				d.Local.Certificates[0].Checks = append(d.Local.Certificates[0].Checks, d.Local.Certificates[0].Checks[1])
			}
			var out bytes.Buffer
			if err := RenderWithOptions(&out, "table", d, RenderOptions{}); err != nil {
				t.Fatal(err)
			}
			text := detailCanaryText(out.String())
			if strings.Count(text, "shared-limit-canary") != 2 {
				t.Fatal("不同檢查或同物件重複項目被錯誤合併", field)
			}
		})
	}
}
