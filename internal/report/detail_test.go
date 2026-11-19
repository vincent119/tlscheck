package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestSummaryKeepsProblemsAndFullKeepsAllFacts(t *testing.T) {
	for _, lang := range []string{"en", "zh-TW", "zh-CN"} {
		d := localizedFixture(lang)
		d.Remote[0].Checks = append(d.Remote[0].Checks, Check{Name: "dns", Result: Result{Status: "passed", Severity: "none", Code: "success-code-canary", Message: "success-message-canary"}}, Check{Name: "hostname", Result: Result{Status: "failed", Severity: "verification", Code: "failure-code-canary", Message: "failure-message-canary", Advice: &Message{Code: "advice-code-canary", Message: "advice-message-canary"}}}, Check{Name: "new-check", Result: Result{Status: "future-status", Severity: "none", Code: "future-code-canary", Message: "future-message-canary"}})
		d.Remote[0].Limitations = append(d.Remote[0].Limitations, Message{Code: "limit-code-canary", Message: "limit-message-canary"})
		d.Remote[0].Checks = append(d.Remote[0].Checks, Check{Name: "dns", Result: Result{Status: "passed", Severity: "warning", Code: "warning-code-canary", Message: "warning-message-canary"}})
		d.Local.Certificates[0].Info.SerialNumber = "serial-full-only-canary"
		before, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		var summary, full bytes.Buffer
		if err := RenderWithOptions(&summary, "table", d, RenderOptions{}); err != nil {
			t.Fatal(err)
		}
		if err := RenderWithOptions(&full, "table", d, RenderOptions{Detail: DetailFull}); err != nil {
			t.Fatal(err)
		}
		for _, v := range []string{"failure-code-canary", "failure-message-canary", "advice-code-canary", "advice-message-canary", "limit-code-canary", "limit-message-canary", "future-code-canary", "future-message-canary", "warning-code-canary", "warning-message-canary"} {
			if !strings.Contains(detailCanaryText(summary.String()), v) || !strings.Contains(detailCanaryText(full.String()), v) {
				t.Fatal("問題或限制遺失", lang, v)
			}
		}
		for _, v := range []string{"serial-full-only-canary", "success-code-canary", "success-message-canary"} {
			if strings.Contains(detailCanaryText(summary.String()), v) || !strings.Contains(detailCanaryText(full.String()), v) {
				t.Fatal("摘要省略或完整模式契約不符", lang, v)
			}
		}
		after, err := json.Marshal(d)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("渲染改寫 Document")
		}
		if !strings.Contains(summary.String(), "--detail full") {
			t.Fatal("缺少完整模式提示")
		}
	}
}

func TestDetailDoesNotChangeOtherFormats(t *testing.T) {
	for _, lang := range []string{"en", "zh-TW", "zh-CN"} {
		for _, format := range []string{"json", "html", "markdown"} {
			d := localizedFixture(lang)
			var before bytes.Buffer
			if err := Render(&before, format, d); err != nil {
				t.Fatal(err)
			}
			for _, detail := range []Detail{"", DetailSummary, DetailFull} {
				var out bytes.Buffer
				if err := RenderWithOptions(&out, format, d, RenderOptions{Detail: detail}); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(before.Bytes(), out.Bytes()) {
					t.Fatal("detail 改變其他格式", lang, format)
				}
			}
		}
	}
	var out bytes.Buffer
	if err := RenderWithOptions(&out, "json", localizedFixture("en"), RenderOptions{Detail: "invalid"}); err == nil || out.Len() != 0 {
		t.Fatal("非法 detail 不得寫入輸出")
	}
}

// 只供無空白 canary 跨布局續行搜尋，值內空白另由精確布局測試驗證。
func detailCanaryText(s string) string {
	columns := make([]strings.Builder, 4)
	for _, line := range strings.Split(s, "\n") {
		parts := strings.Split(line, "|")
		for i := 1; i < len(parts)-1 && i <= len(columns); i++ {
			columns[i-1].WriteString(strings.ReplaceAll(parts[i], " ", ""))
		}
	}
	var out strings.Builder
	for i := range columns {
		out.WriteString(columns[i].String())
		out.WriteString("\n")
	}
	return out.String()
}

func TestSummaryScopesAndWidths(t *testing.T) {
	for _, lang := range []string{"en", "zh-TW", "zh-CN"} {
		d := localizedFixture(lang)
		d.Inputs = d.Inputs[1:]
		d.Local = Local{Checks: []Check{{Name: "pairing", Result: Result{Status: "not_performed", Severity: "none", Code: "pairing.no_private_keys", Message: "no-key-canary"}}}}
		d.Presentation = Presentation{}
		d.Summary = Summary{Passed: 6, NotPerformed: 3, HighestSeverity: "none"}
		for _, width := range []int{40, 80, 120} {
			var out bytes.Buffer
			if err := renderTableDetail(&out, d, width, DetailSummary); err != nil {
				t.Fatal(err)
			}
			for _, line := range strings.Split(out.String(), "\n") {
				if tableDisplayWidth(line) > width {
					t.Fatal("摘要超出欄寬", lang, width, line)
				}
			}
			if !strings.Contains(detailCanaryText(out.String()), "no-key-canary") {
				t.Fatal("共用未執行原因遺失")
			}
			if d.Summary.Passed != 6 || d.Summary.NotPerformed != 3 {
				t.Fatal("摘要重算全域統計")
			}
			if lang == "en" && strings.Contains(out.String(), "Applicable checks") {
				t.Fatal("單輸入不應重複計數")
			}
		}
	}
}

func TestSummaryDoesNotHideIntermediateExpiryWarnings(t *testing.T) {
	d := localizedFixture("en")
	d.Remote[0].Certificates = []PublicCertificate{{Subject: "leaf"}, {Subject: "intermediate-warning-canary", ExpiringSoon: true}}
	var out bytes.Buffer
	if err := RenderWithOptions(&out, "table", d, RenderOptions{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(detailCanaryText(out.String()), "intermediate-warning-canary") {
		t.Fatal("中繼憑證到期提醒被摘要隱藏")
	}
}
