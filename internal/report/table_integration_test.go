package report

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

func TestNonTableFormatsKeepTheirOutputContract(t *testing.T) {
	want := map[string]string{"en/json": "2c4c02bcc0bdc907739e5c65c8f0d040718e368432211e958cf538cfd5cd3062", "en/html": "4dfd490d489de22af9bab5d380e6dd4936f128e18c9cfe62b196a050b365f784", "en/markdown": "d7aea03ae6dcef71c686726b9ba0216b2462a5563f5bf217c8913c7c3b0af36f", "zh-TW/json": "0a3ff25344cd39c99d8d2a8e9770ca68f8e70dd5989675ceb5f9b30c45ecefa4", "zh-TW/html": "41413f431003f7c2c867bf06358f4911ebc75b0a9f90fbc3a01f37d8496ab679", "zh-TW/markdown": "7be5235eead08b4efa83af055162a7b9e8d5b6b7d11349b245ef3e99d27b7f78", "zh-CN/json": "43f9ed7d5881a2c50180609973b6cff57c3a05f57f3827ad01b84baf35fe01af", "zh-CN/html": "e3845637fdc67b711dc3ab47010a39b0e24e73c5f68c13ed770ec3aba0eaf51f", "zh-CN/markdown": "8c70e861c26668929e00392e218eddf0cc3e6efe393432518d16a6fe9651257e"}

	for _, lang := range []string{"en", "zh-TW", "zh-CN"} {
		d := localizedFixture(lang)
		d.GeneratedAt = "2026-11-19T00:00:00Z"
		for _, format := range []string{"json", "html", "markdown"} {
			var out bytes.Buffer
			if err := Render(&out, format, d); err != nil {
				t.Fatal("產生契約基準失敗", err)
			}
			if got := fmt.Sprintf("%x", sha256.Sum256(out.Bytes())); got != want[lang+"/"+format] {
				t.Fatal("其他格式的輸出契約被改動", lang, format)
			}
		}
	}
}

func TestTableSeparatesCheckScopesAndOmitsEmptyPairGrid(t *testing.T) {
	d := localizedFixture("en")
	d.Summary = Summary{Passed: 6, NotPerformed: 3}
	d.Local.Checks = []Check{{Name: "pairing", Result: Result{Status: "not_performed", Severity: "none", Code: "pairing.no_private_keys", Message: "No private keys were provided."}}}
	before := d.Summary
	var out bytes.Buffer
	if err := Render(&out, "table", d); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Global checks", "Applicable checks", "Shared / global checks", "No private keys were provided."} {
		if !strings.Contains(out.String(), want) {
			t.Fatal("缺少閱讀結構與統計範圍", want)
		}
	}
	if strings.Contains(out.String(), "Pair table") || strings.Contains(out.String(), "[]") {
		t.Fatal("不應輸出空配對表或空集合陣列字面值")
	}
	if d.Summary != before {
		t.Fatal("table不應重算全域計數")
	}
}

func TestTableRetainsLiteralArrayTextAndUnknownCertificateFields(t *testing.T) {
	d := localizedFixture("en")
	d.Local.Certificates[0].Info.Subject = "[]"
	d.Local.Certificates[0].Info.PublicKeyAlgorithm = "RSA"
	var out bytes.Buffer
	if err := Render(&out, "table", d); err != nil {
		t.Fatal(err)
	}
	if tablePairCount(out.String(), "Subject", "[]") != 1 || tablePairCount(out.String(), "Not after (UTC)", "Unknown / not observed") != 1 {
		t.Fatal("公開字串或必要未知欄位被當空集合省略", out.String())
	}
	if tablePairCount(out.String(), "public key curve", "Unknown / not observed") > 0 {
		t.Fatal("RSA不適用的曲線不應顯示")
	}
}

func TestTableGroupsRepeatedCertificatesWithoutChangingSourcesOrPairs(t *testing.T) {
	d := localizedFixture("en")
	c := d.Local.Certificates[0].Info
	c.ID = "shared-cert"
	c.Subject = "unique shared subject"
	d.Local.Certificates[0].Info = c
	d.Remote[0].Certificates = []PublicCertificate{c}
	d.Local.Pairs = []Pair{{KeyID: "key:0", CertificateID: c.ID}}
	d.Remote[0].Trust.VerifiedChains = [][]ChainCertificate{{{ID: "root-only", Subject: "root subject", Issuer: "root issuer"}}}
	var out bytes.Buffer
	if err := Render(&out, "table", d); err != nil {
		t.Fatal(err)
	}
	if tablePairCount(out.String(), "Subject", "unique shared subject") != 1 {
		t.Fatal("共同憑證明細重複或遺失")
	}
	for _, want := range []string{"parse-execution.pem", "key:0", "shared-cert", "root-only", "root subject", "root issuer"} {
		if !strings.Contains(out.String(), want) {
			t.Fatal("來源／配對／驗證鏈資訊遺失", want)
		}
	}
}

func TestTableScopesKeepRemoteAndGlobalCountsDistinct(t *testing.T) {
	d := localizedFixture("en")
	d.Inputs = d.Inputs[1:]
	d.Local = Local{Checks: []Check{{Name: "pairing", Result: Result{Code: "pairing.no_private_keys", Status: "not_performed", Severity: "none", Message: "No private keys were provided."}}}}
	checks := []Check{}
	for _, name := range []string{"dns", "connection", "handshake", "trust", "hostname", "server_usage"} {
		checks = append(checks, Check{Name: name, Result: Result{Code: name, Status: "passed", Severity: "none", Message: name}})
	}
	for _, name := range []string{"aia", "revocation"} {
		checks = append(checks, Check{Name: name, Result: Result{Code: name, Status: "not_performed", Severity: "none", Message: name}})
	}
	d.Remote[0].Checks = checks
	d.Remote[0].Trust = Trust{}
	d.Summary = Summary{Passed: 6, NotPerformed: 3, HighestSeverity: "none"}
	d.Presentation = present(d)
	var out bytes.Buffer
	if err := Render(&out, "table", d); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Passed: 6; failed: 0; not performed: 2.", "No private keys were provided."} {
		if !strings.Contains(out.String(), want) {
			t.Fatal("全域與逐輸入範圍顯示錯誤", want, out.String())
		}
	}
	if tablePairCount(out.String(), "not performed", "3") != 1 {
		t.Fatal("全域未執行數沒有保留")
	}
	if d.Summary.NotPerformed != 3 || d.Presentation.Inputs[0].NotPerformed != 2 {
		t.Fatal("渲染改寫統計")
	}
}

func TestTableDoesNotLabelSourceSpecificIssuesAsShared(t *testing.T) {
	d := localizedFixture("en")
	d.Local.Checks = []Check{{Name: "pairing", Result: Result{Code: "pairing.no_private_keys", Status: "not_performed", Severity: "none", Message: "No private keys were provided."}}}
	d.Local.Issues = []Issue{{Source: &Source{Path: "broken.pem", InputIndex: 0}, Result: Result{Code: "input.bad", Status: "failed", Severity: "execution", Message: "scoped-failure"}}}
	var out bytes.Buffer
	if err := Render(&out, "table", d); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	at := strings.Index(text, "Shared / global checks")
	if at < 0 || !strings.Contains(text[:at], "scoped-failure") || strings.Contains(text[at:], "scoped-failure") {
		t.Fatal("來源專屬問題被誤標為共用檢查")
	}
}

func TestTableUsesFieldAndCheckColumnHeaders(t *testing.T) {
	var out bytes.Buffer
	if err := Render(&out, "table", localizedFixture("en")); err != nil {
		t.Fatal(err)
	}
	for _, headers := range [][]string{{"Field", "Value"}, {"Check item", "Status", "Description"}} {
		found := false
		for _, line := range strings.Split(out.String(), "\n") {
			cells := strings.Split(line, "|")
			if len(cells) != len(headers)+2 {
				continue
			}
			match := true
			for i, header := range headers {
				if strings.TrimSpace(cells[i+1]) != header {
					match = false
				}
			}
			found = found || match
		}
		if !found {
			t.Fatal("缺少真正的多欄表頭", headers)
		}
	}
}

func TestTableKeepsAllDiagnosticCodesOnlyInTrailingDetails(t *testing.T) {
	d := localizedFixture("en")
	d.Remote[0].Checks[0].Result.Advice = &Message{Code: "advice.custom", Message: "Use a valid endpoint."}
	d.Remote[0].Limitations = []Message{{Code: "custom.limit", Message: "Synthetic limit."}}
	var out bytes.Buffer
	if err := Render(&out, "table", d); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	at := strings.Index(text, "Diagnostic details")
	if at < 0 || at < strings.LastIndex(text, "Generated at") {
		t.Fatal("診斷明細沒有集中於報告後方")
	}
	for _, code := range []string{"remote.handshake_failed", "certificate.parsed", "advice.custom", "custom.limit"} {
		if strings.Contains(text[:at], code) || !strings.Contains(text[at:], code) {
			t.Fatal("代碼遺失或仍穿插前台", code)
		}
	}
	if !strings.Contains(text[:at], "Use a valid endpoint.") || !strings.Contains(text[at:], "Remote [1] example.com:443") {
		t.Fatal("建議或明細目標關聯遺失")
	}
}

// 此helper只比對無邊界空白的固定欄位；空白完整性另以精確grid斷言驗證。
func tablePairCount(text, key, value string) int {
	count := 0
	for _, line := range strings.Split(text, "\n") {
		cells := strings.Split(line, "|")
		if len(cells) == 4 && strings.TrimSpace(cells[1]) == key && strings.TrimSpace(cells[2]) == value {
			count++
		}
	}
	return count
}
