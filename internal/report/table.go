package report

import (
	"bytes"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/vincent119/tlscheck/internal/i18n"
)

type tableReport struct {
	out             *bytes.Buffer
	t               *i18n.Translator
	width           int
	summary         bool
	err             error
	pending         []tableCheck
	pendingCodes    []Message
	diagnostics     []row
	diagnosticCount int
}

func (r *tableReport) text(key string) string { return r.t.Text("table."+key, nil) }

type tableCheck struct {
	check  Check
	source *Source
}

func (r *tableReport) grid(headers []string, data [][]string, widths []int) {
	if r.err != nil || len(data) == 0 {
		return
	}
	safe := make([][]string, len(data))
	for i, record := range data {
		safe[i] = make([]string, len(record))
		for j, value := range record {
			safe[i][j] = tableText(Safe(value))
		}
	}
	frame, err := tableGrid(headers, safe, widths)
	if err != nil {
		r.err = err
		return
	}
	fmt.Fprintln(r.out, frame)
	fmt.Fprintln(r.out)
}

func (r *tableReport) fields(rows []row) {
	if len(rows) == 0 {
		return
	}
	fieldWidth := tableDisplayWidth(label(r.t, "field"))
	for _, item := range rows {
		fieldWidth = max(fieldWidth, tableDisplayWidth(tableText(Safe(item.Label))))
	}
	fieldWidth = min(fieldWidth, (r.width-7)/2)
	data := make([][]string, len(rows))
	for i, item := range rows {
		value := item.Value
		if value == "" {
			value = label(r.t, "unknown")
		}
		data[i] = []string{item.Label, value}
	}
	r.grid([]string{label(r.t, "field"), label(r.t, "value")}, data, []int{fieldWidth, r.width - 7 - fieldWidth})
}

func (r *tableReport) block(title string, rows []row) {
	if r.err != nil || (len(rows) == 0 && len(r.pending) == 0 && len(r.pendingCodes) == 0) {
		return
	}
	heading, err := tableWrap(tableText(Safe(title)), r.width)
	if err != nil {
		r.err = err
		return
	}
	fmt.Fprintln(r.out, strings.Join(heading, "\n"))
	checks := [][]string{}
	ordered := make([]tableCheck, 0, len(r.pending))
	for _, failed := range []bool{true, false} {
		for _, entry := range r.pending {
			if (entry.check.Result.Status == "failed") == failed {
				ordered = append(ordered, entry)
			}
		}
	}
	for _, entry := range ordered {
		c := entry.check
		result := c.Result
		name := displayValue(r.t, "check", c.Name)
		if c.Name == "issues" {
			name = label(r.t, "issues")
		}
		// 只省略明確無問題的成功敘述；未知狀態與任何建議保守保留。
		if r.summary && result.Status == "passed" && result.Severity == "none" && result.Advice == nil {
			checks = append(checks, []string{name, tableStatus(r.t, result.Status), ""})
			continue
		}
		r.diagnosticCount++
		id := strconv.Itoa(r.diagnosticCount)
		description := result.Message
		if result.Severity != "none" && result.Severity != "" {
			description += "; " + label(r.t, "severity") + ": " + displayValue(r.t, "severity", result.Severity)
		}
		if result.Advice != nil {
			description += "; " + label(r.t, "advice") + ": " + result.Advice.Message
		}
		checks = append(checks, []string{"[" + id + "] " + name, tableStatus(r.t, result.Status), description})
		r.diagnostics = append(r.diagnostics, row{"[" + id + "]", title + " / " + name}, row{label(r.t, "severity"), displayValue(r.t, "severity", result.Severity)})
		if result.Code != "" {
			r.diagnostics = append(r.diagnostics, row{label(r.t, "code"), result.Code})
		}
		if result.Advice != nil {
			r.diagnostics = append(r.diagnostics, row{label(r.t, "advice") + " / " + label(r.t, "code"), result.Advice.Code})
		}
		if entry.source != nil {
			r.diagnostics = append(r.diagnostics, r.object(reflect.ValueOf(*entry.source))...)
		}
	}
	for _, message := range r.pendingCodes {
		r.diagnosticCount++
		id := strconv.Itoa(r.diagnosticCount)
		r.diagnostics = append(r.diagnostics, row{"[" + id + "]", title + " / " + label(r.t, "limitations")}, row{label(r.t, "code"), message.Code}, row{label(r.t, "message"), message.Message})
	}
	r.pending = nil
	r.pendingCodes = nil
	if len(checks) > 0 {
		available := r.width - 10
		nameWidth := tableDisplayWidth(r.text("check_item"))
		statusWidth := tableDisplayWidth(r.text("check_status"))
		for _, record := range checks {
			nameWidth = max(nameWidth, tableDisplayWidth(record[0]))
			statusWidth = max(statusWidth, tableDisplayWidth(record[1]))
		}
		nameWidth = min(nameWidth, available/2)
		statusWidth = min(statusWidth, available/3)
		r.grid([]string{r.text("check_item"), r.text("check_status"), r.text("check_description")}, checks, []int{nameWidth, statusWidth, available - nameWidth - statusWidth})
	}
	r.fields(rows)
}

// object只接受已清理Document的公開欄位；空集合合併說明，不省略未知數值、false或0。
func (r *tableReport) object(v reflect.Value, omit ...string) []row {
	skipped := map[string]bool{}
	for _, name := range omit {
		skipped[name] = true
	}
	rows := []row{}
	empty := []string{}
	for i := 0; i < v.NumField(); i++ {
		name := v.Type().Field(i).Tag.Get("json")
		if skipped[name] {
			continue
		}
		if v.Field(i).Kind() == reflect.Slice && v.Field(i).Len() == 0 {
			empty = append(empty, label(r.t, name))
			continue
		}
		// 維持既有分類值翻譯，避免把公開文字猜成訊息識別碼。
		category := ""
		switch {
		case v.Type() == reflect.TypeFor[Remote]() && name == "stage":
			category = "stage"
		case v.Type() == reflect.TypeFor[Certificate]() && name == "role":
			value := v.Field(i).String()
			if value == "site" || value == "ca" {
				value = r.t.Text("role."+value, nil)
			}
			rows = append(rows, row{label(r.t, name), value})
			continue
		}
		if category != "" {
			rows = append(rows, row{label(r.t, name), displayValue(r.t, category, v.Field(i).String())})
			continue
		}
		flatten(r.t, v.Field(i), label(r.t, name), &rows)
	}
	compact := rows
	if len(empty) > 0 {
		compact = append(compact, row{r.text("empty_fields"), strings.Join(empty, ", ")})
	}
	return compact
}

// checks保留typed檢查直到章節確定，避免依顯示文字猜測欄位或明細歸屬。
func (r *tableReport) checks(checks []Check) []row {
	for _, failed := range []bool{true, false} {
		for _, c := range checks {
			if (c.Result.Status == "failed") == failed {
				r.pending = append(r.pending, tableCheck{check: c})
			}
		}
	}
	return nil
}

func (r *tableReport) issues(issues []Issue) []row {
	rows := []row{}
	for _, issue := range issues {
		rows = append(rows, r.checks([]Check{{Name: label(r.t, "issues"), Result: issue.Result}})...)
		r.pending[len(r.pending)-1].source = issue.Source
		if issue.Source != nil {
			rows = append(rows, r.object(reflect.ValueOf(*issue.Source))...)
		}
	}
	return rows
}

func (r *tableReport) messages(messages []Message) []row {
	rows := []row{}
	for _, m := range messages {
		rows = append(rows, row{label(r.t, "limitations"), m.Message})
		r.pendingCodes = append(r.pendingCodes, m)
	}
	return rows
}

func (r *tableReport) chains(trust Trust) []row {
	rows := []row{}
	for i, chain := range trust.VerifiedChains {
		for j, c := range chain {
			rows = append(rows, row{fmt.Sprintf("%s [%d.%d]", label(r.t, "verified_chains"), i, j), c.ID}, row{label(r.t, "subject"), c.Subject}, row{label(r.t, "issuer"), c.Issuer})
		}
	}
	return rows
}

// inputFailures僅投影該occurrence的失敗，來源共用仍保留關聯，不參與全域計數。
func inputFailures(d Document, index int) []Check {
	failures := []Check{}
	add := func(checks []Check) {
		for _, c := range checks {
			if c.Result.Status == "failed" {
				failures = append(failures, c)
			}
		}
	}
	for _, remote := range d.Remote {
		if remote.InputIndex == index {
			add(remote.Checks)
			add(remote.Trust.Checks)
			for _, issue := range remote.Issues {
				add([]Check{{Name: "issues", Result: issue.Result}})
			}
		}
	}
	for _, c := range d.Local.Certificates {
		matched := false
		for _, source := range c.Sources {
			if source.InputIndex == index {
				matched = true
				break
			}
		}
		if matched {
			add(c.Checks)
			add(c.Trust.Checks)
			if c.Pairing != nil {
				add([]Check{{Name: "pairing", Result: *c.Pairing}})
			}
		}
	}
	for _, key := range d.Local.Keys {
		if key.Source.InputIndex == index {
			add(key.Checks)
		}
	}
	for _, issue := range d.Local.Issues {
		if issue.Source != nil && issue.Source.InputIndex == index {
			add([]Check{{Name: "issues", Result: issue.Result}})
		}
	}
	return failures
}

func renderTable(out *bytes.Buffer, d Document, width int) error {
	return renderTableDetail(out, d, width, DetailFull)
}

func renderTableDetail(out *bytes.Buffer, d Document, width int, detail Detail) error {
	r := tableReport{out: out, t: i18n.New(d.Language), width: width, summary: detail == DetailSummary}
	if width < 40 {
		return fmt.Errorf("表格可用欄寬不足")
	}
	summary := []row{{label(r.t, "inputs"), strconv.Itoa(len(d.Inputs))}}
	summary = append(summary, r.object(reflect.ValueOf(d.Summary))...)
	// Summary分類翻譯由同一既有規則處理，數字只讀既有快照。
	for i := range summary {
		if summary[i].Label == label(r.t, "highest_severity") {
			summary[i].Value = displayValue(r.t, "severity", d.Summary.HighestSeverity)
		}
	}
	scopeNote := r.text("scope_note")
	if r.summary && len(d.Inputs) == 1 {
		scopeNote = r.text("single_scope_note")
	}
	summary = append(summary, row{r.text("scope"), scopeNote})
	r.block(r.text("global_checks"), summary)
	views := map[int]InputView{}
	inputViews := d.Presentation.Inputs
	if len(inputViews) == 0 && len(d.Inputs) > 0 {
		inputViews = present(d).Inputs
	}
	for _, v := range inputViews {
		views[v.Index] = v
	}
	if len(d.Inputs) > 1 {
		rows := []row{}
		for _, input := range d.Inputs {
			v := views[input.Index]
			rows = append(rows, row{fmt.Sprintf("[%d]", input.Index), displayValue(r.t, "kind", input.Kind) + "; " + v.Target + "; " + r.t.Text("status."+v.Status, nil) + " (" + displayValue(r.t, "severity", v.HighestSeverity) + "); " + r.t.Text("summary.counts", i18n.Params{"Passed": strconv.Itoa(v.Passed), "Failed": strconv.Itoa(v.Failed), "NotPerformed": strconv.Itoa(v.NotPerformed)})})
		}
		r.block(label(r.t, "input_summary"), rows)
	}
	for _, input := range d.Inputs {
		rows := []row{{label(r.t, "kind"), displayValue(r.t, "kind", input.Kind)}}
		if input.Target != nil {
			rows = append(rows, row{label(r.t, "target"), *input.Target})
		}
		if input.LocalSource != nil {
			rows = append(rows, row{label(r.t, "local_source"), *input.LocalSource})
		}
		if v, ok := views[input.Index]; ok {
			rows = append(rows, row{label(r.t, "result"), r.t.Text("status."+v.Status, nil)})
			if !r.summary || v.HighestSeverity != "none" {
				rows = append(rows, row{label(r.t, "severity"), displayValue(r.t, "severity", v.HighestSeverity)})
			}
			if !r.summary {
				rows = append(rows, row{r.text("applicable_checks"), r.t.Text("summary.counts", i18n.Params{"Passed": strconv.Itoa(v.Passed), "Failed": strconv.Itoa(v.Failed), "NotPerformed": strconv.Itoa(v.NotPerformed)})})
			}
		}
		if !r.summary {
			rows = append(rows, r.checks(inputFailures(d, input.Index))...)
		}
		r.block(fmt.Sprintf("%s [%d]", label(r.t, "inputs"), input.Index), rows)
	}
	if len(d.Inputs) == 0 {
		r.block(label(r.t, "inputs"), []row{{"", r.text("none")}})
	}
	for _, remote := range d.Remote {
		checks := append([]Check{}, remote.Checks...)
		checks = append(checks, remote.Trust.Checks...)
		rows := r.checks(checks)
		rows = append(rows, r.issues(remote.Issues)...)
		if r.summary {
			if remote.TLS != nil {
				rows = append(rows, r.selected(reflect.ValueOf(*remote.TLS), "version", "cipher_suite")...)
			} else {
				rows = append(rows, row{label(r.t, "tls"), label(r.t, "unknown")})
			}
			// 遠端憑證順序沿用握手所觀測的鏈，不以 CN 或名稱猜測葉憑證。
			if len(remote.Certificates) > 0 {
				rows = append(rows, r.certificateSummary(remote.Certificates[0])...)
				for i, c := range remote.Certificates[1:] {
					if c.Expired || c.ExpiringSoon {
						rows = append(rows, row{label(r.t, "certificates"), strconv.Itoa(i + 1)})
						rows = append(rows, r.certificateSummary(c)...)
					}
				}
			} else {
				rows = append(rows, row{label(r.t, "certificates"), label(r.t, "unknown")})
			}
		} else {
			rows = append(rows, r.object(reflect.ValueOf(remote), "input_index", "target", "certificates", "checks", "trust", "limitations", "issues")...)
			for i, c := range remote.Certificates {
				rows = append(rows, row{fmt.Sprintf("%s [%d]", label(r.t, "certificates"), i), c.ID})
			}
			rows = append(rows, r.chains(remote.Trust)...)
		}
		rows = append(rows, r.messages(remote.Limitations)...)
		r.block(fmt.Sprintf("%s [%d] %s", label(r.t, "remote"), remote.InputIndex, remote.Target), rows)
	}
	// 本機證據依穩定ID引用共同憑證明細，來源／配對／驗證鏈仍逐筆保留。
	for i, c := range d.Local.Certificates {
		rows := r.checks(c.Checks)
		rows = append(rows, r.checks(c.Trust.Checks)...)
		if c.Pairing != nil {
			rows = append(rows, r.checks([]Check{{Name: "pairing", Result: *c.Pairing}})...)
		}
		if r.summary {
			rows = append(rows, r.selected(reflect.ValueOf(c), "role", "sources", "matching_keys")...)
			rows = append(rows, r.certificateSummary(c.Info)...)
		} else {
			rows = append(rows, r.object(reflect.ValueOf(c), "info", "checks", "trust", "pairing")...)
			rows = append(rows, row{label(r.t, "certificate_id"), c.Info.ID})
			rows = append(rows, r.chains(c.Trust)...)
		}
		r.block(fmt.Sprintf("%s / %s [%d]", label(r.t, "local"), label(r.t, "certificates"), i), rows)
	}
	for i, key := range d.Local.Keys {
		rows := r.checks(key.Checks)
		omitted := []string{"checks", "limitations"}
		if key.Curve == nil && key.Algorithm != "ECDSA" {
			omitted = append(omitted, "curve")
		}
		if r.summary {
			rows = append(rows, r.selected(reflect.ValueOf(key), "id", "source", "format", "algorithm", "bits")...)
			if key.Algorithm == "ECDSA" {
				rows = append(rows, r.selected(reflect.ValueOf(key), "curve")...)
			}
		} else {
			rows = append(rows, r.object(reflect.ValueOf(key), omitted...)...)
		}
		rows = append(rows, r.messages(key.Limitations)...)
		r.block(fmt.Sprintf("%s / %s [%d]", label(r.t, "local"), label(r.t, "keys"), i), rows)
	}
	sourceIssues, sharedIssues := []Issue{}, []Issue{}
	for _, issue := range d.Local.Issues {
		if issue.Source == nil {
			sharedIssues = append(sharedIssues, issue)
		} else {
			sourceIssues = append(sourceIssues, issue)
		}
	}
	r.block(label(r.t, "local")+" / "+label(r.t, "issues"), r.issues(sourceIssues))
	shared := r.checks(d.Local.Checks)
	shared = append(shared, r.issues(sharedIssues)...)
	r.block(r.text("shared_checks"), shared)
	if len(d.Local.Pairs) > 0 {
		rows := []row{}
		for _, pair := range d.Local.Pairs {
			certificateID := pair.CertificateID
			if r.summary {
				for i, c := range d.Local.Certificates {
					if c.Info.ID == certificateID {
						certificateID = fmt.Sprintf("%s [%d]", label(r.t, "certificates"), i)
						break
					}
				}
			}
			rows = append(rows, row{pair.KeyID, certificateID})
		}
		r.block(label(r.t, "pair_table"), rows)
	}
	if !r.summary {
		certificates := []PublicCertificate{}
		for _, c := range d.Local.Certificates {
			certificates = append(certificates, c.Info)
		}
		for _, remote := range d.Remote {
			certificates = append(certificates, remote.Certificates...)
		}
		seen := map[string][]PublicCertificate{}
		for i, c := range certificates {
			duplicate := false
			if c.ID != "" {
				for _, previous := range seen[c.ID] {
					if reflect.DeepEqual(previous, c) {
						duplicate = true
						break
					}
				}
			}
			if duplicate {
				continue
			}
			seen[c.ID] = append(seen[c.ID], c)
			omitted := []string{}
			if c.PublicKeyCurve == nil && c.PublicKeyAlgorithm != "ECDSA" {
				omitted = append(omitted, "public_key_curve")
			}
			r.block(fmt.Sprintf("%s [%d]", label(r.t, "certificates"), i), r.object(reflect.ValueOf(c), omitted...))
		}
		metadata := r.object(reflect.ValueOf(d.Tool))
		metadata = append(metadata, row{label(r.t, "generated_at"), d.GeneratedAt})
		r.block(label(r.t, "tool"), metadata)
	}
	r.block(r.text("diagnostics"), r.diagnostics)
	if r.summary {
		fmt.Fprintln(r.out, r.text("detail_hint"))
	}
	return r.err
}

// selected 依欄位白名單選擇摘要，不以值為空或字面內容推測是否重要。
func (r *tableReport) selected(v reflect.Value, names ...string) []row {
	allowed := map[string]bool{}
	for _, name := range names {
		allowed[name] = true
	}
	omitted := []string{}
	for i := 0; i < v.NumField(); i++ {
		name := v.Type().Field(i).Tag.Get("json")
		if !allowed[name] {
			omitted = append(omitted, name)
		}
	}
	return r.object(v, omitted...)
}

func (r *tableReport) certificateSummary(c PublicCertificate) []row {
	rows := r.selected(reflect.ValueOf(c), "subject", "public_key_algorithm", "public_key_bits", "not_after", "expired", "expiring_soon")
	if c.PublicKeyAlgorithm == "ECDSA" {
		rows = append(rows, r.selected(reflect.ValueOf(c), "public_key_curve")...)
	}
	if c.NotAfter != nil {
		rows = append(rows, r.selected(reflect.ValueOf(c), "remaining_days")...)
	} else {
		rows = append(rows, row{label(r.t, "remaining_days"), label(r.t, "unknown")})
	}
	return rows
}

func tableStatus(t *i18n.Translator, status string) string {
	switch status {
	case "passed", "failed", "not_performed":
		return t.Text("status."+status, nil)
	}
	return status
}
