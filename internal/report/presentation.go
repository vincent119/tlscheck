package report

import (
	"strconv"

	"github.com/vincent119/tlscheck/internal/i18n"
)

// Presentation 是安全事實的衍生視圖，不進入 JSON 契約，也不影響全域檢查計數。
type Presentation struct{ Inputs []InputView }

// InputView 保留各 occurrence 的適用結果，重複來源不會被去重。
type InputView struct {
	Index                                 int
	Kind, Target, Status, HighestSeverity string
	Passed, Failed, NotPerformed          int
}

func present(d Document) Presentation {
	p := Presentation{Inputs: make([]InputView, len(d.Inputs))}
	byIndex := make(map[int]*InputView, len(d.Inputs))
	local := map[int]bool{}
	for i, input := range d.Inputs {
		target := ""
		if input.Target != nil {
			target = *input.Target
		}
		if input.LocalSource != nil {
			target = *input.LocalSource
		}
		p.Inputs[i] = InputView{Index: input.Index, Kind: input.Kind, Target: target, Status: "not_performed", HighestSeverity: "none"}
		byIndex[input.Index] = &p.Inputs[i]
		local[input.Index] = input.Target == nil && input.Kind != "remote"
	}
	add := func(index int, r Result) {
		v := byIndex[index]
		if v == nil || r.Code == "" {
			return
		}
		switch r.Status {
		case "passed":
			v.Passed++
		case "failed":
			v.Failed++
		default:
			v.NotPerformed++
		}
		if r.Severity == "execution" || r.Severity == "verification" && v.HighestSeverity == "none" {
			v.HighestSeverity = r.Severity
		}
		if v.Failed > 0 {
			v.Status = "failed"
		} else if v.Passed > 0 {
			v.Status = "passed"
		}
	}
	checks := func(index int, values []Check) {
		for _, value := range values {
			add(index, value.Result)
		}
	}
	for _, cert := range d.Local.Certificates {
		seen := map[int]bool{}
		for _, s := range cert.Sources {
			if seen[s.InputIndex] {
				continue
			}
			seen[s.InputIndex] = true
			checks(s.InputIndex, cert.Checks)
			checks(s.InputIndex, cert.Trust.Checks)
			if cert.Pairing != nil {
				add(s.InputIndex, *cert.Pairing)
			}
		}
	}
	for _, key := range d.Local.Keys {
		checks(key.Source.InputIndex, key.Checks)
	}
	for _, issue := range d.Local.Issues {
		if issue.Source != nil {
			add(issue.Source.InputIndex, issue.Result)
		} else {
			for index, isLocal := range local {
				if isLocal {
					add(index, issue.Result)
				}
			}
		}
	}
	for _, r := range d.Remote {
		if r.Comparison != nil {
			add(r.InputIndex, r.Comparison.Result)
		}
		checks(r.InputIndex, r.Checks)
		checks(r.InputIndex, r.Trust.Checks)
		for _, issue := range r.Issues {
			add(r.InputIndex, issue.Result)
		}
	}
	return p
}

type grid struct {
	Title   string
	Headers []string
	Rows    [][]string
	Widths  []int
}

func humanGrids(d Document, t *i18n.Translator) []grid {
	summary := grid{Title: t.Text("document.input_summary", nil), Headers: []string{label(t, "input_index"), label(t, "kind"), label(t, "target"), label(t, "result"), label(t, "severity")}, Rows: [][]string{}, Widths: []int{6, 8, 32, 28, 14}}
	for _, v := range d.Presentation.Inputs {
		counts := t.Text("summary.counts", i18n.Params{"Passed": strconv.Itoa(v.Passed), "Failed": strconv.Itoa(v.Failed), "NotPerformed": strconv.Itoa(v.NotPerformed)})
		summary.Rows = append(summary.Rows, []string{strconv.Itoa(v.Index), displayValue(t, "kind", v.Kind), v.Target, t.Text("status."+v.Status, nil) + "; " + counts, displayValue(t, "severity", v.HighestSeverity)})
	}
	pairs := grid{Title: label(t, "pair_table"), Headers: []string{label(t, "key_id"), label(t, "certificate_id")}, Rows: [][]string{}, Widths: []int{14, 64}}
	for _, pair := range d.Local.Pairs {
		pairs.Rows = append(pairs.Rows, []string{pair.KeyID, pair.CertificateID})
	}
	return []grid{summary, pairs}
}
