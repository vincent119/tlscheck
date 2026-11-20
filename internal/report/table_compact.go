package report

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

// compactCertificates只建立顯示視圖，集中重複檢查時保留原憑證與全域歸屬，不重算Summary。
func (r *tableReport) compactCertificates(d Document) {
	if len(d.Local.Certificates) == 0 {
		return
	}
	paths := map[int]string{}
	for _, input := range d.Inputs {
		if input.LocalSource != nil {
			paths[input.Index] = *input.LocalSource
		}
	}
	records := [][]string{}
	groups := []tableCheck{}
	add := func(owner string, checks []Check) {
		for _, check := range checks {
			eligible := (check.Result.Status == "passed" || check.Result.Status == "not_performed") && check.Result.Severity == "none" && check.Result.Advice == nil
			merged := false
			if eligible {
				for i := range groups {
					if reflect.DeepEqual(groups[i].check, check) {
						// 同一owner重複的結果不能被視為跨物件共用而靜默消失。
						seen := false
						for _, previous := range groups[i].owners {
							if previous == owner {
								seen = true
								break
							}
						}
						if !seen {
							groups[i].owners = append(groups[i].owners, owner)
							merged = true
							break
						}
					}
				}
			}
			if !merged {
				groups = append(groups, tableCheck{check: check, owners: []string{owner}})
			}
		}
	}
	for i, c := range d.Local.Certificates {
		owner := fmt.Sprintf("%s [%d]", label(r.t, "certificates"), i)
		identity := owner + " / " + r.t.Text("role."+c.Role, nil) + "; " + c.Info.Subject
		if c.Role != "ca" && c.Role != "site" {
			identity = owner + " / " + c.Role + "; " + c.Info.Subject
		}
		identity += "; " + c.Info.PublicKeyAlgorithm
		if c.Info.PublicKeyBits != nil {
			identity += " " + strconv.Itoa(*c.Info.PublicKeyBits)
		}
		if c.Info.PublicKeyCurve != nil {
			identity += " " + *c.Info.PublicKeyCurve
		}
		expiry := label(r.t, "unknown")
		if c.Info.NotAfter != nil {
			expiry = *c.Info.NotAfter + "; " + label(r.t, "remaining_days") + ": " + strconv.FormatInt(c.Info.RemainingDays, 10)
		}
		if c.Info.Expired {
			expiry += "; " + label(r.t, "expired") + ": " + r.t.Text("report.yes", nil)
		}
		if c.Info.ExpiringSoon {
			expiry += "; " + label(r.t, "expiring_soon") + ": " + r.t.Text("report.yes", nil)
		}
		checks := append([]Check{}, c.Checks...)
		checks = append(checks, c.Trust.Checks...)
		if c.Pairing != nil {
			checks = append(checks, Check{Name: "pairing", Result: *c.Pairing})
		}
		states := []string{}
		seen := map[string]bool{}
		for _, c := range checks {
			if !seen[c.Result.Status] {
				seen[c.Result.Status] = true
				states = append(states, tableStatus(r.t, c.Result.Status))
			}
		}
		if len(states) == 0 {
			states = append(states, label(r.t, "unknown"))
		}
		sources := []string{}
		for _, source := range c.Sources {
			ref := fmt.Sprintf("%d:%d (%s)", source.InputIndex, source.Block, source.Encoding)
			path, known := paths[source.InputIndex]
			if !known || path != source.Path {
				ref += "; " + source.Path
			}
			sources = append(sources, ref)
		}
		if len(sources) == 0 {
			sources = append(sources, label(r.t, "unknown"))
		}
		if len(c.MatchingKeys) > 0 {
			sources = append(sources, label(r.t, "matching_keys")+": "+strings.Join(c.MatchingKeys, ", "))
		}
		records = append(records, []string{identity, expiry, strings.Join(states, " / "), strings.Join(sources, "; ")})
		add(owner, checks)
	}
	add(r.text("shared_checks"), d.Local.Checks)
	heading, err := tableWrap(tableText(Safe(r.text("certificate_summary"))), r.width)
	if err != nil {
		r.err = err
		return
	}
	fmt.Fprintln(r.out, strings.Join(heading, "\n"))
	available := r.width - 13
	expiryWidth := available / 3
	sourceWidth := max(5, available/5)
	statusWidth := max(5, available/8)
	r.grid([]string{r.text("certificate_summary"), label(r.t, "not_after"), label(r.t, "result"), r.text("source_reference")}, records, []int{available - expiryWidth - sourceWidth - statusWidth, expiryWidth, statusWidth, sourceWidth})
	r.pending = append(r.pending, groups...)
	r.block(r.text("certificate_checks"), nil)
}
