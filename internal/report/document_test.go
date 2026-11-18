package report

import (
	"bytes"
	"encoding/json"
	"html"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vincent119/tlscheck/internal/check"
	"github.com/vincent119/tlscheck/internal/model"
)

func TestDocumentFormatsShareSafeProjection(t *testing.T) {
	now := time.Date(2026, 11, 18, 0, 0, 0, 123, time.UTC)
	local := check.LocalResult{Certificates: []check.CertificateResult{{Info: check.CertificateInfo{Subject: "<script>alert(1)</script>|`[x](https://evil)", FingerprintSHA256: strings.Repeat("A", 64), URIs: []string{"urn:https://user:secret@example.com/private?q=hidden", "spiffe://cluster.local/ns/a"}}}}}
	d := Build("en", "test", "abc", now, []model.InputSpec{}, []model.InputResult{}, local, check.PairingResult{}, nil, 0)
	for _, format := range []string{"table", "json", "html", "markdown"} {
		var b bytes.Buffer
		if err := Render(&b, format, d); err != nil {
			t.Fatal(err)
		}
		s := b.String()
		if strings.Contains(s, "secret") || strings.Contains(s, "hidden") || strings.Contains(s, "\x1b") {
			t.Fatal(format, s)
		}
		if !strings.Contains(html.UnescapeString(s), "spiffe://cluster.local/ns/a") {
			t.Fatal("遺失有效 URI", format)
		}
		if format == "json" {
			var v map[string]json.RawMessage
			if json.Unmarshal(b.Bytes(), &v) != nil || string(v["schema_version"]) != "1" || string(v["remote"]) != "[]" || string(v["inputs"]) != "[]" {
				t.Fatal(s)
			}
		}
		if format == "html" && (strings.Contains(s, "<script>") || !strings.Contains(s, "<!DOCTYPE html>")) {
			t.Fatal(s)
		}
		if format == "markdown" && (strings.Contains(s, "<script>") || strings.Contains(s, "[x](https://evil)")) {
			t.Fatal(s)
		}
	}
}
func TestSummaryCountsOutcomesOnce(t *testing.T) {
	passed := check.Outcome{Status: check.Passed, Code: "certificate.parsed"}
	failed := check.Outcome{Status: check.Failed, Class: check.VerificationFailure, Code: "trust.unknown_authority"}
	d := Build("zh-TW", "test", "abc", time.Now(), nil, nil, check.LocalResult{Certificates: []check.CertificateResult{{Parse: passed, Trust: check.TrustResult{Outcome: failed}, Info: check.CertificateInfo{ExpiringSoon: true}}}}, check.PairingResult{}, nil, 1)
	if d.Summary.Passed != 1 || d.Summary.Failed != 1 || d.Summary.Warnings != 1 || d.Summary.CheckExitCode != 1 {
		t.Fatal(d.Summary)
	}
	for _, f := range []string{"json", "table", "html", "markdown"} {
		var b bytes.Buffer
		if err := Render(&b, f, d); err != nil {
			t.Fatal(err)
		}
	}
	if d.Summary.Passed != 1 || d.Summary.Failed != 1 {
		t.Fatal("renderer 改動結果")
	}
}

func TestJSONEmptyDocumentMatchesVersionedFixture(t *testing.T) {
	d := Build("en", "fixture", "unknown", time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC), nil, nil, check.LocalResult{}, check.PairingResult{}, nil, 0)
	want, err := os.ReadFile("testdata/empty-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := Render(&out, "json", d); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), want) {
		t.Fatal(out.String())
	}
}
func TestTableCJKWidthAndLongValuesArePreserved(t *testing.T) {
	value := strings.Repeat("憑證", 100) + " e\u0301 SHA-256"
	lines := wrap(value, 72)
	if strings.Join(lines, "") != value {
		t.Fatal("遺失內容")
	}
	for _, line := range lines {
		n := 0
		for _, r := range line {
			n += runeWidth(r)
		}
		if n > 72 {
			t.Fatal(n)
		}
	}
}
