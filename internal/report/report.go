// Package report 只格式化公開資料，不保存解析私鑰或完整輸入 URL。
package report

import (
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/vincent119/tlscheck/internal/check"
	"github.com/vincent119/tlscheck/internal/i18n"
	"github.com/vincent119/tlscheck/internal/model"
)

// Writer 保存安全模板與輸出狀態，I/O 錯誤交由入口轉為 2。
type Writer struct {
	Out, Diagnostics io.Writer
	T                *i18n.Translator
	Err              error
	Counts           [3]int
}

// Safe 只移除終端控制字元，不把公開文字或路徑猜成 URL。
func Safe(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			return -1
		}
		return r
	}, s)
}

// safeURI 只接受可明確解析的階層式 URI；不透明值不回顯以免夾帶嵌入帳密。
func safeURI(s string, target bool) string {
	u, err := url.Parse(Safe(s))
	if err != nil || u.Opaque != "" || u.Scheme == "" || u.Host == "" {
		return "[URI]"
	}
	u.User = nil
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	u.RawFragment = ""
	if target {
		u.Path = ""
		u.RawPath = ""
	}
	return u.String()
}

// Text 僅輸出既有模板，不回顯 ID。
func (w *Writer) Text(id string) { w.line(w.Out, w.T.Text(id, nil)) }
func (w *Writer) line(dst io.Writer, s string) {
	if _, err := fmt.Fprintln(dst, s); err != nil && w.Err == nil {
		w.Err = err
	}
}

// Field 的資料只能來自公開資訊模型。
func (w *Writer) Field(id, value string) {
	if id == "field.target" && strings.Contains(value, "://") {
		value = safeURI(value, true)
	}
	w.line(w.Out, w.T.Text("report.field", i18n.Params{"Label": w.T.Text(id, nil), "Value": Safe(value)}))
}

// Outcome 同時保留完整報告與執行診斷分流。
func (w *Writer) Outcome(label string, o check.Outcome) {
	if o.Code == "" {
		return
	}
	status := "status.not_performed"
	index := 2
	if o.Status == check.Passed {
		status = "status.passed"
		index = 0
	}
	if o.Status == check.Failed {
		status = "status.failed"
		index = 1
	}
	w.Counts[index]++
	message := w.T.Text("report.outcome", i18n.Params{"Label": w.T.Text(label, nil), "Status": w.T.Text(status, nil), "Reason": w.T.Text(o.Code, nil)})
	w.line(w.Out, message)
	if o.Class == check.ExecutionFailure {
		w.line(w.Diagnostics, message)
	}
	if o.Status == check.Failed {
		advice := "advice.check_input"
		switch {
		case strings.HasPrefix(o.Code, "remote."):
			advice = "advice.check_network"
		case strings.HasPrefix(o.Code, "pairing."):
			advice = "advice.check_pair"
		case strings.Contains(o.Code, "hostname"):
			advice = "advice.check_hostname"
		case strings.Contains(o.Code, "expired") || strings.Contains(o.Code, "not_yet_valid"):
			advice = "advice.replace_certificate"
		case strings.HasPrefix(o.Code, "trust."):
			advice = "advice.provide_chain"
		}
		w.Text(advice)
	}
}

// Source 保留來源索引而不展開解析物件。
func (w *Writer) Source(s model.SourceRef) {
	w.line(w.Out, w.T.Text("report.source", i18n.Params{"Path": Safe(s.Path), "Input": strconv.Itoa(s.InputIndex), "Block": strconv.Itoa(s.Block), "Encoding": s.Encoding}))
}

// Certificate 只接受 S02 公開資訊。
func (w *Writer) Certificate(c check.CertificateInfo) {
	for _, f := range []struct{ id, value string }{{"field.subject", c.Subject}, {"field.issuer", c.Issuer}, {"field.serial_number", c.SerialNumber}, {"field.fingerprint_sha256", c.FingerprintSHA256}, {"field.dns_names", strings.Join(c.DNSNames, ", ")}, {"field.ip_addresses", strings.Join(c.IPAddresses, ", ")}, {"field.email_addresses", strings.Join(c.EmailAddresses, ", ")}, {"field.algorithm", c.PublicKeyAlgorithm}, {"field.bits", strconv.Itoa(c.PublicKeyBits)}, {"field.curve", c.PublicKeyCurve}, {"field.not_before", c.NotBefore.UTC().Format(time.RFC3339)}, {"field.not_after", c.NotAfter.UTC().Format(time.RFC3339)}, {"field.remaining_days", strconv.FormatInt(c.RemainingDays, 10)}} {
		w.Field(f.id, f.value)
	}
	for _, uri := range c.URIs {
		w.Field("field.uris", safeURI(uri, false))
	}
	for _, f := range []struct {
		id string
		v  bool
	}{{"field.self_issued", c.SelfIssued}, {"field.self_signed", c.SelfSigned}} {
		id := "report.no"
		if f.v {
			id = "report.yes"
		}
		w.Field(f.id, w.T.Text(id, nil))
	}
	if c.ExpiringSoon {
		w.Text("warning.expiring_soon")
	}
}

// LocalCertificate 不重新計算信任或鏈結。
func (w *Writer) LocalCertificate(c check.CertificateResult) {
	for _, s := range c.Sources {
		w.Source(s)
	}
	w.Field("field.role", w.T.Text("role."+string(c.Role), nil))
	w.Certificate(c.Info)
	for _, v := range []struct {
		label string
		o     check.Outcome
	}{{"field.parse", c.Parse}, {"field.validity", c.Validity}, {"field.ca_constraints", c.CAConstraints}, {"field.linkage", c.Linkage}, {"field.trust", c.Trust.Outcome}, {"field.hostname", c.Trust.Hostname}, {"field.server_usage", c.Trust.ServerUsage}} {
		w.Outcome(v.label, v.o)
	}
	for _, chain := range c.Trust.Chains {
		for _, cert := range chain {
			w.Field("field.verified_chain", cert.Subject.String())
		}
	}
}

// Remote 僅輸出安全連線事實，忽略原始 ServerChain 物件。
func (w *Writer) Remote(r check.RemoteResult) {
	w.Field("field.target", r.Target.String())
	for _, v := range []struct {
		label string
		o     check.Outcome
	}{{"field.dns", r.DNS}, {"field.connection", r.Connection}, {"field.handshake", r.Handshake}, {"field.trust", r.Trust.Outcome}, {"field.hostname", r.Trust.Hostname}, {"field.server_usage", r.Trust.ServerUsage}, {"field.revocation", r.Revocation}, {"field.aia", r.AIARetrieval}} {
		w.Outcome(v.label, v.o)
	}
	w.Field("field.tls_version", r.TLSVersionName)
	w.Field("field.cipher_suite", r.CipherSuiteName)
	for _, c := range r.Certificates {
		w.Field("field.presented_chain", c.Subject)
		w.Certificate(c)
	}
	for _, chain := range r.Trust.Chains {
		for _, c := range chain {
			w.Field("field.verified_chain", c.Subject.String())
		}
	}
	if r.PlatformPolicy != "" {
		w.Text(r.PlatformPolicy)
	}
	for _, o := range r.Issues {
		w.Outcome("field.target", o)
	}
}

// Key 只接受 S04 安全結果，無法取得 signer。
func (w *Writer) Key(k check.KeyResult) {
	w.Source(k.Info.Source)
	w.Field("field.format", k.Info.Format)
	w.Field("field.algorithm", k.Info.Algorithm)
	w.Field("field.bits", strconv.Itoa(k.Info.Bits))
	w.Field("field.curve", k.Info.Curve)
	w.Field("field.public_key_fingerprint_sha256", k.Info.PublicKeyFingerprintSHA256)
	w.Outcome("field.key_validation", k.Validation)
	for _, o := range k.Checks {
		w.Outcome("field.key_validation", o)
	}
	w.Outcome("field.pairing", k.Pairing)
	for _, id := range k.Limitations {
		w.Text(id)
	}
}

// Summary 的計數只描述實際列出的檢查，不重算失敗等級。
func (w *Writer) Summary(code int) {
	w.line(w.Out, w.T.Text("summary.counts", i18n.Params{"Passed": strconv.Itoa(w.Counts[0]), "Failed": strconv.Itoa(w.Counts[1]), "NotPerformed": strconv.Itoa(w.Counts[2])}))
	w.line(w.Out, w.T.Text("summary.exit", i18n.Params{"Code": strconv.Itoa(code)}))
}
