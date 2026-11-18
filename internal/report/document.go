package report

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/vincent119/tlscheck/internal/check"
	"github.com/vincent119/tlscheck/internal/i18n"
	"github.com/vincent119/tlscheck/internal/model"
)

// Document 的欄位僅限已清理公開值，不能保存任何解析器私密型別。
type Document struct {
	Presentation  Presentation `json:"-"`
	SchemaVersion int          `json:"schema_version"`
	Tool          Tool         `json:"tool"`
	GeneratedAt   string       `json:"generated_at"`
	Language      string       `json:"language"`
	Inputs        []Input      `json:"inputs"`
	Local         Local        `json:"local"`
	Remote        []Remote     `json:"remote"`
	Summary       Summary      `json:"summary"`
}

// Tool 只保存已清理的建置識別資訊。
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

// Source 保留來源位置，不含檔案內容。
type Source struct {
	Path       string `json:"path"`
	InputIndex int    `json:"input_index"`
	Block      int    `json:"block"`
	Encoding   string `json:"encoding"`
}

// Input 保留出現順序，無效遠端不回顯原始輸入。
type Input struct {
	Index       int     `json:"index"`
	Kind        string  `json:"kind"`
	Target      *string `json:"target"`
	LocalSource *string `json:"local_source"`
}

// Result 使用固定代碼與本地化訊息，不保存底層錯誤。
type Result struct {
	Status   string   `json:"status"`
	Severity string   `json:"severity"`
	Code     string   `json:"code"`
	Message  string   `json:"message"`
	Advice   *Message `json:"advice"`
}

// Check 將安全結果連到檢查名稱。
type Check struct {
	Name   string `json:"name"`
	Result Result `json:"result"`
}

// Issue 來源可未知，錯誤內容仍使用固定代碼。
type Issue struct {
	Source *Source `json:"source"`
	Result Result  `json:"result"`
}

// URI 明確揭露遮蔽狀態，不提供還原原值的欄位。
type URI struct {
	Value    string  `json:"value"`
	Redacted bool    `json:"redacted"`
	Reason   *string `json:"reason"`
}

// PublicCertificate 僅限公開憑證事實，未知數值使用 nullable 欄位。
type PublicCertificate struct {
	ID                 string   `json:"id"`
	Subject            string   `json:"subject"`
	Issuer             string   `json:"issuer"`
	SerialNumber       string   `json:"serial_number"`
	FingerprintSHA256  string   `json:"fingerprint_sha256"`
	DNSNames           []string `json:"dns_names"`
	IPAddresses        []string `json:"ip_addresses"`
	EmailAddresses     []string `json:"email_addresses"`
	URIs               []URI    `json:"uris"`
	PublicKeyAlgorithm string   `json:"public_key_algorithm"`
	PublicKeyBits      *int     `json:"public_key_bits"`
	PublicKeyCurve     *string  `json:"public_key_curve"`
	NotBefore          *string  `json:"not_before"`
	NotAfter           *string  `json:"not_after"`
	RemainingDays      int64    `json:"remaining_days"`
	Expired            bool     `json:"expired"`
	ExpiringSoon       bool     `json:"expiring_soon"`
	SelfIssued         bool     `json:"self_issued"`
	SelfSigned         bool     `json:"self_signed"`
}

// ChainCertificate 只投影驗證鏈的公開識別，不保存解析物件。
type ChainCertificate struct {
	ID      string `json:"id"`
	Subject string `json:"subject"`
	Issuer  string `json:"issuer"`
}

// Trust 將信任結果與實際驗證鏈分開。
type Trust struct {
	Checks         []Check              `json:"checks"`
	VerifiedChains [][]ChainCertificate `json:"verified_chains"`
}

// Link 描述簽發關係，不表示信任已成立。
type Link struct {
	IssuerID       string `json:"issuer_id"`
	SignatureValid bool   `json:"signature_valid"`
}

// Certificate 彙整同一憑證的全部來源及檢查。
type Certificate struct {
	Info         PublicCertificate `json:"info"`
	Role         string            `json:"role"`
	Sources      []Source          `json:"sources"`
	Checks       []Check           `json:"checks"`
	Links        []Link            `json:"links"`
	Trust        Trust             `json:"trust"`
	Pairing      *Result           `json:"pairing"`
	MatchingKeys []string          `json:"matching_keys"`
}

// Key 只有逐來源識別碼及公開中繼資訊。
type Key struct {
	ID                   string    `json:"id"`
	Source               Source    `json:"source"`
	Format               string    `json:"format"`
	Algorithm            string    `json:"algorithm"`
	Bits                 *int      `json:"bits"`
	Curve                *string   `json:"curve"`
	PublicFingerprint    string    `json:"public_key_fingerprint_sha256"`
	Checks               []Check   `json:"checks"`
	Limitations          []Message `json:"limitations"`
	MatchingCertificates []string  `json:"matching_certificates"`
}

// Message 保存固定限制代碼與顯示說明。
type Message struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Pair 以安全識別碼參照配對雙方。
type Pair struct {
	KeyID         string `json:"key_id"`
	CertificateID string `json:"certificate_id"`
}

// Local 僅包含本機共同集合的安全投影。
type Local struct {
	Certificates []Certificate `json:"certificates"`
	Keys         []Key         `json:"keys"`
	Pairs        []Pair        `json:"pairs"`
	Checks       []Check       `json:"checks"`
	Issues       []Issue       `json:"issues"`
}

// TLS 僅在握手完成後存在。
type TLS struct {
	Version       string `json:"version"`
	VersionID     uint16 `json:"version_id"`
	CipherSuite   string `json:"cipher_suite"`
	CipherSuiteID uint16 `json:"cipher_suite_id"`
}

// Remote 不接收本機金鑰，未觀測 TLS 使用 nil。
type Remote struct {
	InputIndex        int                 `json:"input_index"`
	Target            string              `json:"target"`
	Stage             string              `json:"stage"`
	HandshakeComplete bool                `json:"handshake_complete"`
	TLS               *TLS                `json:"tls"`
	Certificates      []PublicCertificate `json:"certificates"`
	Checks            []Check             `json:"checks"`
	Trust             Trust               `json:"trust"`
	Limitations       []Message           `json:"limitations"`
	Issues            []Issue             `json:"issues"`
}

// Summary 只在投影時統計一次，I/O 不改寫檢查結果。
type Summary struct {
	Passed          int    `json:"passed"`
	Failed          int    `json:"failed"`
	NotPerformed    int    `json:"not_performed"`
	Warnings        int    `json:"warnings"`
	HighestSeverity string `json:"highest_severity"`
	CheckExitCode   int    `json:"check_exit_code"`
}

func source(s model.SourceRef) Source {
	return Source{Safe(s.Path), s.InputIndex, s.Block, Safe(s.Encoding)}
}
func texts(values []string) []string {
	r := make([]string, 0, len(values))
	for _, v := range values {
		r = append(r, Safe(v))
	}
	return r
}
func optional(s string) *string {
	if s == "" {
		return nil
	}
	v := Safe(s)
	return &v
}
func optionalInt(n int) *int {
	if n == 0 {
		return nil
	}
	return &n
}
func timestamp(t time.Time) *string {
	if t.IsZero() {
		return nil
	}
	s := t.UTC().Format(time.RFC3339Nano)
	return &s
}
func public(c check.CertificateInfo) PublicCertificate {
	p := PublicCertificate{ID: Safe(c.FingerprintSHA256), Subject: Safe(c.Subject), Issuer: Safe(c.Issuer), SerialNumber: Safe(c.SerialNumber), FingerprintSHA256: Safe(c.FingerprintSHA256), DNSNames: texts(c.DNSNames), IPAddresses: texts(c.IPAddresses), EmailAddresses: texts(c.EmailAddresses), URIs: []URI{}, PublicKeyAlgorithm: Safe(c.PublicKeyAlgorithm), PublicKeyBits: optionalInt(c.PublicKeyBits), PublicKeyCurve: optional(c.PublicKeyCurve), NotBefore: timestamp(c.NotBefore), NotAfter: timestamp(c.NotAfter), RemainingDays: c.RemainingDays, Expired: c.Expired, ExpiringSoon: c.ExpiringSoon, SelfIssued: c.SelfIssued, SelfSigned: c.SelfSigned}
	for _, u := range c.URIs {
		v := safeURI(u, false)
		item := URI{Value: v, Redacted: v != u}
		if v == "[URI]" {
			item.Reason = optional("uri.invalid_or_opaque")
		} else if v != u {
			item.Reason = optional("uri.sensitive_components_removed")
		}
		p.URIs = append(p.URIs, item)
	}
	return p
}

type builder struct {
	t       *i18n.Translator
	summary Summary
}

func (b *builder) outcome(o check.Outcome) Result {
	r := Result{Status: "not_performed", Severity: "none", Code: Safe(o.Code), Message: b.t.Text(o.Code, nil)}
	if o.Status == check.Passed {
		r.Status = "passed"
		b.summary.Passed++
	} else if o.Status == check.Failed {
		r.Status = "failed"
		b.summary.Failed++
	} else {
		b.summary.NotPerformed++
	}
	if o.Class == check.VerificationFailure {
		r.Severity = "verification"
	}
	if o.Class == check.ExecutionFailure {
		r.Severity = "execution"
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
		r.Advice = &Message{Code: advice, Message: b.t.Text(advice, nil)}
	}
	return r
}
func (b *builder) add(dst *[]Check, name string, o check.Outcome) {
	if o.Code != "" {
		*dst = append(*dst, Check{Name: name, Result: b.outcome(o)})
	}
}
func (b *builder) issue(o check.Outcome, s *Source) Issue {
	return Issue{Source: s, Result: b.outcome(o)}
}
func (b *builder) trust(t check.TrustResult) Trust {
	v := Trust{Checks: []Check{}, VerifiedChains: [][]ChainCertificate{}}
	b.add(&v.Checks, "trust", t.Outcome)
	b.add(&v.Checks, "hostname", t.Hostname)
	b.add(&v.Checks, "server_usage", t.ServerUsage)
	for _, chain := range t.Chains {
		items := []ChainCertificate{}
		for _, c := range chain {
			if c == nil {
				continue
			}
			hash := sha256.Sum256(c.Raw)
			items = append(items, ChainCertificate{ID: strings.ToUpper(hex.EncodeToString(hash[:])), Subject: Safe(c.Subject.String()), Issuer: Safe(c.Issuer.String())})
		}
		v.VerifiedChains = append(v.VerifiedChains, items)
	}
	return v
}

// Build 是唯一資料投影與計數入口，renderer 不再取得 domain 物件。
func Build(language, version, commit string, now time.Time, specs []model.InputSpec, inputs []model.InputResult, local check.LocalResult, pairs check.PairingResult, remotes []check.RemoteResult, exitCode int) Document {
	b := builder{t: i18n.New(language), summary: Summary{CheckExitCode: exitCode, HighestSeverity: "none"}}
	d := Document{SchemaVersion: 1, Tool: Tool{"tlscheck", Safe(version), Safe(commit)}, GeneratedAt: now.UTC().Format(time.RFC3339Nano), Language: language, Inputs: []Input{}, Remote: []Remote{}, Local: Local{Certificates: []Certificate{}, Keys: []Key{}, Pairs: []Pair{}, Checks: []Check{}, Issues: []Issue{}}}
	for _, spec := range specs {
		v := Input{Index: spec.Index, Kind: string(spec.Kind)}
		for _, r := range inputs {
			if r.InputIndex != spec.Index {
				continue
			}
			if r.Target != nil {
				v.Target = optional(r.Target.String())
			} else if spec.Kind == model.LocalInput || len(r.Certificates) > 0 || len(r.Keys) > 0 {
				v.LocalSource = optional(spec.Value)
			} else {
				for _, issue := range r.Issues {
					if issue.Source.Path != "" {
						v.LocalSource = optional(issue.Source.Path)
						break
					}
				}
			}
		}
		d.Inputs = append(d.Inputs, v)
	}
	for _, r := range inputs {
		for _, i := range r.Issues {
			s := source(i.Source)
			d.Local.Issues = append(d.Local.Issues, b.issue(check.Outcome{Code: string(i.Code), Status: check.Failed, Class: check.ExecutionFailure}, &s))
		}
	}
	for _, c := range local.Certificates {
		item := Certificate{Info: public(c.Info), Role: Safe(string(c.Role)), Sources: []Source{}, Checks: []Check{}, Links: []Link{}, Trust: b.trust(c.Trust), MatchingKeys: []string{}}
		for _, s := range c.Sources {
			item.Sources = append(item.Sources, source(s))
		}
		b.add(&item.Checks, "parse", c.Parse)
		b.add(&item.Checks, "validity", c.Validity)
		b.add(&item.Checks, "ca_constraints", c.CAConstraints)
		b.add(&item.Checks, "linkage", c.Linkage)
		for _, link := range c.Links {
			item.Links = append(item.Links, Link{Safe(link.IssuerFingerprint), link.SignatureValid})
		}
		for _, pc := range pairs.Certificates {
			if pc.FingerprintSHA256 == c.Info.FingerprintSHA256 {
				if pc.Pairing.Code != "" {
					result := b.outcome(pc.Pairing)
					item.Pairing = &result
				}
				for _, ki := range pc.MatchingKeys {
					item.MatchingKeys = append(item.MatchingKeys, fmt.Sprintf("key:%d", ki))
				}
			}
		}
		if c.Info.ExpiringSoon {
			b.summary.Warnings++
		}
		d.Local.Certificates = append(d.Local.Certificates, item)
	}
	for i, k := range pairs.Keys {
		item := Key{ID: fmt.Sprintf("key:%d", i), Source: source(k.Info.Source), Format: Safe(k.Info.Format), Algorithm: Safe(k.Info.Algorithm), Bits: optionalInt(k.Info.Bits), Curve: optional(k.Info.Curve), PublicFingerprint: Safe(k.Info.PublicKeyFingerprintSHA256), Checks: []Check{}, Limitations: []Message{}, MatchingCertificates: []string{}}
		b.add(&item.Checks, "key_validation", k.Validation)
		for _, o := range k.Checks {
			b.add(&item.Checks, "key_validation", o)
		}
		b.add(&item.Checks, "pairing", k.Pairing)
		for _, code := range k.Limitations {
			item.Limitations = append(item.Limitations, Message{Safe(code), b.t.Text(code, nil)})
		}
		for _, ci := range k.MatchingCertificates {
			if ci >= 0 && ci < len(pairs.Certificates) {
				item.MatchingCertificates = append(item.MatchingCertificates, Safe(pairs.Certificates[ci].FingerprintSHA256))
			}
		}
		d.Local.Keys = append(d.Local.Keys, item)
	}
	for _, p := range pairs.Pairs {
		if p.KeyIndex >= 0 && p.KeyIndex < len(pairs.Keys) && p.CertificateIndex >= 0 && p.CertificateIndex < len(pairs.Certificates) {
			d.Local.Pairs = append(d.Local.Pairs, Pair{fmt.Sprintf("key:%d", p.KeyIndex), Safe(pairs.Certificates[p.CertificateIndex].FingerprintSHA256)})
		}
	}
	b.add(&d.Local.Checks, "pairing", pairs.Pairing)
	for _, o := range append(append([]check.Outcome{}, local.Issues...), pairs.Issues...) {
		d.Local.Issues = append(d.Local.Issues, b.issue(o, nil))
	}
	for _, r := range remotes {
		item := Remote{InputIndex: r.Target.InputIndex, Target: Safe(r.Target.String()), Stage: Safe(r.Stage), HandshakeComplete: r.HandshakeComplete, Certificates: []PublicCertificate{}, Checks: []Check{}, Trust: b.trust(r.Trust), Limitations: []Message{}, Issues: []Issue{}}
		if r.HandshakeComplete {
			item.TLS = &TLS{Safe(r.TLSVersionName), r.TLSVersion, Safe(r.CipherSuiteName), r.CipherSuite}
		}
		for _, c := range r.Certificates {
			item.Certificates = append(item.Certificates, public(c))
			if c.ExpiringSoon {
				b.summary.Warnings++
			}
		}
		b.add(&item.Checks, "dns", r.DNS)
		b.add(&item.Checks, "connection", r.Connection)
		b.add(&item.Checks, "handshake", r.Handshake)
		b.add(&item.Checks, "revocation", r.Revocation)
		b.add(&item.Checks, "aia", r.AIARetrieval)
		if r.PlatformPolicy != "" {
			item.Limitations = append(item.Limitations, Message{Safe(r.PlatformPolicy), b.t.Text(r.PlatformPolicy, nil)})
		}
		for _, o := range r.Issues {
			item.Issues = append(item.Issues, b.issue(o, nil))
		}
		d.Remote = append(d.Remote, item)
	}
	if exitCode == 1 {
		b.summary.HighestSeverity = "verification"
	}
	if exitCode == 2 {
		b.summary.HighestSeverity = "execution"
	}
	d.Summary = b.summary
	d.Presentation = present(d)
	return d
}
