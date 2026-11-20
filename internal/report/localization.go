package report

import "github.com/vincent119/tlscheck/internal/i18n"

// displayValue 僅翻譯已知分類值；憑證原值、路徑與未知識別碼不作猜測。
func displayValue(t *i18n.Translator, category, value string) string {
	switch category {
	case "comparison_field":
		switch value {
		case "subject", "issuer", "serial_number", "dns_names", "ip_addresses", "email_addresses", "uris", "not_before", "not_after", "public_key_spki_sha256", "certificate_der":
			return t.Text("document."+value, nil)
		}
	case "kind":
		switch value {
		case "auto", "local", "remote":
			return t.Text("display.kind."+value, nil)
		}
	case "severity":
		switch value {
		case "none", "verification", "execution":
			return t.Text("display.severity."+value, nil)
		}
	case "stage":
		switch value {
		case "input", "dns", "connect", "handshake", "verify", "complete":
			return t.Text("display.stage."+value, nil)
		}
	case "check":
		switch value {
		case "parse", "validity", "ca_constraints", "linkage", "trust", "hostname", "server_usage", "key_validation", "pairing", "dns", "connection", "handshake", "revocation", "aia", "expiry_policy", "comparison":
			return t.Text("display.check."+value, nil)
		}
	case "uri_reason":
		switch value {
		case "uri.invalid_or_opaque", "uri.sensitive_components_removed":
			return t.Text(value, nil)
		}
	}
	return value
}
