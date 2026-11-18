package report

import "github.com/vincent119/tlscheck/internal/i18n"

// displayValue 僅翻譯已知分類值；憑證原值、路徑與未知識別碼不作猜測。
func displayValue(t *i18n.Translator, category, value string) string {
	switch category {
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
		case "parse", "validity", "ca_constraints", "linkage", "trust", "hostname", "server_usage", "key_validation", "pairing", "dns", "connection", "handshake", "revocation", "aia":
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
