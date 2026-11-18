package input

import (
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/net/idna"

	"github.com/vincent119/tlscheck/internal/model"
)

// 僅保存分類碼的錯誤，避免 net/url 的原始錯誤回顯完整 URL。
type targetError struct{ code model.IssueCode }

func (e targetError) Error() string { return string(e.code) }

func targetIssue(err error) model.IssueCode {
	var issue targetError
	if errors.As(err, &issue) {
		return issue.code
	}
	return model.InvalidTarget
}

func parseTarget(value string, index int) (*model.Target, error) {
	fail := func(code model.IssueCode) (*model.Target, error) { return nil, targetError{code: code} }
	if value == "" || strings.IndexFunc(value, unicode.IsSpace) >= 0 || strings.ContainsAny(value, "\x00\\") {
		return fail(model.InvalidTarget)
	}
	authority := value
	isURL := strings.Contains(value, "://") || strings.HasPrefix(strings.ToLower(value), "https:") || strings.HasPrefix(strings.ToLower(value), "http:")
	if isURL {
		u, err := url.Parse(value)
		if err != nil {
			return fail(model.InvalidTarget)
		}
		if !strings.EqualFold(u.Scheme, "https") {
			return fail(model.UnsupportedScheme)
		}
		if !strings.HasPrefix(strings.ToLower(value), "https://") || u.Host == "" || u.Opaque != "" {
			return fail(model.InvalidTarget)
		}
		// 不保留 userinfo、path、query 或 fragment，也不傳出 net/url 原始錯誤。
		authority = u.Host
	} else if strings.ContainsAny(value, "/?#@") {
		return fail(model.InvalidTarget)
	}
	host, portText := authority, "443"
	if strings.HasPrefix(authority, "[") {
		closing := strings.IndexByte(authority, ']')
		if closing < 0 {
			return fail(model.InvalidTarget)
		}
		host = authority[1:closing]
		suffix := authority[closing+1:]
		if suffix != "" {
			if !strings.HasPrefix(suffix, ":") {
				return fail(model.InvalidTarget)
			}
			portText = suffix[1:]
		}
		addr, err := netip.ParseAddr(host)
		if err != nil || !addr.Is6() {
			return fail(model.InvalidTarget)
		}
	} else if addr, err := netip.ParseAddr(authority); err == nil {
		if addr.Zone() != "" {
			return fail(model.UnsupportedZone)
		}
		// URL 的 IPv6 必須有括號，裸 IPv6 僅限無 scheme 輸入。
		if isURL && addr.Is6() {
			return fail(model.InvalidTarget)
		}
	} else if strings.Count(authority, ":") == 1 {
		var found bool
		host, portText, found = strings.Cut(authority, ":")
		if !found {
			return fail(model.InvalidTarget)
		}
	} else if strings.Contains(authority, ":") {
		return fail(model.InvalidTarget)
	}
	if strings.Contains(host, "%") {
		return fail(model.UnsupportedZone)
	}
	if portText == "" {
		return fail(model.InvalidPort)
	}
	for _, c := range portText {
		if c < '0' || c > '9' {
			return fail(model.InvalidPort)
		}
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return fail(model.InvalidPort)
	}
	ascii, err := normalizeHost(host)
	if err != nil {
		return fail(model.InvalidTarget)
	}
	return &model.Target{Host: host, ASCIIHost: ascii, Port: uint16(port), InputIndex: index}, nil
}

func normalizeHost(host string) (string, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Zone() != "" {
			return "", targetError{code: model.UnsupportedZone}
		}
		return addr.String(), nil
	}
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return "", err
	}
	ascii = strings.TrimSuffix(strings.ToLower(ascii), ".")
	if ascii == "" || len(ascii) > 253 {
		return "", targetError{code: model.InvalidTarget}
	}
	// 無效點分數字不能退回當成 DNS 名稱，以免錯誤 IP 被送往 DNS。
	if strings.Contains(ascii, ".") && strings.Trim(ascii, "0123456789.") == "" && net.ParseIP(ascii) == nil {
		return "", targetError{code: model.InvalidTarget}
	}
	for _, label := range strings.Split(ascii, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", targetError{code: model.InvalidTarget}
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return "", targetError{code: model.InvalidTarget}
			}
		}
	}
	return ascii, nil
}
