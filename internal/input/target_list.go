package input

import (
	"bytes"
	"context"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/vincent119/tlscheck/internal/model"
)

const (
	// MaxTargetListSize 與原始憑證大小分開，清單最多1MiB。
	MaxTargetListSize = 1 << 20
	// MaxTargetLineSize 限制含註解的每一實際行，避免以註解繞過解析預算。
	MaxTargetLineSize = 8 << 10
	// MaxTargetLists 限制單次CLI清單個數，包含重複檔案。
	MaxTargetLists = 200
	// MaxTargetListBytes 是所有清單累計實際讀取量。
	MaxTargetListBytes = 8 << 20
	// MaxBatchTargets 限制展開後的所有occurrence，含無效目標。
	MaxBatchTargets = 1000
)

const (
	// TargetListInvalid 是格式／行長／regular-file問題的安全代碼。
	TargetListInvalid model.IssueCode = "input.targets_file_invalid"
	// TargetListUnreadable 不包含底層檔案錯誤或內容。
	TargetListUnreadable model.IssueCode = "input.targets_file_unreadable"
	// TargetListTooLarge 區分單檔大小超限。
	TargetListTooLarge model.IssueCode = "input.targets_file_too_large"
	// BatchLimitExceeded 表示整體前處理預算超限，不可先啟動網路。
	BatchLimitExceeded model.IssueCode = "input.batch_limit_exceeded"
)

// TargetListEntry 只保留行的原值與真實行號，後續必須強制作remote解析。
type TargetListEntry struct {
	Value string
	Line  int
}

// TargetListResult 不交付失敗檔案的部分目標；Bytes仍計入全域讀取預算。
type TargetListResult struct {
	Entries []TargetListEntry
	Bytes   int
	Issue   model.IssueCode
}

// ReadTargetList 使用剩餘全域預算有界讀取，不解析成CLI參數或讀取其他來源。
func (p *Parser) ReadTargetList(ctx context.Context, path string, remaining int) (result TargetListResult) {
	if ctx.Err() != nil {
		result.Issue = model.Canceled
		return
	}
	if remaining < 0 || remaining > MaxTargetListBytes {
		result.Issue = BatchLimitExceeded
		return
	}
	f, err := p.open(path)
	if err != nil {
		result.Issue = TargetListUnreadable
		return
	}
	defer func() {
		if f.Close() != nil {
			result.Entries = nil
			if result.Issue == "" {
				result.Issue = TargetListUnreadable
			}
		}
	}()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		result.Issue = TargetListInvalid
		return
	}
	data, err := io.ReadAll(io.LimitReader(contextReader{ctx: ctx, reader: f}, int64(min(MaxTargetListSize+1, remaining+1))))
	result.Bytes = len(data)
	if len(data) > remaining {
		result.Issue = BatchLimitExceeded
		return
	}
	if err != nil {
		result.Issue = TargetListUnreadable
		if ctx.Err() != nil {
			result.Issue = model.Canceled
		}
		return
	}
	if len(data) > MaxTargetListSize {
		result.Issue = TargetListTooLarge
		return
	}
	if !utf8.Valid(data) || bytes.HasPrefix(data, []byte{0xef, 0xbb, 0xbf}) || bytes.ContainsRune(data, 0) {
		result.Issue = TargetListInvalid
		return
	}
	// 每檔最多1001個有效行佔位；尚未完成檔案檢查前不交付其中任何目標。
	lines := bytes.Split(data, []byte{'\n'})
	for i, raw := range lines {
		if ctx.Err() != nil {
			result.Entries = nil
			result.Issue = model.Canceled
			return
		}
		if i < len(lines)-1 {
			raw = bytes.TrimSuffix(raw, []byte{'\r'})
		}
		if len(raw) > MaxTargetLineSize || bytes.ContainsRune(raw, '\r') {
			result.Entries = nil
			result.Issue = TargetListInvalid
			return
		}
		value := strings.TrimSpace(string(raw))
		if value == "" || strings.HasPrefix(value, "#") {
			continue
		}
		if len(result.Entries) >= MaxBatchTargets {
			result.Entries = nil
			result.Issue = BatchLimitExceeded
			return
		}
		result.Entries = append(result.Entries, TargetListEntry{Value: value, Line: i + 1})
	}
	return
}
