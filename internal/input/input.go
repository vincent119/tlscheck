// Package input 辨識目標與本機檔案，不執行遠端連線或信任驗證。
package input

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"strings"

	"github.com/vincent119/tlscheck/internal/model"
)

// MaxFileSize 限制實際讀取量，避免檔案大小資訊過時或不可靠。
const MaxFileSize = 10 * 1024 * 1024

// Parser 的檔案邊界可於套件測試替換，不保存單一解析狀態。
type Parser struct {
	stat func(string) (fs.FileInfo, error)
	open func(string) (fs.File, error)
}

// NewParser 不搜尋額外檔案，也不建立任何網路連線。
func NewParser() *Parser {
	return &Parser{stat: os.Stat, open: openFile}
}

// Parse 保留有效物件及獨立錯誤；無效 URL 不會被放入來源欄位。
func (p *Parser) Parse(ctx context.Context, value string, index int) model.InputResult {
	result := model.InputResult{InputIndex: index}
	if ctx.Err() != nil {
		addIssue(&result, model.Canceled, model.SourceRef{InputIndex: index})
		return result
	}
	info, err := p.stat(value)
	if err == nil {
		source := model.SourceRef{Path: value, InputIndex: index}
		if !info.Mode().IsRegular() {
			addIssue(&result, model.NotRegularFile, source)
			return result
		}
		p.readFile(ctx, value, source, &result)
		return result
	}
	// URL 的底層檔案錯誤可能包含帳密；不保留或回傳原始錯誤。
	if strings.Contains(value, "://") || strings.HasPrefix(strings.ToLower(value), "https:") || strings.HasPrefix(strings.ToLower(value), "http:") {
		result.Target, err = parseTarget(value, index)
		if err != nil {
			addIssue(&result, targetIssue(err), model.SourceRef{InputIndex: index})
		}
		return result
	}
	// 合法 Unicode 網域的 UTF-8 可能超過檔名長度，但 IDNA 後仍是合法目標。
	nameTooLongTarget := isNameTooLong(err) && !explicitPath(value)
	if !errors.Is(err, fs.ErrNotExist) && !nameTooLongTarget {
		addIssue(&result, model.FileUnreadable, model.SourceRef{InputIndex: index})
		return result
	}
	if explicitPath(value) {
		addIssue(&result, model.FileNotFound, model.SourceRef{Path: value, InputIndex: index})
		return result
	}
	result.Target, err = parseTarget(value, index)
	if err != nil {
		addIssue(&result, targetIssue(err), model.SourceRef{InputIndex: index})
	}
	return result
}

// ParseAll 只依輸入順序分類；一項失敗不會停止其他項目。
func (p *Parser) ParseAll(ctx context.Context, values []string) []model.InputResult {
	results := make([]model.InputResult, 0, len(values))
	for i, value := range values {
		results = append(results, p.Parse(ctx, value, i))
	}
	return results
}

func explicitPath(value string) bool {
	if strings.ContainsAny(value, `/\`) || (len(value) == 2 && value[1] == ':') {
		return true
	}
	lower := strings.ToLower(value)
	for _, suffix := range []string{".pem", ".cer", ".crt", ".key"} {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}

func (p *Parser) readFile(ctx context.Context, path string, source model.SourceRef, result *model.InputResult) {
	file, err := p.open(path)
	if err != nil {
		addIssue(result, model.FileUnreadable, source)
		return
	}
	// 重新檢查開啟後物件，避免依賴先前可能已過時的 stat 結果。
	defer func() {
		if err := file.Close(); err != nil {
			addIssue(result, model.FileUnreadable, source)
		}
	}()
	info, err := file.Stat()
	if err != nil {
		addIssue(result, model.FileUnreadable, source)
		return
	}
	if !info.Mode().IsRegular() {
		addIssue(result, model.NotRegularFile, source)
		return
	}
	data, err := io.ReadAll(io.LimitReader(contextReader{ctx: ctx, reader: file}, MaxFileSize+1))
	if err != nil {
		code := model.FileUnreadable
		if ctx.Err() != nil {
			code = model.Canceled
		}
		addIssue(result, code, source)
		return
	}
	if len(data) > MaxFileSize {
		addIssue(result, model.FileTooLarge, source)
		return
	}
	parseData(ctx, data, source, result)
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(data []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(data)
}

func addIssue(result *model.InputResult, code model.IssueCode, source model.SourceRef) {
	result.Issues = append(result.Issues, model.Issue{Code: code, Source: source})
}
