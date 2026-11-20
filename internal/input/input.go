// Package input 辨識目標與本機檔案，不執行遠端連線或信任驗證。
package input

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"strings"

	"github.com/vincent119/tlscheck/internal/model"
)

// MaxFileSize 限制實際讀取量，避免檔案大小資訊過時或不可靠。
const MaxFileSize = 10 * 1024 * 1024

// Parser 的檔案邊界可於套件測試替換，不保存單一解析狀態。
type Parser struct {
	stat     func(string) (fs.FileInfo, error)
	open     func(string) (fs.File, error)
	password PasswordProvider
}

// NewParser 不搜尋額外檔案，也不建立任何網路連線。
// PasswordProvider 僅在已辨識 PFX 時取得單次密碼；呼叫者不得寫入報告。
type PasswordProvider func(context.Context, model.SourceRef) ([]byte, error)

// NewParserWithPasswordProvider 不保存密碼或 context，只保存可替換的私密讀取邊界。
func NewParserWithPasswordProvider(provider PasswordProvider) *Parser {
	p := NewParser()
	p.password = provider
	return p
}

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
	if !errors.Is(err, fs.ErrNotExist) && !nameTooLongTarget && !ipAfterPathError(value, err) {
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

func ipAfterPathError(value string, err error) bool {
	if !isInvalidName(err) || explicitPath(value) {
		return false
	}
	// Windows 的冒號檔名限制不代表 IP 無效；只容許已完整驗證的 IP，保留其他 I/O 錯誤。
	target, parseErr := parseTarget(value, 0)
	if parseErr != nil {
		return false
	}
	_, parseErr = netip.ParseAddr(target.ASCIIHost)
	return parseErr == nil
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
	for _, suffix := range []string{".pem", ".cer", ".crt", ".key", ".p7b", ".p7c", ".pfx", ".p12"} {
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
	parseDataWithPassword(ctx, data, source, result, p.password)
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

// ParseSpec 的強制模式不會跨到另一個 I/O 邊界。
func (p *Parser) ParseSpec(ctx context.Context, spec model.InputSpec) model.InputResult {
	if spec.Problem != "" {
		return model.InputResult{InputIndex: spec.Index, Issues: []model.Issue{{Code: spec.Problem, Source: model.SourceRef{InputIndex: spec.Index}}}}
	}
	if spec.Kind == model.AutoInput {
		return p.Parse(ctx, spec.Value, spec.Index)
	}
	r := model.InputResult{InputIndex: spec.Index}
	source := model.SourceRef{InputIndex: spec.Index}
	if ctx.Err() != nil {
		addIssue(&r, model.Canceled, source)
		return r
	}
	if spec.Kind == model.RemoteInput {
		var err error
		r.Target, err = parseTarget(spec.Value, spec.Index)
		if err != nil {
			addIssue(&r, targetIssue(err), source)
		}
		return r
	}
	if spec.Kind != model.LocalInput {
		addIssue(&r, model.InvalidData, source)
		return r
	}
	source.Path = spec.Value
	info, err := p.stat(spec.Value)
	if err != nil {
		code := model.FileUnreadable
		if errors.Is(err, fs.ErrNotExist) {
			code = model.FileNotFound
		}
		addIssue(&r, code, source)
		return r
	}
	if !info.Mode().IsRegular() {
		addIssue(&r, model.NotRegularFile, source)
		return r
	}
	p.readFile(ctx, spec.Value, source, &r)
	return r
}

// LocalPaths 只定位報告不得取代的檔名，不讀內容或建立連線。
func (p *Parser) LocalPaths(ctx context.Context, specs []model.InputSpec) []string {
	paths := []string{}
	for _, spec := range specs {
		if ctx.Err() != nil {
			return paths
		}
		if spec.Kind == model.RemoteInput {
			continue
		}
		if spec.Kind == model.LocalInput {
			paths = append(paths, spec.Value)
			continue
		}
		_, err := p.stat(spec.Value)
		if err == nil {
			paths = append(paths, spec.Value)
			continue
		}
		// URL 在 Windows 可因非法檔名回傳錯誤；必須與 Parse 的 URL 分支順序一致。
		if strings.Contains(spec.Value, "://") || strings.HasPrefix(strings.ToLower(spec.Value), "https:") || strings.HasPrefix(strings.ToLower(spec.Value), "http:") {
			continue
		}
		if ipAfterPathError(spec.Value, err) {
			continue
		}
		if explicitPath(spec.Value) || !errors.Is(err, fs.ErrNotExist) && !isNameTooLong(err) {
			paths = append(paths, spec.Value)
		}
	}
	return paths
}
