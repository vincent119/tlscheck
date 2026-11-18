package i18n

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"text/template/parse"
	"unicode"
)

func catalogForTest(t *testing.T, language string) map[string]string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("catalog", language+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var entries map[string]string
	if err := json.Unmarshal(data, &entries); err != nil {
		t.Fatal(err)
	}
	return entries
}

func TestThreeLanguagesAndParameters(t *testing.T) {
	cases := []struct{ language, want string }{{"en", "Passed"}, {"zh-TW", "通過"}, {"zh-CN", "通过"}}
	for _, tt := range cases {
		t.Run(tt.language, func(t *testing.T) {
			tr := New(tt.language)
			if got := tr.Text("status.passed", nil); got != tt.want {
				t.Fatalf("翻譯不符：%q", got)
			}
			params := Params{"Value": "例子.example /測試/憑證.pem RSA {{.Injected}}"}
			out := tr.Text("report.value", params)
			if out != params["Value"] {
				t.Fatalf("公開原值不應翻譯或再次解析：%q", out)
			}
			got := tr.Text("summary.counts", Params{"Passed": "2", "Failed": "1", "NotPerformed": "3"})
			for _, n := range []string{"2", "1", "3"} {
				if !strings.Contains(got, n) {
					t.Fatalf("參數未替換：%q", got)
				}
			}
			if strings.Contains(got, "summary.") || strings.Contains(got, "<no value>") {
				t.Fatal(got)
			}
		})
	}
	if New("unknown").Text("status.passed", nil) != "Passed" {
		t.Fatal("未知語系未回退")
	}
}

func TestMissingTranslationAndInvalidTemplateFallback(t *testing.T) {
	english := map[string]string{"message": "Certificate {{.Value}} is not trusted.", "broken": "Safe English fallback."}
	translated := map[string]string{"broken": "{{"}
	tr := newTranslator(english, translated)
	if got := tr.Text("message", Params{"Value": "例子.example"}); got != "Certificate 例子.example is not trusted." {
		t.Fatalf("未回退英文：%q", got)
	}
	if got := tr.Text("broken", nil); got != "Safe English fallback." {
		t.Fatal(got)
	}
	for _, got := range []string{tr.Text("private.synthetic.unknown", nil), tr.Text("message", nil)} {
		if got == "" || strings.Contains(got, "private.synthetic") || strings.Contains(got, "message") || strings.Contains(got, "<no value>") || strings.Contains(got, "template:") {
			t.Fatalf("錯誤回退洩漏：%q", got)
		}
	}
	english["message"] = "changed"
	if got := tr.Text("message", Params{"Value": "example.com"}); got != "Certificate example.com is not trusted." {
		t.Fatal("呼叫者改動污染既有模板")
	}
}

func templateFields(node parse.Node, set map[string]bool) {
	if node == nil {
		return
	}
	switch n := node.(type) {
	case *parse.ListNode:
		if n != nil {
			for _, child := range n.Nodes {
				templateFields(child, set)
			}
		}
	case *parse.ActionNode:
		templateFields(n.Pipe, set)
	case *parse.PipeNode:
		for _, cmd := range n.Cmds {
			templateFields(cmd, set)
		}
	case *parse.CommandNode:
		for _, arg := range n.Args {
			templateFields(arg, set)
		}
	case *parse.FieldNode:
		for _, field := range n.Ident {
			set[field] = true
		}
	}
}

func TestCatalogCompletenessAndTemplateParameters(t *testing.T) {
	en := catalogForTest(t, "en")
	if len(en) < 100 {
		t.Fatalf("catalog 未涵蓋既有功能：%d", len(en))
	}
	for _, language := range []string{"en", "zh-TW", "zh-CN"} {
		entries := catalogForTest(t, language)
		if len(entries) != len(en) {
			t.Fatalf("%s 鍵數不同", language)
		}
		tr := New(language)
		for id, baseline := range en {
			message, ok := entries[id]
			if !ok || strings.TrimSpace(message) == "" {
				t.Fatalf("%s 缺少 %s", language, id)
			}
			for _, r := range message {
				if r >= 0x1f000 && r <= 0x1faff || r >= 0x2600 && r <= 0x27bf {
					t.Fatalf("%s 含 emoji", id)
				}
			}
			englishTemplate := parseTemplate(baseline)
			localTemplate := parseTemplate(message)
			if englishTemplate == nil || localTemplate == nil {
				t.Fatalf("模板無效：%s", id)
			}
			fields := map[string]bool{}
			localFields := map[string]bool{}
			templateFields(englishTemplate.Tree.Root, fields)
			templateFields(localTemplate.Tree.Root, localFields)
			if len(fields) != len(localFields) {
				t.Fatalf("參數數量不同：%s", id)
			}
			params := Params{}
			for field := range fields {
				if !localFields[field] {
					t.Fatalf("%s 參數不同", id)
				}
				params[field] = "合成值-" + field
			}
			output := tr.Text(id, params)
			if output == "" || output == unavailableMessage || output == tr.fallback || strings.Contains(output, "<no value>") {
				t.Fatalf("%s %s 無法渲染", language, id)
			}
			for _, value := range params {
				if !strings.Contains(output, value) {
					t.Fatalf("參數遺失：%s", id)
				}
			}
			if language != "en" && strings.Contains(id, ".") && strings.HasPrefix(id, "config.") {
				continue
			}
			// 母語選項名稱跨語系保持原名，只允許這個固定鍵保留 English。
			if id == "language.name.en" && message == "English" {
				continue
			}
			if language != "en" && id != "report.value" && id != "report.field" && id != "report.outcome" {
				if !strings.ContainsFunc(message, func(r rune) bool { return unicode.Is(unicode.Han, r) }) {
					t.Fatalf("中文訊息缺少中文：%s", id)
				}
			}
		}
	}
}

func TestCatalogCoversExistingOutcomeCodes(t *testing.T) {
	entries := catalogForTest(t, "en")
	count := 0
	for _, directory := range []string{"../model", "../check"} {
		files, err := filepath.Glob(filepath.Join(directory, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range files {
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			tree, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			ast.Inspect(tree, func(node ast.Node) bool {
				literal, ok := node.(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					return true
				}
				value, err := strconv.Unquote(literal.Value)
				if err != nil {
					return true
				}
				for _, prefix := range []string{"input.", "certificate.", "trust.", "remote.", "key.", "pairing."} {
					if strings.HasPrefix(value, prefix) && len(value) > len(prefix) && !strings.HasSuffix(value, "_") {
						count++
						if _, ok := entries[value]; !ok {
							t.Errorf("catalog 未涵蓋 %s", value)
						}
					}
				}
				return true
			})
		}
	}
	for _, stage := range []string{"dns", "connect", "handshake"} {
		for _, suffix := range []string{"_failed", "_timeout"} {
			if _, ok := entries["remote."+stage+suffix]; !ok {
				t.Errorf("缺少動態遠端代碼 %s%s", stage, suffix)
			}
		}
	}
	if count < 100 {
		t.Fatal("未掃描到既有功能代碼")
	}
}

func TestTranslationCanBeUsedConcurrently(t *testing.T) {
	tr := New("zh-TW")
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			for range 50 {
				if tr.Text("status.passed", nil) != "通過" {
					t.Error("並行翻譯錯誤")
				}
			}
		})
	}
	wg.Wait()
}

func TestTemplateExecutionFailureFallsBackWithoutPartialOutput(t *testing.T) {
	tr := newTranslator(map[string]string{"example": "Safe {{.Value}}"}, map[string]string{"example": "不完整 {{.Value}} {{.Missing}}"})
	if got := tr.Text("example", Params{"Value": "example.com"}); got != "Safe example.com" {
		t.Fatalf("未完整回退或輸出部分模板：%q", got)
	}
}
