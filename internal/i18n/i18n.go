// Package i18n 集中使用者訊息，讓檢查結果不依賴終端語系。
package i18n

import (
	"bytes"
	"embed"
	"encoding/json"
	"text/template"
)

// Params 僅接受安全報告的公開字串，不接受私鑰物件或原始錯誤。
type Params map[string]string

// 唯讀內嵌檔案避免執行時讀取可遭替換的外部翻譯。
//
//go:embed catalog/*.json
var catalogFiles embed.FS

// 最終保底不經模板，避免 catalog 損壞時再次觸發翻譯失敗。
const (
	unavailableMessage     = "Unable to display this result."
	unavailableTraditional = "無法顯示此結果。"
	unavailableSimplified  = "无法显示此结果。"
)

// Translator 的模板在建構後不再修改，可供多個檢查共用。
type Translator struct {
	fallback   string
	english    map[string]*template.Template
	translated map[string]*template.Template
}

// New 對不支援語系使用英文，不讀取環境變數。
func New(language string) *Translator {
	english := readCatalog("en")
	switch language {
	case "zh-TW", "zh-CN":
		result := newTranslator(english, readCatalog(language))
		if language == "zh-TW" {
			result.fallback = unavailableTraditional
		} else {
			result.fallback = unavailableSimplified
		}
		return result
	default:
		return newTranslator(english, nil)
	}
}

// Text 缺譯先回退英文模板，全部失敗才使用有效語系的固定保底。
func (t *Translator) Text(id string, params Params) string {
	if message, ok := render(t.translated[id], params); ok {
		return message
	}
	if message, ok := render(t.english[id], params); ok {
		return message
	}
	if t.fallback != "" {
		return t.fallback
	}
	return unavailableMessage
}

func readCatalog(language string) map[string]string {
	data, err := catalogFiles.ReadFile("catalog/" + language + ".json")
	if err != nil {
		return nil
	}
	var entries map[string]string
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil
	}
	return entries
}

func newTranslator(english, translated map[string]string) *Translator {
	result := &Translator{fallback: unavailableMessage, english: make(map[string]*template.Template, len(english)), translated: make(map[string]*template.Template, len(translated))}
	for id, text := range english {
		result.english[id] = parseTemplate(text)
		// 只提供英文基準已知的鍵，避免單一語系創造不相容的介面。
		if text, ok := translated[id]; ok {
			result.translated[id] = parseTemplate(text)
		}
	}
	return result
}

func parseTemplate(text string) *template.Template {
	if text == "" {
		return nil
	}
	value, err := template.New("message").Option("missingkey=error").Parse(text)
	if err != nil {
		return nil
	}
	return value
}

func render(value *template.Template, params Params) (string, bool) {
	if value == nil {
		return "", false
	}
	var buffer bytes.Buffer
	if err := value.Execute(&buffer, params); err != nil {
		return "", false
	}
	return buffer.String(), true
}
