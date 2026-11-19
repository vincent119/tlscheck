package report

import (
	"fmt"
	"strings"
	"unicode"

	gp "github.com/jedib0t/go-pretty/v6/table"
	"github.com/mattn/go-runewidth"
	"github.com/rivo/uniseg"
)

// 字寬策略留在呼叫範圍內，避免隨環境或其他Writer的全域設定改變。
func tableDisplayWidth(s string) int {
	condition := runewidth.Condition{EastAsianWidth: false, StrictEmojiNeutral: true}
	return condition.StringWidth(s)
}

func tableWrap(s string, width int) ([]string, error) {
	if width < 1 {
		return nil, fmt.Errorf("內容欄寬必須大於零")
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return nil, fmt.Errorf("表格布局只接受已清理的單行文字")
		}
	}
	lines := []string{}
	var line strings.Builder
	used := 0
	g := uniseg.NewGraphemes(s)
	for g.Next() {
		cluster := g.Str()
		n := tableDisplayWidth(cluster)
		if n > width {
			return nil, fmt.Errorf("字素群組寬度超過可用欄寬")
		}
		if used > 0 && used+n > width {
			lines = append(lines, line.String())
			line.Reset()
			used = 0
		}
		line.WriteString(cluster)
		used += n
	}
	return append(lines, line.String()), nil
}

// tableFrame保留單欄呼叫介面；多欄使用同一個局部字寬與還原流程。
func tableFrame(values []string, width int) (string, error) {
	rows := make([][]string, len(values))
	for i, value := range values {
		rows[i] = []string{value}
	}
	return tableGrid(nil, rows, []int{width})
}

// 上游只排固定ASCII框架；先核對每列每欄的形狀，再按位置還原原值。
func tableGrid(headers []string, data [][]string, widths []int) (string, error) {
	if len(widths) == 0 {
		return "", fmt.Errorf("表格至少需要一欄")
	}
	for _, width := range widths {
		if width < 1 {
			return "", fmt.Errorf("內容欄寬必須大於零")
		}
	}
	if len(data) == 0 {
		return "", nil
	}
	all := data
	if len(headers) > 0 {
		all = append([][]string{headers}, data...)
	}
	writer := gp.NewWriter()
	writer.SetStyle(gp.StyleDefault)
	configs := make([]gp.ColumnConfig, len(widths))
	border := "+"
	for i, w := range widths {
		configs[i] = gp.ColumnConfig{Number: i + 1, WidthMin: w, WidthMax: w}
		border += strings.Repeat("-", w+2) + "+"
	}
	writer.SetColumnConfigs(configs)
	expected := []string{border}
	restored := []string{border}
	for rowIndex, record := range all {
		if len(record) != len(widths) {
			return "", fmt.Errorf("表格資料欄數不符")
		}
		cells := make([][]string, len(widths))
		height := 1
		for i, value := range record {
			lines, err := tableWrap(value, widths[i])
			if err != nil {
				return "", err
			}
			cells[i] = lines
			if len(lines) > height {
				height = len(lines)
			}
		}
		shadow := make(gp.Row, len(widths))
		for i, w := range widths {
			shadow[i] = strings.TrimSuffix(strings.Repeat(strings.Repeat("x", w)+"\n", height), "\n")
		}
		writer.AppendRow(shadow)
		for lineIndex := 0; lineIndex < height; lineIndex++ {
			raw, actual := "|", "|"
			for i, w := range widths {
				value := ""
				if lineIndex < len(cells[i]) {
					value = cells[i][lineIndex]
				}
				raw += " " + strings.Repeat("x", w) + " |"
				actual += " " + value + strings.Repeat(" ", w-tableDisplayWidth(value)) + " |"
			}
			expected = append(expected, raw)
			restored = append(restored, actual)
		}
		if rowIndex == 0 && len(headers) > 0 && len(all) > 1 {
			writer.AppendSeparator()
			expected = append(expected, border)
			restored = append(restored, border)
		}
	}
	expected = append(expected, border)
	restored = append(restored, border)
	raw := strings.Split(writer.Render(), "\n")
	if len(raw) != len(expected) {
		return "", fmt.Errorf("上游ASCII框架列數不符")
	}
	for i := range raw {
		if raw[i] != expected[i] {
			return "", fmt.Errorf("上游ASCII框架欄位或邊框不符")
		}
	}
	return strings.Join(restored, "\n"), nil
}
