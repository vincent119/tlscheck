package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"reflect"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/text/width"

	"github.com/vincent119/tlscheck/internal/i18n"
)

type row struct{ Label, Value string }
type section struct {
	Title string
	Rows  []row
}

// Render 先完成記憶體序列化，再輸出，避免格式錯誤留下半份文件。
func Render(out io.Writer, format string, d Document) error {
	var buf bytes.Buffer
	if format == "json" {
		e := json.NewEncoder(&buf)
		e.SetIndent("", "  ")
		if err := e.Encode(d); err != nil {
			return err
		}
	} else {
		t := i18n.New(d.Language)
		grids := humanGrids(d, t)
		sections := []section{}
		for _, v := range []struct {
			name  string
			value reflect.Value
		}{{"summary", reflect.ValueOf(d.Summary)}, {"tool", reflect.ValueOf(d.Tool)}, {"generated_at", reflect.ValueOf(d.GeneratedAt)}, {"inputs", reflect.ValueOf(d.Inputs)}, {"local", reflect.ValueOf(d.Local)}, {"remote", reflect.ValueOf(d.Remote)}} {
			s := section{Title: label(t, v.name)}
			flatten(t, v.value, "", &s.Rows)
			sections = append(sections, s)
		}
		switch format {
		case "table":
			for _, g := range grids {
				writeGrid(&buf, g)
			}
			for _, s := range sections {
				fmt.Fprintln(&buf, s.Title)
				border := "+" + strings.Repeat("-", 30) + "+" + strings.Repeat("-", 74) + "+"
				fmt.Fprintln(&buf, border)
				tableRow(&buf, label(t, "field"), label(t, "value"))
				fmt.Fprintln(&buf, border)
				for _, r := range s.Rows {
					tableRow(&buf, r.Label, r.Value)
				}
				fmt.Fprintln(&buf, border)
				fmt.Fprintln(&buf)
			}
		case "markdown":
			for _, g := range grids {
				fmt.Fprintf(&buf, "## %s\n\n", markdown(g.Title))
				markdownRow(&buf, g.Headers)
				separators := make([]string, len(g.Headers))
				for i := range separators {
					separators[i] = ":---"
				}
				fmt.Fprintf(&buf, "| %s |\n", strings.Join(separators, " | "))
				for _, r := range g.Rows {
					markdownRow(&buf, r)
				}
				fmt.Fprintln(&buf)
			}
			for _, s := range sections {
				fmt.Fprintf(&buf, "## %s\n\n| %s | %s |\n| :--- | :--- |\n", markdown(s.Title), markdown(label(t, "field")), markdown(label(t, "value")))
				for _, r := range s.Rows {
					fmt.Fprintf(&buf, "| %s | %s |\n", markdown(r.Label), markdown(r.Value))
				}
				fmt.Fprintln(&buf)
			}
		case "html":
			const page = `<!DOCTYPE html>
<html lang="{{.Language}}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>tlscheck</title><style>body{font-family:system-ui,sans-serif;margin:2rem auto;padding:0 1rem;max-width:70rem;color:#17202a;background:#fff}table{width:100%;border-collapse:collapse;table-layout:fixed;margin-bottom:2rem}th,td{text-align:left;vertical-align:top;border:1px solid #9ba5af;padding:.6rem;overflow-wrap:anywhere;white-space:pre-wrap}th:first-child,td:first-child{width:32%}caption{text-align:left;font-size:1.4rem;font-weight:bold;margin:1rem 0}</style></head><body><h1>tlscheck</h1>{{range .Grids}}<table><caption>{{.Title}}</caption><thead><tr>{{range .Headers}}<th scope="col">{{.}}</th>{{end}}</tr></thead><tbody>{{range .Rows}}<tr>{{range .}}<td>{{.}}</td>{{end}}</tr>{{end}}</tbody></table>{{end}}{{range .Sections}}<table><caption>{{.Title}}</caption><thead><tr><th scope="col">{{$.Field}}</th><th scope="col">{{$.Value}}</th></tr></thead><tbody>{{range .Rows}}<tr><td>{{.Label}}</td><td>{{.Value}}</td></tr>{{end}}</tbody></table>{{end}}</body></html>
`
			pageTemplate, err := template.New("report").Parse(page)
			if err != nil {
				return err
			}
			data := struct {
				Language, Field, Value string
				Sections               []section
				Grids                  []grid
			}{d.Language, label(t, "field"), label(t, "value"), sections, grids}
			if err := pageTemplate.Execute(&buf, data); err != nil {
				return err
			}
		default:
			return errors.New("無效報告格式")
		}
	}
	n, err := out.Write(buf.Bytes())
	if err == nil && n != buf.Len() {
		err = io.ErrShortWrite
	}
	return err
}

func label(t *i18n.Translator, key string) string { return t.Text("document."+key, nil) }

// flatten 只走訪已投影 Document 的欄位；不能接收 domain 物件或私鑰。
func flatten(t *i18n.Translator, v reflect.Value, path string, rows *[]row) {
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			*rows = append(*rows, row{path, label(t, "unknown")})
			return
		}
		flatten(t, v.Elem(), path, rows)
		return
	}
	switch v.Kind() {
	case reflect.Struct:
		typ := v.Type()
		for i := 0; i < v.NumField(); i++ {
			name := typ.Field(i).Tag.Get("json")
			next := label(t, name)
			if path != "" {
				next = path + " / " + next
			}
			field := v.Field(i)

			category := ""
			switch {
			case typ == reflect.TypeFor[Input]() && name == "kind":
				category = "kind"
			case name == "severity" && typ == reflect.TypeFor[Result](), name == "highest_severity" && typ == reflect.TypeFor[Summary]():
				category = "severity"
			case typ == reflect.TypeFor[Remote]() && name == "stage":
				category = "stage"
			case typ == reflect.TypeFor[Check]() && name == "name":
				category = "check"
			case typ == reflect.TypeFor[URI]() && name == "reason":
				category = "uri_reason"
			}
			if category != "" {
				value := field
				if value.Kind() == reflect.Pointer {
					if value.IsNil() {
						flatten(t, field, next, rows)
						continue
					}
					value = value.Elem()
				}
				if value.Kind() == reflect.String {
					*rows = append(*rows, row{next, displayValue(t, category, value.String())})
					continue
				}
			}
			if name == "status" && field.Kind() == reflect.String {
				*rows = append(*rows, row{next, t.Text("status."+field.String(), nil)})
				continue
			}
			if name == "role" && field.Kind() == reflect.String && (field.String() == "site" || field.String() == "ca") {
				*rows = append(*rows, row{next, t.Text("role."+field.String(), nil)})
				continue
			}
			flatten(t, field, next, rows)
		}
	case reflect.Slice:
		if v.Len() == 0 {
			*rows = append(*rows, row{path, "[]"})
			return
		}
		for i := 0; i < v.Len(); i++ {
			flatten(t, v.Index(i), path+" ["+strconv.Itoa(i)+"]", rows)
		}
	case reflect.String:
		*rows = append(*rows, row{path, v.String()})
	case reflect.Bool:
		s := t.Text("report.no", nil)
		if v.Bool() {
			s = t.Text("report.yes", nil)
		}
		*rows = append(*rows, row{path, s})
	case reflect.Int, reflect.Int64:
		*rows = append(*rows, row{path, strconv.FormatInt(v.Int(), 10)})
	case reflect.Uint16:
		*rows = append(*rows, row{path, strconv.FormatUint(v.Uint(), 10)})
	}
}
func markdown(s string) string {
	// 所有外部文字都用實體編碼標點，避免成為連結、HTML、表格或程式碼語法。
	var b strings.Builder
	for _, r := range s {
		if unicode.IsPunct(r) || unicode.IsSymbol(r) {
			fmt.Fprintf(&b, "&#%d;", r)
		} else if r == '\n' || r == '\r' {
			b.WriteString(" ")
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}
func runeWidth(r rune) int {
	if unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Me, r) {
		return 0
	}
	switch width.LookupRune(r).Kind() {
	case width.EastAsianWide, width.EastAsianFullwidth:
		return 2
	}
	return 1
}
func wrap(s string, maxWidth int) []string {
	lines := []string{}
	runes := []rune(s)
	for len(runes) > 0 {
		n, end, lastSpace := 0, 0, -1
		for end < len(runes) && n+runeWidth(runes[end]) <= maxWidth {
			n += runeWidth(runes[end])
			if runes[end] == ' ' {
				lastSpace = end
			}
			end++
		}
		if end < len(runes) && lastSpace > 0 && lastSpace > end/3 {
			end = lastSpace + 1
		}
		if end == 0 {
			end = 1
		}
		lines = append(lines, string(runes[:end]))
		runes = runes[end:]
	}
	if len(lines) == 0 {
		return []string{""}
	}
	return lines
}

func tableRow(out *bytes.Buffer, left, right string) {
	a, b := wrap(tableText(left), 28), wrap(tableText(right), 72)
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		l, r := "", ""
		if i < len(a) {
			l = a[i]
		}
		if i < len(b) {
			r = b[i]
		}
		fmt.Fprintf(out, "| %s | %s |\n", pad(l, 28), pad(r, 72))
	}
}
func pad(s string, n int) string {
	w := 0
	for _, r := range s {
		w += runeWidth(r)
	}
	return s + strings.Repeat(" ", max(0, n-w))
}

// Diagnostics 只將固定執行錯誤訊息送到 stderr，不重複計數。
func Diagnostics(out io.Writer, d Document) error {
	var walk func(reflect.Value) error
	walk = func(v reflect.Value) error {
		if v.Kind() == reflect.Pointer {
			if v.IsNil() {
				return nil
			}
			return walk(v.Elem())
		}
		if v.Type() == reflect.TypeFor[Result]() {
			if v.FieldByName("Severity").String() == "execution" {
				_, err := fmt.Fprintln(out, v.FieldByName("Message").String())
				return err
			}
			return nil
		}
		switch v.Kind() {
		case reflect.Struct:
			for i := 0; i < v.NumField(); i++ {
				if err := walk(v.Field(i)); err != nil {
					return err
				}
			}
		case reflect.Slice:
			for i := 0; i < v.Len(); i++ {
				if err := walk(v.Index(i)); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(reflect.ValueOf(d))
}

// tableText 的反斜線先跳脫，使資料中的字面 \u007c 與 pipe 保持可區別。
func tableText(s string) string { return strings.NewReplacer("\\", "\\\\", "|", "\\u007c").Replace(s) }

func writeGrid(out *bytes.Buffer, g grid) {
	fmt.Fprintln(out, g.Title)
	border := "+"
	for _, w := range g.Widths {
		border += strings.Repeat("-", w+2) + "+"
	}
	fmt.Fprintln(out, border)
	gridRow(out, g.Headers, g.Widths)
	fmt.Fprintln(out, border)
	for _, r := range g.Rows {
		gridRow(out, r, g.Widths)
	}
	fmt.Fprintln(out, border)
	fmt.Fprintln(out)
}
func gridRow(out *bytes.Buffer, values []string, widths []int) {
	cells := make([][]string, len(widths))
	n := 1
	for i, w := range widths {
		value := ""
		if i < len(values) {
			value = values[i]
		}
		cells[i] = wrap(tableText(value), w)
		n = max(n, len(cells[i]))
	}
	for line := 0; line < n; line++ {
		out.WriteByte('|')
		for i, w := range widths {
			value := ""
			if line < len(cells[i]) {
				value = cells[i][line]
			}
			fmt.Fprintf(out, " %s |", pad(value, w))
		}
		out.WriteByte('\n')
	}
}
func markdownRow(out *bytes.Buffer, values []string) {
	cells := make([]string, len(values))
	for i, v := range values {
		cells[i] = markdown(v)
	}
	fmt.Fprintf(out, "| %s |\n", strings.Join(cells, " | "))
}
