package report

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jedib0t/go-pretty/v6/text"
)

func TestTableFramePreservesWidthValuesAndGlobalPolicy(t *testing.T) {
	before := text.StringWidthWithoutEscSequences("α·β·γ")
	values := []string{"α·β·γ", "  中Ａe\u0301  ", strings.Repeat("A1", 32), strings.Repeat("a-long-name-", 20), "one   two    three", tableText(`x|alpha\beta`)}
	for _, width := range []int{36, 76, 116} {
		for _, value := range values {
			lines, err := tableWrap(value, width)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Join(lines, "") != value {
				t.Fatal("換行遺失字元或空白")
			}
			frame, err := tableFrame([]string{value}, width)
			if err != nil {
				t.Fatal(err)
			}
			rows := strings.Split(frame, "\n")
			if len(rows) != len(lines)+2 {
				t.Fatal("框架行數不符")
			}
			for i, line := range lines {
				w := 0
				for _, r := range line {
					w += runeWidth(r)
				}
				if w > width || rows[i+1] != "| "+line+strings.Repeat(" ", width-w)+" |" {
					t.Fatal("字寬、布局或空白不符", width, value)
				}
			}
		}
	}
	if tableDisplayWidth("α·β·γ") != 5 || text.StringWidthWithoutEscSequences("α·β·γ") != before {
		t.Fatal("模糊寬字未固定或上游全域設定遭修改")
	}
}

func TestTableFrameUsesSameContractInBothEnvironments(t *testing.T) {
	for _, mode := range []string{"0", "1"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^(TestTableFramePreservesWidthValuesAndGlobalPolicy|TestTableGridKeepsColumnsAndWhitespace|TestSummaryScopesAndWidths|TestCompactLocalSummaryRetainsFactsAndFullContract)$", "-test.v")
			for _, v := range os.Environ() {
				if !strings.HasPrefix(v, "RUNEWIDTH_EASTASIAN=") {
					cmd.Env = append(cmd.Env, v)
				}
			}
			cmd.Env = append(cmd.Env, "RUNEWIDTH_EASTASIAN="+mode)
			out, err := cmd.CombinedOutput()
			if err != nil || !strings.Contains(string(out), "--- PASS: TestTableFramePreservesWidthValuesAndGlobalPolicy") || !strings.Contains(string(out), "--- PASS: TestTableGridKeepsColumnsAndWhitespace") || !strings.Contains(string(out), "--- PASS: TestSummaryScopesAndWidths") || !strings.Contains(string(out), "--- PASS: TestCompactLocalSummaryRetainsFactsAndFullContract") || strings.Contains(string(out), "SKIP") {
				t.Fatalf("雙環境回歸未具名通過：%v\n%s", err, out)
			}
		})
	}
}

func TestTableReportStaysWithinConfiguredWidth(t *testing.T) {
	for _, lang := range []string{"en", "zh-TW", "zh-CN"} {
		for _, width := range []int{40, 80, 120} {
			var buf bytes.Buffer
			d := localizedFixture(lang)
			if err := renderTable(&buf, d, width); err != nil {
				t.Fatal(err)
			}
			for _, line := range strings.Split(buf.String(), "\n") {
				n := 0
				for _, r := range line {
					n += runeWidth(r)
				}
				if n > width || strings.ContainsRune(line, '\x1b') {
					t.Fatal("報告超寬或含ANSI", lang, width, n)
				}
			}
		}
	}
}

func TestTableGridKeepsColumnsAndWhitespace(t *testing.T) {
	got, err := tableGrid([]string{"A", "B", "C"}, [][]string{{"中a", " α ", "x  y"}}, []int{4, 4, 6})
	if err != nil {
		t.Fatal(err)
	}
	want := "+------+------+--------+\n| A    | B    | C      |\n+------+------+--------+\n| 中a  |  α   | x  y   |\n+------+------+--------+"
	if got != want {
		t.Fatalf("多欄寬度或值內空白改變：\n%s", got)
	}
	got, err = tableGrid(nil, [][]string{{"甲乙丙", "12"}, {"e\u0301", "abcde"}}, []int{4, 3})
	if err != nil {
		t.Fatal(err)
	}
	want = "+------+-----+\n| 甲乙 | 12  |\n| 丙   |     |\n| e\u0301    | abc |\n|      | de  |\n+------+-----+"
	if got != want {
		t.Fatalf("多欄續行、組合字或相鄰欄位關聯遺失：\n%s", got)
	}
}
