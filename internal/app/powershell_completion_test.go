package app

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPowerShellEmptyCandidatesDoNotFallbackToFiles(t *testing.T) {
	pwsh, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("缺少 PowerShell，無法執行真實補全引擎驗收")
	}
	for _, noDescriptions := range []bool{false, true} {
		name := "包含描述"
		if noDescriptions {
			name = "不含描述"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			for _, file := range []string{"--for-file-bait", "--invalid-file-bait", "secret-file-bait", "invalid-file-bait", "憑證 file.pem"} {
				if err := os.WriteFile(filepath.Join(dir, file), []byte("合成檔名誘餌"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			args := []string{"completion", "powershell"}
			if noDescriptions {
				args = append(args, "--no-descriptions")
			}
			var script, diagnostics bytes.Buffer
			if code := New().Run(t.Context(), args, &script, &diagnostics); code != 0 || diagnostics.Len() != 0 {
				t.Fatalf("無法產生補全腳本：%d，%s", code, diagnostics.String())
			}
			completion := filepath.Join(dir, "completion.ps1")
			if err := os.WriteFile(completion, script.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
			sentinel := filepath.Join(dir, "debug-sentinel")
			if err := os.WriteFile(sentinel, []byte("unchanged"), 0600); err != nil {
				t.Fatal(err)
			}
			// 函式只轉送至既有測試入口；補全本身仍經過真實 PowerShell 引擎。
			body := "$ErrorActionPreference = 'Stop'\n$script:helper = " + powerShellLiteral(os.Args[0]) + "\n" +
				"function tlscheck { & $script:helper '-test.run=^TestCompletionProcessHelper$' '--' @args }\n. " + powerShellLiteral(completion) + "\n" + powerShellEngineAssertions
			path := filepath.Join(dir, "verify.ps1")
			if err := os.WriteFile(path, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, pwsh, "-NoProfile", "-NonInteractive", "-File", path)
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "TLSCHECK_COMPLETION_TEST_HELPER=1", "BASH_COMP_DEBUG_FILE="+sentinel)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("PowerShell 補全引擎回歸失敗：%v\n%s", err, out)
			}
			if data, err := os.ReadFile(sentinel); err != nil || string(data) != "unchanged" {
				t.Fatal("補全改寫偵錯檔", err)
			}
		})
	}
}

func powerShellLiteral(value string) string { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }

func TestPowerShellCompletionRejectsUnknownTemplate(t *testing.T) {
	var original bytes.Buffer
	if err := completionCommand(&RunOptions{}).GenPowerShellCompletionWithDesc(&original); err != nil {
		t.Fatal(err)
	}
	for _, script := range []string{
		strings.Replace(original.String(), "$CursorPosition\n", "$CursorOffset\n", 1),
		strings.Replace(original.String(), "if ($Values.Length -eq 0)", "if ($Values.Count -eq 0)", 1),
		strings.Replace(original.String(), "if (($Directive -band $ShellCompDirectiveError) -ne 0 )", "if ($Directive -eq 1)", 1),
		original.String() + original.String(),
	} {
		if result, err := withPowerShellEmptyCandidates(script); err == nil || result != "" {
			t.Fatal("未知 PowerShell 模板未停止生成")
		}
	}
}

const powerShellEngineAssertions = `
function Get-CommandWords([string]$line) {
    $tokens = $null; $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($line, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count) { throw '補全結果不是有效命令' }
    $command = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true)
    return ($command.CommandElements | ForEach-Object { $_.Extent.Text }) -join [char]0
}
foreach ($case in @(
    @{ Line='tlscheck --format json --for' },
    @{ Line='tlscheck --invalid' },
    @{ Line='tlscheck completion zsh '; Empty=$true },
    @{ Line='tlscheck --remote secret' },
    @{ Line='tlscheck --format invalid' },
    @{ Line='tlscheck --format=invalid' },
    @{ Line="tlscheck --remote 'secret phrase'" },
    @{ Line='tlscheck --remote "secret phrase"' },
    @{ Line='tlscheck --remote secretTrailing'; Cursor=24 },
    @{ Line='tlscheck --remote secret --language en'; Cursor=23 },
    @{ Line='tlscheck --help '; Empty=$true }
)) {
    $line = $case.Line
    $cursor = if ($case.ContainsKey('Cursor')) { $case.Cursor } else { $line.Length }
    $result = TabExpansion2 $line $cursor
    if ($result.CompletionMatches.Count -ne 1) {
        throw ('無候選未回傳唯一占位，可能回退檔名：' + $line + '，游標=' + $cursor + '，數量=' + $result.CompletionMatches.Count)
    }
    foreach ($match in $result.CompletionMatches) {
        $completed = $line.Remove($result.ReplacementIndex, $result.ReplacementLength).Insert($result.ReplacementIndex, $match.CompletionText)
        if ($case.Empty) {
            if ($match.CompletionText -cne ' ' -or $result.ReplacementLength -ne 0) {
                throw '空游標占位不是單一空白'
            }
        } elseif ($completed -cne $line) {
            throw ('無候選更動已有字詞：' + $line + ' -> ' + $completed)
        }
        if ((Get-CommandWords $completed) -cne (Get-CommandWords $line)) {
            throw '無候選補全更動參數或回退到檔名'
        }
    }
}
foreach ($case in @(
    @{ Line='tlscheck --format j'; Expected='json' },
    @{ Line='tlscheck --format=j'; Expected='--format=json' },
    @{ Line='tlscheck -f h'; Expected='html' },
    @{ Line='tlscheck -L zh-T'; Expected='zh-TW' },
    @{ Line='tlscheck completion z'; Expected='zsh' }
)) {
    $matches = @((TabExpansion2 $case.Line $case.Line.Length).CompletionMatches)
    if ($matches.Count -ne 1 -or $matches[0].CompletionText.TrimEnd() -cne $case.Expected) {
        throw '有效候選補全遺失或不符'
    }
}
$line = 'tlscheck --local ./憑'
$matches = @((TabExpansion2 $line $line.Length).CompletionMatches)
if ($matches.Count -ne 1 -or $matches[0].CompletionText -notlike '*憑證 file.pem*') {
    throw '本機檔名補全遺失空白或 Unicode'
}
$line = 'tlscheck --output ./憑'
$matches = @((TabExpansion2 $line $line.Length).CompletionMatches)
if ($matches.Count -ne 1 -or $matches[0].CompletionText -notlike '*憑證 file.pem*') {
    throw '輸出路徑檔名補全被禁止'
}
`
