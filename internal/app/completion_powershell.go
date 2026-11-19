package app

import (
	"errors"
	"strings"
)

// withPowerShellEmptyCandidates 僅轉換已知模板，避免未知版本重新啟用檔名回退。
func withPowerShellEmptyCandidates(script string) (string, error) {
	const header = `[scriptblock]${__tlscheckCompleterBlock} = {
    param(
            $WordToComplete,
            $CommandAst,
            $CursorPosition
        )
`
	const empty = `        if ($Values.Length -eq 0) {
            # Just print an empty string here so the
            # shell does not start to complete paths.
            # We cannot use CompletionResult here because
            # it does not accept an empty string as argument.
            ""
            return
        }`
	const errorGuard = "    if (($Directive -band $ShellCompDirectiveError) -ne 0 ) {"
	if strings.Count(script, header) != 1 || strings.Count(script, empty) != 1 || strings.Count(script, errorGuard) != 1 {
		return "", errors.New("未知 PowerShell 補全腳本結構")
	}
	script = strings.Replace(script, header, header+`
    # 保留引擎原始字詞，避免等號、引號或游標移動後只剩重算的前綴。
    $OriginalWordToComplete = $WordToComplete
`, 1)
	// 在模板處理空值／等號之前攔截，Error 與 NoFileComp 同時出現也不得回退。
	const early = `    if (($Directive -band $ShellCompDirectiveNoFileComp) -ne 0 -and -not $Out) {
        $NoopText = $OriginalWordToComplete
        if ([string]::IsNullOrEmpty($NoopText)) {
            $NoopText = " "
        }
        [System.Management.Automation.CompletionResult]::new($NoopText, $NoopText, 'ParameterValue', ' ')
        return
    }

`
	script = strings.Replace(script, errorGuard, early+errorGuard, 1)
	const placeholder = `        if ($Values.Length -eq 0) {
            # 空集合會回退檔名，空字串會被部分 PowerShell 版本拒絕。
            # 占位保留既有字詞；空游標只增加一個空白，不增加參數。
            $NoopText = $OriginalWordToComplete
            if ([string]::IsNullOrEmpty($NoopText)) {
                $NoopText = " "
            }
            [System.Management.Automation.CompletionResult]::new($NoopText, $NoopText, 'ParameterValue', ' ')
            return
        }`
	return strings.Replace(script, empty, placeholder, 1), nil
}
