param(
    [string]$BinaryPath = (Join-Path $PSScriptRoot 'tlscheck.exe'),
    [string]$OutputDirectory,
    [switch]$Worker
)

# 子程序參數使用 ArgumentList，避免空字串、空白與引號被 shell 重新解譯。
function Invoke-ExeProbe {
    param([string]$BinaryPath, [string[]]$Arguments, [string]$WorkingDirectory,
          [int]$TimeoutMilliseconds = 10000)
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $BinaryPath
    $info.WorkingDirectory = $WorkingDirectory
    $info.UseShellExecute = $false
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.RedirectStandardInput = $true
    $info.StandardOutputEncoding = [Text.UTF8Encoding]::new($false, $true)
    $info.StandardErrorEncoding = [Text.UTF8Encoding]::new($false, $true)
    foreach ($item in $Arguments) { $info.ArgumentList.Add($item) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $info
    try {
        $null = $process.Start()
        $process.StandardInput.Close()
        $outTask = $process.StandardOutput.ReadToEndAsync()
        $errTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutMilliseconds)) {
            $process.Kill($true)
            $process.WaitForExit()
            throw '子程序逾時，驗收失敗'
        }
        $result = [pscustomobject]@{ Code=$process.ExitCode; Out=$outTask.GetAwaiter().GetResult(); Err=$errTask.GetAwaiter().GetResult() }
        if ($null -ne $script:AcceptanceProbes) {
            $script:AcceptanceProbes.Add([pscustomobject]@{ Arguments=$Arguments; Code=$result.Code; Out=$result.Out; Err=$result.Err })
        }
        return $result
    } finally { $process.Dispose() }
}

function Assert-Acceptance([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Get-AcceptanceFileState([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        return "缺檔;目錄存在=$(Test-Path -LiteralPath (Split-Path -Parent $Path))"
    }
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer) { throw '設定位置不是一般檔案' }
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $acl = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes((Get-Acl -LiteralPath $Path).Sddl)))
    } finally { $sha.Dispose() }
    return "$((Get-FileHash -LiteralPath $Path).Hash);$($item.Length);$($item.LastWriteTimeUtc.Ticks);$($item.Attributes);$acl"
}

function Get-AcceptanceWords([string]$Line) {
    $tokens = $null; $parseErrors = $null
    $ast = [Management.Automation.Language.Parser]::ParseInput($Line, [ref]$tokens, [ref]$parseErrors)
    Assert-Acceptance ($parseErrors.Count -eq 0) '補全產生無效命令'
    $command = $ast.Find({ param($node) $node -is [Management.Automation.Language.CommandAst] }, $true)
    return ($command.CommandElements | ForEach-Object { $_.Extent.Text }) -join [char]0
}

function Invoke-AcceptanceCase([string]$Name, [scriptblock]$Test) {
    try {
        & $Test | Out-Null
        $script:AcceptanceResults.Add([pscustomobject]@{ Name=$Name; Status='PASS'; Detail='' })
        Write-Host "PASS $Name"
    } catch {
        $script:AcceptanceResults.Add([pscustomobject]@{ Name=$Name; Status='FAIL'; Detail=$_.Exception.Message })
        Write-Host "FAIL $Name：$($_.Exception.Message)"
    }
}

# 可攜子集可在開發環境對原生 binary 驗證；不等同 Windows 實機通過。
function Invoke-AcceptanceSuite([string]$Binary, [string]$Root) {
    $script:AcceptanceBinary = $Binary
    $script:AcceptanceRoot = $Root
    $script:AcceptanceResults = [Collections.Generic.List[object]]::new()
    $script:AcceptanceProbes = [Collections.Generic.List[object]]::new()
    $utf8 = [Text.UTF8Encoding]::new($false)
    foreach ($name in @('--for-file-bait','--invalid-file-bait','secret-file-bait','invalid-file-bait','憑證 file.pem')) {
        [IO.File]::WriteAllText((Join-Path $Root $name), '合成測試資料', $utf8)
    }
    Invoke-AcceptanceCase '版本與結束碼' {
        $r = Invoke-ExeProbe $Binary @('--language','en','--version') $Root
        Assert-Acceptance ($r.Code -eq 0 -and $r.Out -match 'tlscheck' -and $r.Err -eq '') '版本輸出或結束碼不符'
        $script:AcceptanceVersion = $r.Out.Trim()
    }
    foreach ($lang in @('en','zh-TW','zh-CN')) {
        Invoke-AcceptanceCase "語系說明 $lang" {
            $r = Invoke-ExeProbe $Binary @('--language',$lang,'--help') $Root
            Assert-Acceptance ($r.Code -eq 0 -and $r.Out.Length -gt 0 -and $r.Err -eq '') '說明查詢失敗'
        }
    }
    foreach ($arguments in @(
        @('--language','en','--unknown=synthetic-secret'),
        @('--language','en','--remote'),
        @('--language','en','--local',''),
        @('--language','en','--timeout','0s')
    )) {
        Invoke-AcceptanceCase ('無效參數 ' + ($arguments -join ' ')) {
            $r = Invoke-ExeProbe $Binary $arguments $Root
            Assert-Acceptance ($r.Code -eq 2 -and $r.Out -eq '') '參數錯誤必須回 2 且不產生報告'
            Assert-Acceptance (-not $r.Err.Contains('synthetic-secret')) '參數錯誤洩漏原始值'
        }
    }
    foreach ($format in @('table','json','html','markdown')) {
        Invoke-AcceptanceCase "本機錯誤與格式 $format" {
            $r = Invoke-ExeProbe $Binary @('-L','en','-l','憑證 file.pem','-f',$format) $Root
            Assert-Acceptance ($r.Code -eq 2 -and $r.Out.Length -gt 0) '本機解析錯誤須回 2 並產生報告'
            if ($format -eq 'json') {
                $doc = $r.Out | ConvertFrom-Json
                Assert-Acceptance ($doc.schema_version -eq 1 -and $doc.summary.check_exit_code -eq 2) 'JSON 契約或結束碼不符'
            }
            if ($format -eq 'html') { Assert-Acceptance ($r.Out -match '<html') 'HTML 結構缺失' }
            if ($format -eq 'markdown') { Assert-Acceptance ($r.Out -match '\|') 'Markdown 表格缺失' }
        }
    }
    Invoke-AcceptanceCase '報告寫入與拒絕覆寫' {
        $path = Join-Path $Root 'report.json'
        $r = Invoke-ExeProbe $Binary @('-L','en','-l','憑證 file.pem','-f','json','-o',$path) $Root
        Assert-Acceptance ($r.Code -eq 2 -and $r.Out -eq '' -and (Test-Path -LiteralPath $path)) '報告寫入失敗'
        $before = (Get-FileHash -LiteralPath $path).Hash
        $r = Invoke-ExeProbe $Binary @('-L','en','-l','憑證 file.pem','-f','json','-o',$path) $Root
        Assert-Acceptance ($r.Code -eq 2 -and $before -eq (Get-FileHash -LiteralPath $path).Hash) '覆寫保護失敗'
    }
    Invoke-AcceptanceCase '非 TTY 選單拒絕與結束碼' {
        $r = Invoke-ExeProbe $Binary @('--settings') $Root
        Assert-Acceptance ($r.Code -eq 2 -and $r.Out -eq '') '非 TTY 不可開啟設定選單'
    }
    # 僅在專用子程序註冊 completer，不改 profile 或日常 PowerShell 工作階段。
    function global:tlscheck {
        $r = Invoke-ExeProbe $script:AcceptanceBinary @($args) $script:AcceptanceRoot
        $global:LASTEXITCODE = $r.Code
        if ($r.Err) { throw '補全有非預期診斷' }
        $r.Out.TrimEnd([char[]]"`r`n") -split '\r?\n'
    }
    Push-Location -LiteralPath $Root
    try {
        foreach ($variant in @('包含描述','不含描述')) {
            $arguments = @('completion','powershell')
            if ($variant -eq '不含描述') { $arguments += '--no-descriptions' }
            $r = Invoke-ExeProbe $Binary $arguments $Root
            if ($r.Code -ne 0 -or $r.Err) { throw '無法產生補全腳本' }
            [IO.File]::WriteAllText((Join-Path $Root ($variant + '.ps1')), $r.Out, $utf8)
            . ([scriptblock]::Create($r.Out))
            foreach ($case in @(
                @{ Line='tlscheck --format json --for' }, @{ Line='tlscheck --invalid' },
                @{ Line='tlscheck completion zsh '; Empty=$true }, @{ Line='tlscheck --remote secret' },
                @{ Line='tlscheck --format invalid' }, @{ Line='tlscheck --format=invalid' },
                @{ Line="tlscheck --remote 'secret phrase'" }, @{ Line='tlscheck --remote "secret phrase"' },
                @{ Line='tlscheck --remote secretTrailing'; Cursor=24 },
                @{ Line='tlscheck --remote secret --language en'; Cursor=23 },
                @{ Line='tlscheck --help '; Empty=$true }
            )) {
                Invoke-AcceptanceCase "$variant 無候選 $($case.Line) 游標=$($case.Cursor)" {
                    $line = $case.Line
                    $cursor = if ($case.ContainsKey('Cursor')) { $case.Cursor } else { $line.Length }
                    $result = TabExpansion2 $line $cursor
                    Assert-Acceptance ($result.CompletionMatches.Count -eq 1) '無候選不是唯一占位，存在檔名回退風險'
                    $match = $result.CompletionMatches[0]
                    $completed = $line.Remove($result.ReplacementIndex,$result.ReplacementLength).Insert($result.ReplacementIndex,$match.CompletionText)
                    if ($case.Empty) {
                        Assert-Acceptance ($match.CompletionText -ceq ' ' -and $result.ReplacementLength -eq 0) '空游標占位不符'
                    } else { Assert-Acceptance ($completed -ceq $line) '無候選改寫既有輸入' }
                    Assert-Acceptance ((Get-AcceptanceWords $completed) -ceq (Get-AcceptanceWords $line)) '補全增加參數'
                }
            }
            foreach ($case in @(
                @{ Line='tlscheck --format j'; Expected='json' }, @{ Line='tlscheck --format=j'; Expected='--format=json' },
                @{ Line='tlscheck -f h'; Expected='html' }, @{ Line='tlscheck -L zh-T'; Expected='zh-TW' },
                @{ Line='tlscheck completion z'; Expected='zsh' }
            )) {
                Invoke-AcceptanceCase "$variant 合法候選 $($case.Line)" {
                    $matches = @((TabExpansion2 $case.Line $case.Line.Length).CompletionMatches)
                    Assert-Acceptance ($matches.Count -eq 1 -and $matches[0].CompletionText.TrimEnd() -ceq $case.Expected) '合法補全候選不符'
                }
            }
            foreach ($flag in @('--local','--output')) {
                Invoke-AcceptanceCase "$variant 合法檔名 $flag" {
                    $line = "tlscheck $flag ./憑"
                    $matches = @((TabExpansion2 $line $line.Length).CompletionMatches)
                    Assert-Acceptance ($matches.Count -eq 1 -and $matches[0].CompletionText -like '*憑證 file.pem*') '合法空白／Unicode 檔名補全遺失'
                }
            }
        }
    } finally { Pop-Location }
}

function Invoke-WindowsAcceptance {
    if (-not $IsWindows -or $PSVersionTable.PSVersion.Major -lt 7) { throw '需要 Windows 與 PowerShell 7' }
    $binary = (Resolve-Path -LiteralPath $BinaryPath -ErrorAction Stop).Path
    if ([string]::IsNullOrWhiteSpace($env:APPDATA)) { throw '無法辨識日常設定位置' }
    if (-not $OutputDirectory) { $OutputDirectory = Join-Path ([IO.Path]::GetTempPath()) ('tlscheck-auto-' + [guid]::NewGuid().ToString('N')) }
    $root = [IO.Path]::GetFullPath($OutputDirectory)
    if (Test-Path -LiteralPath $root) { throw '結果目錄已存在，請換新目錄以保留證據' }
    $daily = Join-Path $env:APPDATA 'tlscheck\config.json'
    $dailyBefore = Get-AcceptanceFileState $daily
    $null = New-Item -ItemType Directory -Path $root
    $env:APPDATA = Join-Path $root 'AppData'
    $configPath = Join-Path $env:APPDATA 'tlscheck\config.json'
    $null = New-Item -ItemType Directory -Path (Split-Path -Parent $configPath)
    # 故意損壞的合成設定用來偵測補全是否誤讀設定；不儲存使用者原始內容。
    [IO.File]::WriteAllText($configPath, '{"language":bad', [Text.UTF8Encoding]::new($false))
    $configBefore = Get-AcceptanceFileState $configPath
    $env:BASH_COMP_DEBUG_FILE = Join-Path $root 'debug-sentinel'
    [IO.File]::WriteAllText($env:BASH_COMP_DEBUG_FILE, 'unchanged', [Text.UTF8Encoding]::new($false))
    $debugBefore = (Get-FileHash -LiteralPath $env:BASH_COMP_DEBUG_FILE).Hash
    $aborted = $null
    try { Invoke-AcceptanceSuite $binary $root } catch { $aborted = $_.Exception.Message }
    if ($null -eq $script:AcceptanceResults) { $script:AcceptanceResults = [Collections.Generic.List[object]]::new() }
    if ($aborted) { Invoke-AcceptanceCase '測試流程完整執行' { throw $aborted } }
    Invoke-AcceptanceCase '隔離設定未改寫' {
        $script:AcceptanceConfigAfter = Get-AcceptanceFileState $configPath
        Assert-Acceptance ($script:AcceptanceConfigAfter -ceq $configBefore) '隔離設定改變'
    }
    Invoke-AcceptanceCase '日常設定未改寫' {
        $script:AcceptanceDailyAfter = Get-AcceptanceFileState $daily
        Assert-Acceptance ($script:AcceptanceDailyAfter -ceq $dailyBefore) '日常設定改變，請停止驗收'
    }
    Invoke-AcceptanceCase '補全 debug 未改寫' {
        $script:AcceptanceDebugAfter = (Get-FileHash -LiteralPath $env:BASH_COMP_DEBUG_FILE).Hash
        Assert-Acceptance ($script:AcceptanceDebugAfter -eq $debugBefore) 'debug sentinel 改變'
    }
    $failed = @($script:AcceptanceResults | Where-Object Status -eq 'FAIL').Count
    $report = [ordered]@{
        Platform='Windows 原生自動化，非鍵盤或選單實機驗收'
        PowerShell=$PSVersionTable.PSVersion.ToString(); OS=[Environment]::OSVersion.VersionString
        Architecture=[Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
        BinaryVersion=$script:AcceptanceVersion
        BinarySHA256=(Get-FileHash -LiteralPath $binary).Hash
        ScriptSHA256=(Get-FileHash -LiteralPath $PSCommandPath).Hash
        Isolation=[ordered]@{
            ConfigBefore=$configBefore; ConfigAfter=$script:AcceptanceConfigAfter
            DailyBefore=$dailyBefore; DailyAfter=$script:AcceptanceDailyAfter
            DebugBefore=$debugBefore; DebugAfter=$script:AcceptanceDebugAfter
        }
        Total=$script:AcceptanceResults.Count; Passed=($script:AcceptanceResults.Count - $failed)
        Failed=$failed; Results=@($script:AcceptanceResults.ToArray())
        Probes=@($script:AcceptanceProbes.ToArray())
    }
    $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $root 'results.json') -Encoding utf8NoBOM
    Write-Host "結果：$root；通過=$($script:AcceptanceResults.Count - $failed)，失敗=$failed"
    if ($failed) { return 1 }; return 0
}

if ($MyInvocation.InvocationName -ne '.') {
    $ErrorActionPreference = 'Stop'
    try {
        if (-not $Worker) {
            # 總是在新的無 profile 子程序內改環境及註冊 completer。
            $arguments = @('-NoProfile','-NonInteractive','-File',$PSCommandPath,'-Worker','-BinaryPath',$BinaryPath)
            if ($OutputDirectory) { $arguments += @('-OutputDirectory',$OutputDirectory) }
            & (Get-Process -Id $PID).Path @arguments
            exit $LASTEXITCODE
        }
        exit (Invoke-WindowsAcceptance)
    } catch {
        [Console]::Error.WriteLine('驗收工具失敗：' + $_.Exception.Message)
        exit 2
    }
}
