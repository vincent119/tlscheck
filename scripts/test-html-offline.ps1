param(
    [string]$ReportDirectory = $PSScriptRoot,
    [string]$OutputDirectory,
    [string]$BrowserPath,
    [switch]$StaticOnly,
    [switch]$Worker
)

function Assert-HTML([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}
function Read-HTMLTestText([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    Assert-HTML (-not $item.PSIsContainer -and $item.Length -le 2MB -and
        -not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) '檔案類型或大小不允許'
    $bytes = [IO.File]::ReadAllBytes($item.FullName)
    Assert-HTML (-not ($bytes.Length -ge 3 -and $bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191)) '不接受 UTF-8 BOM'
    return [Text.UTF8Encoding]::new($false,$true).GetString($bytes)
}
function Add-HTMLCheck([string]$Name, [scriptblock]$Check) {
    try {
        & $Check | Out-Null
        $script:HTMLChecks.Add([pscustomobject]@{ Name=$Name; Status='PASS'; Detail='' })
        Write-Host "PASS $Name"
    } catch {
        $script:HTMLChecks.Add([pscustomobject]@{ Name=$Name; Status='FAIL'; Detail=$_.Exception.Message })
        Write-Host "FAIL ${Name}：$($_.Exception.Message)"
    }
}
function Get-HTMLFacts([string]$Text) {
    $tables = [Collections.Generic.List[object]]::new()
    foreach ($table in [regex]::Matches($Text,'(?is)<table\b[^>]*>(.*?)</table>')) {
        $rows = [Collections.Generic.List[object]]::new()
        foreach ($row in [regex]::Matches($table.Groups[1].Value,'(?is)<tr\b[^>]*>(.*?)</tr>')) {
            $cells = @([regex]::Matches($row.Groups[1].Value,'(?is)<td\b[^>]*>(.*?)</td>') | ForEach-Object {
                [Net.WebUtility]::HtmlDecode([regex]::Replace($_.Groups[1].Value,'<[^>]+>','')).Trim()
            })
            if ($cells.Count) { $rows.Add($cells) }
        }
        $tables.Add($rows.ToArray())
    }
    return [pscustomobject]@{ Tables=$tables.ToArray(); Text=[Net.WebUtility]::HtmlDecode([regex]::Replace($Text,'<[^>]+>',' ')) }
}
function Test-HTMLManifest([string]$Directory) {
    $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $lines = @((Read-HTMLTestText (Join-Path $Directory 'SHA256SUMS.txt')) -split '\r?\n' | Where-Object { $_ -ne '' })
    Assert-HTML ($lines.Count -ge 5 -and $lines.Count -le 100) 'manifest 筆數不符'
    foreach ($line in $lines) {
        $match = [regex]::Match($line,'^([a-fA-F0-9]{64})  (.+)$')
        Assert-HTML $match.Success 'manifest 格式不符'
        $name = $match.Groups[2].Value
        Assert-HTML ($name -notmatch '[\\/:]' -and $name -notmatch '\.\.' -and $names.Add($name)) 'manifest 越界或重複名稱'
        $path = Join-Path $Directory $name
        $null = Read-HTMLTestText $path
        Assert-HTML ((Get-FileHash -LiteralPath $path).Hash -eq $match.Groups[1].Value) "檔案雜湊不符：$name"
    }
    foreach ($name in @('en.html','zh-TW.html','zh-CN.html','expected-public.json','report-metadata.json')) {
        Assert-HTML ($names.Contains($name)) 'manifest 缺少必要檔案'
    }
}
function Test-HTMLStatic([string]$Directory, $Expected, $Metadata) {
    Assert-HTML ($Metadata.reports.Count -eq 3) 'metadata 必須包含三語'
    $labels = @{
        en=@('passed','failed','not performed','warnings','highest severity','check exit code')
        'zh-TW'=@('通過','失敗','未執行','提醒','最高嚴重度','檢查結束碼')
        'zh-CN'=@('通过','失败','未执行','提醒','最高严重程度','检查退出码')
    }
    foreach ($lang in @('en','zh-TW','zh-CN')) {
        $path = Join-Path $Directory ($lang+'.html')
        $text = $null; $facts = $null
        $script:HTMLCurrentText = $null
        Add-HTMLCheck "$lang 原始檔與 metadata" {
            $script:HTMLCurrentText = Read-HTMLTestText $path
            $entries = @($Metadata.reports | Where-Object { $_.file -ceq ($lang+'.html') -and $_.language -ceq $lang })
            Assert-HTML ($entries.Count -eq 1) 'metadata 語系或檔名不符'
            Assert-HTML ((Get-Item -LiteralPath $path).Length -eq $entries[0].bytes -and
                (Get-FileHash -LiteralPath $path).Hash -eq $entries[0].sha256) 'metadata 大小或雜湊不符'
        }
        $text = $script:HTMLCurrentText
        if ($null -eq $text) { throw 'HTML 無法讀取，停止流程' }
        $facts = Get-HTMLFacts $text
        Add-HTMLCheck "$lang 文件與語系" {
            Assert-HTML ($text -match '(?is)^\s*<!DOCTYPE html>\s*<html\s+lang="' + [regex]::Escape($lang) + '"') 'DOCTYPE／lang 不符'
            Assert-HTML ($text -match '(?i)<meta\s+charset="utf-8"' -and $text -match '<title>tlscheck</title>' -and $facts.Tables.Count -ge 3) 'charset／標題／表格不符'
        }
        Add-HTMLCheck "$lang 無主動內容或外部資源引用" {
            # 此處是固定報告格式的保守檢查，不宣稱為通用 HTML sanitizer。
            $allowed = @('html','head','meta','title','style','body','h1','p','table','caption','thead','tbody','tr','th','td')
            foreach ($tag in [regex]::Matches($text,'(?i)<\s*([a-z][a-z0-9:-]*)\b[^>]*>')) {
                Assert-HTML ($tag.Groups[1].Value.ToLowerInvariant() -in $allowed) '不允許的 HTML 元素'
                Assert-HTML ($tag.Value -notmatch '(?i)\s(?:src|srcset|href|action|formaction|background|poster|data|http-equiv|style|on[\w-]+)\s*=') '不允許的資源或事件屬性'
            }
            foreach ($style in [regex]::Matches($text,'(?is)<style\b[^>]*>(.*?)</style>')) {
                Assert-HTML ($style.Groups[1].Value -notmatch '(?i)url\s*\(|@|\\|expression\s*\(') '不允許的 CSS 外部引用或動態內容'
            }
            Assert-HTML ($text -notmatch '(?i)<!DOCTYPE[^>]*(?:SYSTEM|PUBLIC)' -and $text -notmatch '<\?') '不允許的外部宣告'
        }
        Add-HTMLCheck "$lang 無敏感 canary 或私鑰" {
            foreach ($value in @('S10_SECRET','S10_QUERY','S10_FRAGMENT','BEGIN PRIVATE KEY')) {
                Assert-HTML (-not $facts.Text.Contains($value)) '敏感 canary 或私鑰標頭外洩'
            }
        }
        Add-HTMLCheck "$lang 公開長值完整" {
            foreach ($value in @($Expected.certificate.id,$Expected.certificate.subject,$Expected.spiffe) + @($Expected.certificate.dns_names)) {
                Assert-HTML (-not [string]::IsNullOrWhiteSpace($value) -and $facts.Text.Contains($value)) '公開欄位遺失或截斷'
            }
        }
        Add-HTMLCheck "$lang 本地化摘要" {
            $severity = @{en='Execution error'; 'zh-TW'='執行錯誤'; 'zh-CN'='执行错误'}[$lang]
            $values = @($Expected.summary.passed,$Expected.summary.failed,$Expected.summary.not_performed,$Expected.summary.warnings,$severity,$Expected.summary.check_exit_code)
            $rows = $facts.Tables[2]
            Assert-HTML ($rows.Count -eq 6) '摘要列數不符'
            for ($i=0;$i -lt 6;$i++) {
                Assert-HTML ($rows[$i].Count -eq 2 -and $rows[$i][0] -ceq $labels[$lang][$i] -and $rows[$i][1] -ceq [string]$values[$i]) '摘要標籤或數值不符'
            }
        }
        Add-HTMLCheck "$lang 輸入與配對筆數" {
            Assert-HTML ($facts.Tables[0].Count -eq $Expected.input_count -and
                $facts.Tables[1].Count -eq $Expected.key_information_count) '輸入或配對列數不符'
        }
    }
}

function Read-HTMLCDPMessage($Socket, $Token) {
    $stream = [IO.MemoryStream]::new()
    try {
        do {
            $buffer = [byte[]]::new(65536)
            $part = $Socket.ReceiveAsync([ArraySegment[byte]]::new($buffer),$Token).GetAwaiter().GetResult()
            Assert-HTML ($part.MessageType -eq [Net.WebSockets.WebSocketMessageType]::Text) '瀏覽器協定非文字或已關閉'
            $stream.Write($buffer,0,$part.Count)
            Assert-HTML ($stream.Length -le 16MB) '瀏覽器訊息超過上限'
        } until ($part.EndOfMessage)
        return ([Text.UTF8Encoding]::new($false,$true).GetString($stream.ToArray()) | ConvertFrom-Json -AsHashtable)
    } finally { $stream.Dispose() }
}
function Invoke-HTMLCDP([string]$Method, [hashtable]$Parameters = @{}) {
    $script:HTMLCDPId++
    $id = $script:HTMLCDPId
    $bytes = [Text.Encoding]::UTF8.GetBytes((@{id=$id;method=$Method;params=$Parameters}|ConvertTo-Json -Depth 20 -Compress))
    $cts = [Threading.CancellationTokenSource]::new(15000)
    try {
        # 新版 .NET 的非泛型 Task 可能向 PowerShell 輸出 VoidTaskResult。
        $null=$script:HTMLSocket.SendAsync([ArraySegment[byte]]::new($bytes),[Net.WebSockets.WebSocketMessageType]::Text,$true,$cts.Token).GetAwaiter().GetResult()
        while ($true) {
            $message = Read-HTMLCDPMessage $script:HTMLSocket $cts.Token
            Assert-HTML ($message -is [Collections.IDictionary]) '瀏覽器協定訊息不是物件'
            if ($message.ContainsKey('id')) {
                Assert-HTML ($message.id -eq $id) '瀏覽器協定回覆順序不符'
                Assert-HTML (-not $message.ContainsKey('error')) ('瀏覽器指令失敗：'+$Method+'；'+[string]$message.error.message)
                Assert-HTML ($message.result -is [Collections.IDictionary]) '瀏覽器協定結果不是物件'
                return $message.result
            }
            Assert-HTML ($script:HTMLEvents.Count -lt 10000) '瀏覽器事件超過上限'
            $script:HTMLEvents.Add($message)
        }
    } finally { $cts.Dispose() }
}
function Get-HTMLReadyState {
    try {
        $r=Invoke-HTMLCDP 'Runtime.evaluate' @{expression='({ready:document.readyState,url:location.href})';returnByValue=$true}
        return $r.result.value
    } catch {
        # 導覽切換 context 是短暫狀態；其餘協定錯誤不能轉成成功。
        if ($_.Exception.Message -match 'Execution context was destroyed|Cannot find context|Inspected target navigated') {
            return @{ready='loading';url=''}
        }
        throw
    }
}
function Find-HTMLBrowser {
    if ($BrowserPath) { return (Resolve-Path -LiteralPath $BrowserPath -ErrorAction Stop).Path }
    foreach ($base in @(${env:ProgramFiles(x86)},$env:ProgramFiles,$env:LOCALAPPDATA)) {
        if (-not $base) { continue }
        foreach ($relative in @('Microsoft\Edge\Application\msedge.exe','Google\Chrome\Application\chrome.exe')) {
            $path = Join-Path $base $relative
            if (Test-Path -LiteralPath $path -PathType Leaf) { return $path }
        }
    }
    throw '找不到 Edge／Chrome；可指定 -BrowserPath，或用 -StaticOnly 明確限定靜態驗收'
}
function Save-HTMLScreenshot([string]$Path) {
    $metrics = Invoke-HTMLCDP 'Page.getLayoutMetrics'
    $size = if ($metrics.ContainsKey('cssContentSize')) { $metrics.cssContentSize } else { $metrics.contentSize }
    $height = [Math]::Min(16000,[Math]::Ceiling($size.height))
    $shot = Invoke-HTMLCDP 'Page.captureScreenshot' @{format='png';captureBeyondViewport=$true;clip=@{x=0;y=0;width=$size.width;height=$height;scale=1}}
    [IO.File]::WriteAllBytes($Path,[Convert]::FromBase64String($shot.data))
    return @{File=[IO.Path]::GetFileName($Path); FullHeight=$size.height; CapturedHeight=$height; Truncated=($height -lt $size.height)}
}
function Get-HTMLPortClosure([int]$Port, [int]$TimeoutMilliseconds = 5000) {
    $clock=[Diagnostics.Stopwatch]::StartNew()
    $observations=[Collections.Generic.List[object]]::new()
    $closed=$false
    do {
        $tcp=[Net.Sockets.TcpClient]::new()
        try {
            $connect=$tcp.ConnectAsync('127.0.0.1',$Port)
            # 使用剩餘總預算，避免 Windows 尚未回報拒絕連線就被反覆取消。
            $remaining=[Math]::Max(1,$TimeoutMilliseconds-[int]$clock.ElapsedMilliseconds)
            if ($connect.Wait($remaining)) {
                $null=$connect.GetAwaiter().GetResult()
                $observations.Add(@{Status='仍可連線'})
            } else { $observations.Add(@{Status='連線等待逾時，不能證明已關閉'}) }
        } catch {
            $baseError=$_.Exception.GetBaseException()
            $closed=$baseError -is [Net.Sockets.SocketException] -and $baseError.SocketErrorCode -eq [Net.Sockets.SocketError]::ConnectionRefused
            $observations.Add(@{Status=$(if($closed){'已拒絕連線'}else{'連線檢查錯誤'});ErrorType=$baseError.GetType().FullName;Error=$baseError.Message})
        } finally { $tcp.Dispose() }
        if (-not $closed -and $clock.ElapsedMilliseconds -lt $TimeoutMilliseconds) { Start-Sleep -Milliseconds 100 }
    } while (-not $closed -and $clock.ElapsedMilliseconds -lt $TimeoutMilliseconds)
    return [pscustomobject]@{Closed=$closed;ElapsedMilliseconds=$clock.ElapsedMilliseconds;Observations=@($observations.ToArray())}
}
function Test-HTMLBrowser([string]$Directory, [string]$Root, $Expected) {
    Assert-HTML $IsWindows '完整瀏覽器模式需要 Windows；本機可使用 -StaticOnly'
    $browser = Find-HTMLBrowser
    $profile = Join-Path $Root 'browser-profile'
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName=$browser; $info.UseShellExecute=$false
    foreach ($argument in @('--headless=new',('--user-data-dir='+$profile),'--remote-debugging-port=0','--remote-debugging-address=127.0.0.1',
        '--no-first-run','--no-default-browser-check','--disable-extensions','--disable-background-networking','--disable-sync','--disable-component-update','about:blank')) {
        $info.ArgumentList.Add($argument)
    }
    $process = [Diagnostics.Process]::new();$process.StartInfo=$info
    $handler = [Net.Http.HttpClientHandler]::new();$handler.UseProxy=$false
    $http = [Net.Http.HttpClient]::new($handler);$http.Timeout=[TimeSpan]::FromSeconds(3)
    $port=$null; $script:HTMLSocket=$null
    try {
        $null=$process.Start()
        $portFile=Join-Path $profile 'DevToolsActivePort'
        $clock=[Diagnostics.Stopwatch]::StartNew()
        while (-not (Test-Path -LiteralPath $portFile)) {
            if ($clock.Elapsed.TotalSeconds -gt 20) { throw '瀏覽器啟動逾時，未取得本次暫存 profile 的 DevTools' }
            Start-Sleep -Milliseconds 100
        }
        $portLines=[IO.File]::ReadAllLines($portFile)
        [int]$port=$portLines[0]
        Assert-HTML ($port -ge 1 -and $port -le 65535) '本機 DevTools port 不合法'
        $version=$http.GetStringAsync("http://127.0.0.1:$port/json/version").GetAwaiter().GetResult()|ConvertFrom-Json
        $script:HTMLBrowserVersion=$version.Browser
        $pages=@($http.GetStringAsync("http://127.0.0.1:$port/json/list").GetAwaiter().GetResult()|ConvertFrom-Json)
        $page=@($pages | Where-Object type -eq 'page')[0]
        $endpoint=[uri]$page.webSocketDebuggerUrl
        Assert-HTML ($endpoint.Scheme -eq 'ws' -and $endpoint.Host -in @('127.0.0.1','localhost') -and $endpoint.Port -eq $port) '拒絕非本次本機 DevTools 端點'
        $script:HTMLSocket=[Net.WebSockets.ClientWebSocket]::new()
        $cts=[Threading.CancellationTokenSource]::new(10000)
        try { $null=$script:HTMLSocket.ConnectAsync($endpoint,$cts.Token).GetAwaiter().GetResult() } finally { $cts.Dispose() }
        $script:HTMLCDPId=0
        $script:HTMLEvents=[Collections.Generic.List[object]]::new()
        $null=Invoke-HTMLCDP 'Page.enable'
        $null=Invoke-HTMLCDP 'Runtime.enable'
        $null=Invoke-HTMLCDP 'Log.enable'
        $null=Invoke-HTMLCDP 'Network.enable'
        $null=Invoke-HTMLCDP 'Network.setCacheDisabled' @{cacheDisabled=$true}
        # Offline 在導覽前設定；不使用禁止 sandbox／web security 的參數。
        $null=Invoke-HTMLCDP 'Network.emulateNetworkConditions' @{offline=$true;latency=0;downloadThroughput=0;uploadThroughput=0}
        @{Browser=$script:HTMLBrowserVersion;OfflineBeforeNavigation=$true;CacheDisabled=$true;FreshProfile=$true;RemoteDebugging='127.0.0.1，動態port';ObservationDelayMilliseconds=500} |
            ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Root 'browser-settings.json') -Encoding utf8NoBOM
        foreach ($lang in @('en','zh-TW','zh-CN')) {
            $script:HTMLEvents.Clear()
            $uri=([uri](Join-Path $Directory ($lang+'.html'))).AbsoluteUri
            Assert-HTML ($uri.StartsWith('file:')) '只能導覽本機報告'
            $null=Invoke-HTMLCDP 'Emulation.setDeviceMetricsOverride' @{width=1280;height=900;deviceScaleFactor=1;mobile=$false}
            $navigation=Invoke-HTMLCDP 'Page.navigate' @{url=$uri}
            Assert-HTML (-not $navigation.ContainsKey('errorText')) '本機報告導覽失敗'
            $clock.Restart()
            do {
                $ready=Get-HTMLReadyState
                if ($ready.ready -eq 'complete' -and $ready.url -eq $uri) { break }
                if ($clock.Elapsed.TotalSeconds -gt 15) { throw '離線報告載入逾時' }
                Start-Sleep -Milliseconds 100
            } while ($true)
            $loadsBefore=@($script:HTMLEvents|Where-Object method -eq 'Page.loadEventFired').Count
            $null=Invoke-HTMLCDP 'Page.reload' @{ignoreCache=$true}
            $clock.Restart()
            do {
                $ready=Get-HTMLReadyState
                $loadsNow=@($script:HTMLEvents|Where-Object method -eq 'Page.loadEventFired').Count
                if ($ready.ready -eq 'complete' -and $ready.url -eq $uri -and $loadsNow -gt $loadsBefore) { break }
                if ($clock.Elapsed.TotalSeconds -gt 15) { throw '離線重新載入逾時或沒有完成事件' }
                Start-Sleep -Milliseconds 100
            } while ($true)
            Start-Sleep -Milliseconds 500
            $expression=@'
(() => ({ lang: document.documentElement.lang, title: document.title, url: location.href,
 text: document.body.textContent,
 tables: Array.from(document.querySelectorAll('table')).map(t=>Array.from(t.querySelectorAll('tbody tr')).map(r=>Array.from(r.querySelectorAll('td')).map(c=>c.textContent.trim()))),
 active: Array.from(document.querySelectorAll('script,iframe,object,embed,img,link,form,base')).map(n=>n.tagName),
 attributes: Array.from(document.querySelectorAll('*')).flatMap(n=>Array.from(n.attributes).filter(a=>/^(on|src$|srcset$|href$|action$|formaction$)/i.test(a.name)).map(a=>({tag:n.tagName,name:a.name,value:a.value}))) }))()
'@
            $evaluation=Invoke-HTMLCDP 'Runtime.evaluate' @{expression=$expression;returnByValue=$true}
            Assert-HTML (-not $evaluation.ContainsKey('exceptionDetails')) '瀏覽器 DOM 收證失敗'
            $dom=$evaluation.result.value
            $dom|ConvertTo-Json -Depth 20|Set-Content -LiteralPath (Join-Path $Root ($lang+'-dom.json')) -Encoding utf8NoBOM
            Add-HTMLCheck "$lang 瀏覽器本機 DOM 與語系" { Assert-HTML ($dom.url -eq $uri -and $dom.lang -ceq $lang -and $dom.title -ceq 'tlscheck') '實際 DOM 語系／網址／標題不符' }
            Add-HTMLCheck "$lang 瀏覽器無主動元素或事件" { Assert-HTML ($dom.active.Count -eq 0 -and $dom.attributes.Count -eq 0) 'DOM 出現主動元素或事件／資源屬性' }
            Add-HTMLCheck "$lang 瀏覽器公開長值與敏感值" {
                foreach ($value in @($Expected.certificate.id,$Expected.certificate.subject,$Expected.spiffe)+@($Expected.certificate.dns_names)) {
                    Assert-HTML ($dom.text.Contains($value)) 'DOM 公開資料遺失'
                }
                foreach ($secret in @('S10_SECRET','S10_QUERY','S10_FRAGMENT','BEGIN PRIVATE KEY')) { Assert-HTML (-not $dom.text.Contains($secret)) 'DOM 敏感 canary 外洩' }
            }
            Add-HTMLCheck "$lang 瀏覽器摘要與筆數" {
                $values=@($Expected.summary.passed,$Expected.summary.failed,$Expected.summary.not_performed,$Expected.summary.warnings)
                Assert-HTML ($dom.tables.Count -ge 3 -and $dom.tables[2].Count -eq 6) 'DOM 摘要結構不符'
                for ($i=0;$i -lt 4;$i++) { Assert-HTML ($dom.tables[2][$i][1] -ceq [string]$values[$i]) 'DOM 摘要不符' }
                Assert-HTML ($dom.tables[2][5][1] -ceq [string]$Expected.summary.check_exit_code -and $dom.tables[0].Count -eq $Expected.input_count) 'DOM 結束碼或來源筆數不符'
            }
            $shots=[Collections.Generic.List[object]]::new()
            $shots.Add((Save-HTMLScreenshot (Join-Path $Root ($lang+'-1280.png'))))
            $null=Invoke-HTMLCDP 'Emulation.setDeviceMetricsOverride' @{width=800;height=900;deviceScaleFactor=1;mobile=$false}
            $shots.Add((Save-HTMLScreenshot (Join-Path $Root ($lang+'-800.png'))))
            $shots.ToArray()|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $Root ($lang+'-screenshots.json')) -Encoding utf8NoBOM
            # 最後一個指令回覆前的事件也一併收集；只觀察這個測試頁的有界時段。
            $null=Invoke-HTMLCDP 'Runtime.evaluate' @{expression='document.readyState';returnByValue=$true}
            $script:HTMLEvents.ToArray()|ConvertTo-Json -Depth 30|Set-Content -LiteralPath (Join-Path $Root ($lang+'-events.json')) -Encoding utf8NoBOM
            Add-HTMLCheck "$lang 離線導覽與重新載入事件" {
                Assert-HTML (@($script:HTMLEvents|Where-Object method -eq 'Page.loadEventFired').Count -ge 2) '缺少初始導覽或重新載入完成事件'
            }
            Add-HTMLCheck "$lang 離線觀測無外部請求" {
                $requests=@($script:HTMLEvents | Where-Object {
                    ($_.method -eq 'Network.requestWillBeSent' -and $_.params.request.url -notmatch '^file:') -or
                    $_.method -in @('Network.webSocketCreated','Network.webTransportCreated')
                })
                Assert-HTML ($requests.Count -eq 0) '測試頁嘗試外部請求，包含被 Offline 阻擋者'
            }
            Add-HTMLCheck "$lang 瀏覽器 Console／例外／對話框" {
                $errors=@($script:HTMLEvents|Where-Object {
                    $_.method -in @('Runtime.exceptionThrown','Page.javascriptDialogOpening','Network.loadingFailed') -or
                    ($_.method -eq 'Runtime.consoleAPICalled' -and $_.params.type -eq 'error') -or
                    ($_.method -eq 'Log.entryAdded' -and $_.params.entry.level -eq 'error')
                })
                Assert-HTML ($errors.Count -eq 0) '瀏覽器發生錯誤或對話框，詳 events.json'
            }
        }
        $script:HTMLBrowserStatus='PASS（僅本次自動觀測，版面待人工）'
    } finally {
        $cleanup=[Collections.Generic.List[string]]::new()
        if ($null -ne $script:HTMLSocket) {
            try { $null=Invoke-HTMLCDP 'Browser.close' } catch { $cleanup.Add('關閉協定回覆：'+$_.Exception.Message) }
            $script:HTMLSocket.Dispose()
        }
        $processStopped=$false
        try {
            if (-not $process.HasExited) { $process.Kill($true);$processStopped=$process.WaitForExit(5000) }
            else { $processStopped=$true }
        } catch {
            $cleanup.Add('終止本次程序：'+$_.Exception.Message)
            # Kill 與自然退出可能同時發生，依實際退出狀態判定，仍需確認 port。
            try { $processStopped=$process.HasExited } catch { $cleanup.Add('無法確認程序退出：'+$_.Exception.Message) }
        }
        $closure=$null
        if ($port) {
            $closure=Get-HTMLPortClosure $port
        }
        $stopped=$processStopped -and ($null -eq $port -or $closure.Closed)
        if (-not $stopped) { $cleanup.Add('程序或 127.0.0.1 DevTools 尚未確認結束，詳 PortCheck') }
        @{Stopped=$stopped;OwnedProcessStopped=$processStopped;Port=$port;PortCheck=$closure;Notes=@($cleanup.ToArray())}|
            ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $Root 'browser-cleanup.json') -Encoding utf8NoBOM
        Add-HTMLCheck '本次瀏覽器與 DevTools 清理' { Assert-HTML $stopped '本次程序或 DevTools 尚未確認結束，請保存清理紀錄' }
        $process.Dispose();$http.Dispose();$handler.Dispose()
    }
}

function Invoke-HTMLAcceptance {
    Assert-HTML ($PSVersionTable.PSVersion.Major -ge 7) '需要 PowerShell 7'
    $directory=(Resolve-Path -LiteralPath $ReportDirectory -ErrorAction Stop).Path
    if (-not $OutputDirectory) { $OutputDirectory=Join-Path ([IO.Path]::GetTempPath()) ('tlscheck-html-auto-'+[guid]::NewGuid().ToString('N')) }
    $root=[IO.Path]::GetFullPath($OutputDirectory)
    Assert-HTML (-not (Test-Path -LiteralPath $root)) '結果目錄已存在，請換新目錄'
    $null=New-Item -ItemType Directory -Path $root
    $script:HTMLChecks=[Collections.Generic.List[object]]::new()
    $script:HTMLBrowserStatus='未執行';$script:HTMLBrowserVersion=$null
    Add-HTMLCheck '交付 manifest 完整性' { Test-HTMLManifest $directory }
    if (@($script:HTMLChecks|Where-Object Status -eq 'FAIL').Count -eq 0) {
        Add-HTMLCheck '三語靜態驗收流程完整' {
            $expected=Read-HTMLTestText (Join-Path $directory 'expected-public.json')|ConvertFrom-Json
            $metadata=Read-HTMLTestText (Join-Path $directory 'report-metadata.json')|ConvertFrom-Json
            $script:HTMLExpected=$expected
            Test-HTMLStatic $directory $expected $metadata
        }
    }
    if (-not $StaticOnly -and @($script:HTMLChecks|Where-Object Status -eq 'FAIL').Count -eq 0) {
        Add-HTMLCheck 'Windows 瀏覽器自動流程完整' { Test-HTMLBrowser $directory $root $script:HTMLExpected }
    }
    Add-HTMLCheck '驗收後來源檔案未改寫' { Test-HTMLManifest $directory }
    $failed=@($script:HTMLChecks|Where-Object Status -eq 'FAIL').Count
    if ($failed -and -not $StaticOnly) { $script:HTMLBrowserStatus='未完成，請檢查失敗紀錄' }
    $result=[ordered]@{
        Mode=$(if($StaticOnly){'StaticOnly'}else{'WindowsBrowser'})
        PowerShell=$PSVersionTable.PSVersion.ToString(); OS=[Environment]::OSVersion.VersionString
        Browser=$script:HTMLBrowserVersion; BrowserStatus=$script:HTMLBrowserStatus
        ScriptSHA256=(Get-FileHash -LiteralPath $PSCommandPath).Hash
        Total=$script:HTMLChecks.Count; Passed=($script:HTMLChecks.Count-$failed);Failed=$failed
        Results=@($script:HTMLChecks.ToArray())
        ManualPending=@('三語自然語意與字型／CJK可讀性','100%／200%與長欄位版面','檢查自動截圖是否截斷；必要時實際互動瀏覽')
        ObservationScope='靜態固定fixture；瀏覽器模式僅本次頁面載入／截圖時段，不保證整台機器離線或無背景流量'
    }
    $result|ConvertTo-Json -Depth 20|Set-Content -LiteralPath (Join-Path $root 'results.json') -Encoding utf8NoBOM
    Write-Host "結果：$root；通過=$($result.Passed)，失敗=$failed；瀏覽器=$script:HTMLBrowserStatus"
    if ($failed) { return 1 };return 0
}
if ($MyInvocation.InvocationName -ne '.') {
    $ErrorActionPreference='Stop'
    try {
        if (-not $Worker) {
            $arguments=@('-NoProfile','-NonInteractive','-File',$PSCommandPath,'-Worker','-ReportDirectory',$ReportDirectory)
            if ($OutputDirectory) { $arguments+=@('-OutputDirectory',$OutputDirectory) }
            if ($BrowserPath) { $arguments+=@('-BrowserPath',$BrowserPath) }
            if ($StaticOnly) { $arguments+='-StaticOnly' }
            & (Get-Process -Id $PID).Path @arguments
            exit $LASTEXITCODE
        }
        exit (Invoke-HTMLAcceptance)
    } catch { [Console]::Error.WriteLine('HTML 驗收工具失敗：'+$_.Exception.Message);exit 2 }
}
