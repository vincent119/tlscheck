"""用合成 HTML 驗證免 Go 腳本的拒絕與結束碼，不啟動瀏覽器。"""
from pathlib import Path
import hashlib
import html
import json
import shutil
import subprocess
import tempfile
import unittest


class HTMLAcceptanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pwsh = shutil.which('pwsh')
        if not cls.pwsh:
            raise unittest.SkipTest('缺少 PowerShell，無法驗證 HTML 工具')
        cls.script = Path('scripts/test-html-offline.ps1').resolve()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / '合成 報告'
        self.source.mkdir()
        expected = {'summary': {'passed': 8, 'failed': 2, 'not_performed': 4, 'warnings': 0,
                                'highest_severity': 'execution', 'check_exit_code': 2},
                    'input_count': 3, 'certificate_count': 1, 'key_information_count': 1,
                    'certificate': {'id': 'A' * 64, 'fingerprint_sha256': 'A' * 64,
                                    'subject': "S10_PUBLIC <script>alert('S10_XSS')</script> 長欄位憑證",
                                    'issuer': '合成 CA', 'dns_names': ['long-example.test']},
                    'spiffe': 'spiffe://cluster.local/ns/s10/service'}
        self.expected = expected
        (self.source / 'expected-public.json').write_text(json.dumps(expected, ensure_ascii=False), encoding='utf-8')
        labels = {'en': ['passed', 'failed', 'not performed', 'warnings', 'highest severity', 'check exit code'],
                  'zh-TW': ['通過', '失敗', '未執行', '提醒', '最高嚴重度', '檢查結束碼'],
                  'zh-CN': ['通过', '失败', '未执行', '提醒', '最高严重程度', '检查退出码']}
        for lang in labels:
            values = [8, 2, 4, 0, {'en': 'Execution error', 'zh-TW': '執行錯誤', 'zh-CN': '执行错误'}[lang], 2]
            table = lambda rows: '<table><caption>合成</caption><tbody>' + ''.join(
                '<tr>' + ''.join('<td>' + html.escape(str(v)) + '</td>' for v in row) + '</tr>' for row in rows) + '</tbody></table>'
            text = '<!DOCTYPE html><html lang="' + lang + '"><head><meta charset="utf-8"><title>tlscheck</title></head><body><h1>tlscheck</h1>'
            text += table([[0], [1], [2]]) + table([['key:0', 'A' * 64]]) + table(zip(labels[lang], values))
            text += '<p>' + html.escape(expected['certificate']['subject']) + ' ' + 'A' * 64 + ' long-example.test ' + expected['spiffe'] + '</p></body></html>'
            (self.source / (lang + '.html')).write_text(text, encoding='utf-8')
        self.refresh_manifest()

    def refresh_manifest(self):
        reports = []
        for lang in ['en', 'zh-TW', 'zh-CN']:
            path = self.source / (lang + '.html')
            reports.append({'file': path.name, 'language': lang, 'bytes': path.stat().st_size,
                            'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
        (self.source / 'report-metadata.json').write_text(json.dumps({'reports': reports}), encoding='utf-8')
        (self.source / 'SHA256SUMS.txt').write_text(''.join(
            hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + p.name + '\n'
            for p in sorted(self.source.iterdir()) if p.name != 'SHA256SUMS.txt'), encoding='utf-8')

    def run_static(self, name='results'):
        output = self.root / name
        result = subprocess.run([self.pwsh, '-NoProfile', '-NonInteractive', '-File', str(self.script),
                                 '-ReportDirectory', str(self.source), '-OutputDirectory', str(output), '-StaticOnly'],
                                capture_output=True, timeout=30)
        path = output / 'results.json'
        report = json.loads(path.read_text(encoding='utf-8')) if path.exists() else None
        return result, report

    def test_valid_static_report_does_not_claim_browser_acceptance(self):
        before = {p.name: p.read_bytes() for p in self.source.iterdir()}
        result, report = self.run_static()
        self.assertEqual(result.returncode, 0, result.stderr.decode('utf-8'))
        self.assertEqual(report['Failed'], 0)
        self.assertEqual(report['Mode'], 'StaticOnly')
        self.assertEqual(report['BrowserStatus'], '未執行')
        self.assertTrue(report['ManualPending'])
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.source.iterdir()}, '驗收改寫來源檔')

    def test_modified_html_fails_hash_verification(self):
        with (self.source / 'en.html').open('a', encoding='utf-8') as f:
            f.write('變更')
        result, _ = self.run_static()
        self.assertNotEqual(result.returncode, 0, '修改原始 HTML 不得通過')

    def test_active_content_and_secrets_fail_even_with_new_hashes(self):
        for index, payload in enumerate(['<script>alert(1)</script>', '<img src="https://example.test/a">',
                                         '<p onclick="alert(1)">x</p>', '<p style="background:url(https://example.test/a)">x</p>',
                                         '<style>@import "https://example.test/a";</style>',
                                         '<p>S10_SECRET</p>']):
            with self.subTest(payload=payload):
                path = self.source / 'en.html'
                original = path.read_text(encoding='utf-8')
                path.write_text(original.replace('</body>', payload + '</body>'), encoding='utf-8')
                self.refresh_manifest()
                result, report = self.run_static('bad-' + str(index))
                self.assertNotEqual(result.returncode, 0, '危險內容不應僅因雜湊更新就通過')
                self.assertIsNotNone(report)
                self.assertEqual(report['Results'][0]['Status'], 'PASS', '負向案例應先通過 manifest')
                self.assertGreater(report['Failed'], 0)
                path.write_text(original, encoding='utf-8')

    def test_wrong_language_summary_and_missing_public_value_fail(self):
        path = self.source / 'en.html'
        original = path.read_text(encoding='utf-8')
        for index, text in enumerate([original.replace('lang="en"', 'lang="zh-TW"'),
                                      original.replace('<td>passed</td><td>8</td>', '<td>passed</td><td>9</td>'),
                                      original.replace('long-example.test', 'other.test')]):
            path.write_text(text, encoding='utf-8')
            self.refresh_manifest()
            result, report = self.run_static('content-' + str(index))
            self.assertNotEqual(result.returncode, 0, '錯語系、摘要或遺失公開值必須失敗')
            self.assertEqual(report['Results'][0]['Status'], 'PASS', '負向案例應先通過 manifest')

    def test_manifest_path_escape_and_existing_results_are_rejected(self):
        (self.source / 'SHA256SUMS.txt').write_text('0' * 64 + '  ../outside\n', encoding='utf-8')
        result, _ = self.run_static('escape')
        self.assertNotEqual(result.returncode, 0, 'manifest 不得越界')
        output = self.root / 'existing'
        output.mkdir()
        marker = output / '保留.txt'
        marker.write_text('不覆寫', encoding='utf-8')
        result, _ = self.run_static('existing')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(marker.read_text(encoding='utf-8'), '不覆寫')

    def test_invalid_utf8_and_incomplete_metadata_are_rejected(self):
        path = self.source / 'en.html'
        original = path.read_bytes()
        path.write_bytes(original + b'\xff')
        self.refresh_manifest()
        result, _ = self.run_static('utf8')
        self.assertNotEqual(result.returncode, 0, '非 UTF-8 不得通過')
        path.write_bytes(original)
        self.refresh_manifest()
        (self.source / 'report-metadata.json').write_text('{"reports":[]}', encoding='utf-8')
        (self.source / 'SHA256SUMS.txt').write_text(''.join(
            hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + p.name + '\n'
            for p in sorted(self.source.iterdir()) if p.name != 'SHA256SUMS.txt'), encoding='utf-8')
        result, report = self.run_static('metadata')
        self.assertNotEqual(result.returncode, 0, '缺少三語 metadata 不得通過')
        self.assertEqual(report['Results'][0]['Status'], 'PASS')

    def test_protocol_handles_fragmented_utf8_events_and_rejects_bad_replies(self):
        source = ". '" + str(self.script).replace("'", "''") + "'\n"
        source += r'''
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Net.WebSockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
public class FakeHTMLSocket {
    Queue<string> messages; byte[] pending; int position;
    public string Sent;
    public FakeHTMLSocket(string[] input) { messages=new Queue<string>(input); }
    public Task SendAsync(ArraySegment<byte> data, WebSocketMessageType type, bool end, CancellationToken token) {
        Sent=Encoding.UTF8.GetString(data.Array,data.Offset,data.Count); return Task.CompletedTask;
    }
    public Task<WebSocketReceiveResult> ReceiveAsync(ArraySegment<byte> data, CancellationToken token) {
        if (pending==null) { pending=Encoding.UTF8.GetBytes(messages.Dequeue()); position=0; }
        int count=Math.Min(7,pending.Length-position);
        Array.Copy(pending,position,data.Array,data.Offset,count); position+=count;
        bool done=position==pending.Length; if (done) pending=null;
        return Task.FromResult(new WebSocketReceiveResult(count,WebSocketMessageType.Text,done));
    }
}
public class AwaitSentinel {
    public AwaitSentinel GetAwaiter() { return this; }
    public object GetResult() { return "非泛型await不應出現在協定輸出"; }
}
public class LeakyHTMLSocket : FakeHTMLSocket {
    public LeakyHTMLSocket(string[] input) : base(input) {}
    public new AwaitSentinel SendAsync(ArraySegment<byte> data, WebSocketMessageType type, bool end, CancellationToken token) {
        base.SendAsync(data,type,end,token); return new AwaitSentinel();
    }
}
'@
$script:HTMLSocket=[LeakyHTMLSocket]::new([string[]]@('{"id":1,"result":{"ok":true}}'))
$script:HTMLCDPId=0; $script:HTMLEvents=[Collections.Generic.List[object]]::new()
$clean=Invoke-HTMLCDP 'Test.echo'
if ($clean -is [array] -or -not ($clean -is [System.Collections.IDictionary]) -or -not $clean.ok) { throw 'await雜值污染協定結果' }
$script:HTMLSocket=[FakeHTMLSocket]::new([string[]]@('{"method":"Test.event","params":{"value":"中文"}}','{"id":1,"result":{"ok":true}}'))
$script:HTMLCDPId=0; $script:HTMLEvents=[Collections.Generic.List[object]]::new()
$r=Invoke-HTMLCDP 'Test.echo' @{value='中文'}
if (-not $r.ok -or $script:HTMLEvents.Count -ne 1 -or $script:HTMLEvents[0].params.value -ne '中文') { throw '分段事件遺失' }
$sent=$script:HTMLSocket.Sent|ConvertFrom-Json
if ($sent.method -ne 'Test.echo' -or $sent.params.value -ne '中文') { throw '傳送參數不符' }
foreach ($reply in @('{"id":99,"result":{}}','{"id":1,"error":{"message":"合成錯誤"}}')) {
    $script:HTMLSocket=[FakeHTMLSocket]::new([string[]]@($reply));$script:HTMLCDPId=0
    $caught=$false
    try { $null=Invoke-HTMLCDP 'Test.echo' } catch { $caught=$true }
    if (-not $caught) { throw '錯誤回覆未拒絕' }
}
function Invoke-HTMLCDP { throw 'Execution context was destroyed.' }
$state=Get-HTMLReadyState
if ($state.ready -ne 'loading') { throw '導覽暫態未重試' }
function Invoke-HTMLCDP { throw '合成不支援的指令' }
$caught=$false
try { $null=Get-HTMLReadyState } catch { $caught=$true }
if (-not $caught) { throw '其他協定錯誤不可隱藏' }
'''
        path = self.root / 'protocol.ps1'
        path.write_text(source, encoding='utf-8')
        result = subprocess.run([self.pwsh, '-NoProfile', '-NonInteractive', '-File', str(path)],
                                capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr.decode('utf-8'))

    def test_port_cleanup_requires_connection_refused_and_rejects_open_port(self):
        source = ". '" + str(self.script).replace("'", "''") + "'\n"
        source += r'''
$ErrorActionPreference='Stop'
$listener=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,0)
$listener.Start(128);$port=$listener.LocalEndpoint.Port
try {
    $open=Get-HTMLPortClosure $port 250
    if ($open -is [array] -or $open.Closed -or $open.Observations.Count -lt 1) { throw '開放port被誤判關閉或有額外輸出' }
} finally { $listener.Stop() }
$closed=Get-HTMLPortClosure $port
if (-not $closed.Closed -or $closed -is [array]) { throw '關閉port未正確確認' }
if (@($closed.Observations | Where-Object Status -eq '已拒絕連線').Count -lt 1) { throw '不得以逾時代替拒絕連線證據' }
'''
        path = self.root / 'ports.ps1'
        path.write_text(source, encoding='utf-8')
        result = subprocess.run([self.pwsh, '-NoProfile', '-NonInteractive', '-File', str(path)],
                                capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr.decode('utf-8'))
