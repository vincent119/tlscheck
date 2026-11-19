"""以 PowerShell 驗證無 Go 驗收工具的程序邊界，不冒充 Windows 實機。"""
from pathlib import Path
import json
import shutil
import subprocess
import tempfile
import unittest


class WindowsAcceptanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pwsh = shutil.which('pwsh')
        if not cls.pwsh:
            raise unittest.SkipTest('缺少 PowerShell，無法驗證驗收工具')
        cls.script = Path('scripts/test-windows.ps1').resolve()

    def run_ps(self, source, root):
        path = root / 'probe.ps1'
        path.write_text(source, encoding='utf-8')
        return subprocess.run([self.pwsh, '-NoProfile', '-NonInteractive', '-File', str(path)],
                              capture_output=True, timeout=30)

    def test_parser_and_missing_binary_fail_without_creating_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = ". '" + str(self.script).replace("'", "''") + "'\n"
            source += "$tokens=$null; $errors=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('" + str(self.script).replace("'", "''") + "',[ref]$tokens,[ref]$errors); if ($errors.Count) { throw '語法錯誤' }\n"
            self.assertEqual(self.run_ps(source, root).returncode, 0, '腳本語法或 dot-source 有副作用')
            result = subprocess.run([self.pwsh, '-NoProfile', '-NonInteractive', '-File', str(self.script),
                                     '-BinaryPath', str(root / 'missing.exe'), '-OutputDirectory', str(root / 'results')],
                                    capture_output=True, timeout=30)
            self.assertNotEqual(result.returncode, 0, '平台／檔案前置失敗不得成功')
            self.assertFalse((root / 'results').exists(), '前置失敗不得建立驗收目錄')

    def test_process_preserves_utf8_and_literal_arguments(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            child = root / 'child.ps1'
            child.write_text("param([Parameter(ValueFromRemainingArguments=$true)][string[]]$Items)\n"
                             "[Console]::Out.Write((ConvertTo-Json -InputObject @($Items) -Compress)); [Console]::Error.Write('中文診斷'); exit 7\n", encoding='utf-8')
            quote = lambda x: "'" + str(x).replace("'", "''") + "'"
            source = '. ' + quote(self.script) + '\n'
            source += '$r=Invoke-ExeProbe -BinaryPath ' + quote(self.pwsh) + ' -WorkingDirectory ' + quote(root)
            source += ' -Arguments @(' + ','.join(map(quote, ['-NoProfile', '-NonInteractive', '-File', child, '空白 路徑', "單'引號", '$(不應執行)', ''])) + ')\n'
            source += '$r | ConvertTo-Json -Compress\n'
            result = self.run_ps(source, root)
            self.assertEqual(result.returncode, 0, result.stderr.decode('utf-8'))
            data = json.loads(result.stdout)
            self.assertEqual(data['Code'], 7, '子程序結束碼遺失')
            self.assertEqual(json.loads(data['Out']), ['空白 路徑', "單'引號", '$(不應執行)', ''])
            self.assertEqual(data['Err'], '中文診斷')

    def test_process_timeout_is_a_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = ". '" + str(self.script).replace("'", "''") + "'\n"
            source += "try { Invoke-ExeProbe -BinaryPath '" + self.pwsh.replace("'", "''") + "' -WorkingDirectory '" + str(root).replace("'", "''") + "' -Arguments @('-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 20') -TimeoutMilliseconds 200; exit 1 } catch { if ($_.Exception.Message -notmatch '逾時') { throw }; exit 0 }\n"
            result = self.run_ps(source, root)
            self.assertEqual(result.returncode, 0, '逾時未終止或未回報失敗')

    def test_case_failure_is_recorded_without_becoming_a_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = ". '" + str(self.script).replace("'", "''") + "'\n"
            source += "$script:AcceptanceResults=[Collections.Generic.List[object]]::new(); Invoke-AcceptanceCase '正向' {}; Invoke-AcceptanceCase '負向' { throw '合成失敗' }; Write-Output ('JSON:' + (ConvertTo-Json -InputObject $script:AcceptanceResults.ToArray() -Compress))\n"
            result = self.run_ps(source, root)
            self.assertEqual(result.returncode, 0, '逐例失敗應保留給總結果彙整')
            records = json.loads(result.stdout.decode('utf-8').split('JSON:', 1)[1])
            self.assertEqual([x['Status'] for x in records], ['PASS', 'FAIL'])
            self.assertEqual(records[1]['Detail'], '合成失敗')
