"""以非 UTF-8 預設環境驗證維護工具，不執行遠端發佈或真實安裝。"""
import contextlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import install_check
import lint_workflows


class EncodingTests(unittest.TestCase):
    def test_maintenance_tools_ignore_default_encoding(self):
        # 關閉 UTF-8 模式並將隱含編碼視為錯誤，避免本機預設 UTF-8 掩蓋 Windows 問題。
        env = dict(os.environ, PYTHONUTF8='0', PYTHONIOENCODING='utf-8',
                   PYTHONCOERCECLOCALE='0', LC_ALL='C', PYTHONPATH=str(Path('scripts').resolve()))
        result = subprocess.run(
            [sys.executable, '-B', '-X', 'utf8=0', '-X', 'warn_default_encoding',
             '-W', 'error::EncodingWarning', '-m', 'unittest', '-q',
             'test_ci_workflow', 'test_release', 'test_go_test_events',
             'test_encoding.EncodingTests.test_installation_text_boundaries_use_utf8',
             'test_encoding.EncodingTests.test_lint_text_boundaries_use_utf8'],
            env=env, capture_output=True, timeout=60,
        )
        self.assertEqual(result.returncode, 0,
                         '非 UTF-8 環境回歸失敗：\n' + result.stderr.decode('utf-8'))

    def test_installation_text_boundaries_use_utf8(self):
        with tempfile.TemporaryDirectory(prefix='tlscheck-encoding-') as root:
            config = Path(root) / 'tlscheck/config.json'
            config.parent.mkdir()
            config.write_text('{"備註":"保留原設定"}\n', encoding='utf-8')
            before = config.read_bytes()
            item = {'version': '1.2.3', 'binary': b'synthetic executable'}
            output = io.StringIO()
            with patch.object(install_check, 'archives', return_value={('windows', 'amd64'): item}), \
                    patch.object(install_check.platform, 'system', return_value='Windows'), \
                    patch.object(install_check.platform, 'machine', return_value='AMD64'), \
                    patch.dict(os.environ, APPDATA=root), \
                    patch.object(install_check.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, 'tlscheck 1.2.3\n', '')) as run, \
                    contextlib.redirect_stdout(output):
                install_check.main()
            self.assertEqual(run.call_count, 2, '必須驗證安裝與重裝')
            for call in run.call_args_list:
                self.assertEqual(call.kwargs.get('encoding'), 'utf-8', 'CLI 版本輸出必須明確以 UTF-8 解碼')
            self.assertEqual(config.read_bytes(), before, '驗證工具改寫原設定')
            self.assertIn('設定保持不變', output.getvalue())

    def test_lint_text_boundaries_use_utf8(self):
        output = io.StringIO()
        with patch.object(lint_workflows.sys, 'argv', ['lint_workflows.py']), \
                patch.object(lint_workflows.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '[]', '')) as run, \
                contextlib.redirect_stdout(output):
            lint_workflows.main()
        self.assertEqual(run.call_args.kwargs.get('encoding'), 'utf-8', 'Actionlint 診斷必須明確以 UTF-8 解碼')
        self.assertIn('契約檢查通過', output.getvalue())


if __name__ == '__main__':
    unittest.main()
