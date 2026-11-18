"""確保後續 shell 能取得已安裝的封裝工具，且試建置不發佈。"""
from pathlib import Path
import os
import re
import subprocess
import sys
import unittest


class WorkflowToolTests(unittest.TestCase):
    def test_python_environment_supports_chinese_streams(self):
        for workflow in ['ci.yml', 'release.yml']:
            with self.subTest(workflow=workflow):
                text = (Path('.github/workflows') / workflow).read_text(encoding='utf-8')
                block = re.search(r'^env:\n((?:  [A-Z0-9_]+: [^\n]+\n)+)', text, re.MULTILINE)
                self.assertIsNotNone(block, '所有 Python 步驟必須共用明確編碼環境')
                values = dict(re.findall(r"^  (PYTHON[A-Z0-9_]+): '([^']+)'$", block[1], re.MULTILINE))
                self.assertEqual(values.get('PYTHONUTF8'), '1', '必須啟用 Python UTF-8 模式')
                self.assertEqual(values.get('PYTHONIOENCODING'), 'utf-8', '必須以 UTF-8 輸出文字串流')
                env = dict(os.environ, PYTHONUTF8='0', PYTHONIOENCODING='cp1252')
                env.update(values)
                result = subprocess.run(
                    [sys.executable, '-B', '-c', "import sys; assert sys.flags.utf8_mode == 1; print('中文標準輸出'); print('中文診斷輸出', file=sys.stderr)"],
                    env=env, capture_output=True, timeout=30,
                )
                self.assertEqual(result.returncode, 0, 'CI 編碼設定無法支援中文輸出')
                self.assertEqual(result.stdout.decode('utf-8').strip(), '中文標準輸出')
                self.assertEqual(result.stderr.decode('utf-8').strip(), '中文診斷輸出')

    def test_snapshot_shell_has_installed_goreleaser(self):
        text = Path('.github/workflows/ci.yml').read_text(encoding='utf-8')
        packages = text.split('\n  packages:\n', 1)[1]
        steps = re.findall(r'^      - .*?(?=^      - |\Z)', packages, re.MULTILINE | re.DOTALL)
        installs = [(i, step) for i, step in enumerate(steps) if 'uses: goreleaser/goreleaser-action@' in step]
        self.assertEqual(len(installs), 1, '封裝工作必須有唯一工具安裝步驟')
        install_index, install = installs[0]
        self.assertIn('goreleaser-action@e435ccd777264be153ace6237001ef4d979d3a7a', install)
        self.assertRegex(install, r'(?m)^          version: v2\.14\.3$')
        self.assertRegex(install, r'(?m)^          install-only: true$', '後續 shell 需要安裝目錄加入 PATH')
        self.assertNotRegex(install, r'(?m)^          args:', '安裝與執行必須明確分離')
        following = ''.join(steps[install_index + 1:])
        version_index = following.find('goreleaser --version')
        check_index = following.find('goreleaser check')
        snapshot_index = following.find('goreleaser release --snapshot --clean --skip=publish')
        self.assertGreaterEqual(version_index, 0, '後續 shell 必須驗證工具可執行')
        self.assertGreater(check_index, version_index, '必須先驗證版本再檢查設定')
        self.assertGreater(snapshot_index, check_index, '必須先 check 再執行 snapshot')
        self.assertIn('python3 scripts/release.py verify', following)

    def test_snapshot_keeps_read_only_permissions_and_no_publish(self):
        text = Path('.github/workflows/ci.yml').read_text(encoding='utf-8')
        self.assertRegex(text, r'(?m)^permissions:\n  contents: read$')
        self.assertNotIn('contents: write', text)
        self.assertNotIn('--execute', text)
        self.assertIn('goreleaser release --snapshot --clean --skip=publish', text)
        config = Path('.goreleaser.yaml').read_text(encoding='utf-8')
        self.assertRegex(config, r'(?m)^release:\n  disable: true$')


if __name__ == '__main__':
    unittest.main()
