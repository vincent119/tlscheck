"""確保後續 shell 能取得已安裝的封裝工具，且試建置不發佈。"""
from pathlib import Path
import re
import unittest


class WorkflowToolTests(unittest.TestCase):
    def test_snapshot_shell_has_installed_goreleaser(self):
        text = Path('.github/workflows/ci.yml').read_text()
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
        text = Path('.github/workflows/ci.yml').read_text()
        self.assertRegex(text, r'(?m)^permissions:\n  contents: read$')
        self.assertNotIn('contents: write', text)
        self.assertNotIn('--execute', text)
        self.assertIn('goreleaser release --snapshot --clean --skip=publish', text)
        config = Path('.goreleaser.yaml').read_text()
        self.assertRegex(config, r'(?m)^release:\n  disable: true$')


if __name__ == '__main__':
    unittest.main()
