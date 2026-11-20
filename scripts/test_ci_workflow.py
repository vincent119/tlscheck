"""確保後續 shell 能取得已安裝的封裝工具，且試建置不發佈。"""
from pathlib import Path
import os
import re
import subprocess
import sys
import unittest


class WorkflowToolTests(unittest.TestCase):
    def test_native_python_tests_load_without_inherited_module_paths(self):
        text = Path('.github/workflows/ci.yml').read_text(encoding='utf-8')
        native = text.split('\n  native:\n', 1)[1].split('\n  html-acceptance:\n', 1)[0]
        step = native.split('      - name: 格式與靜態檢查\n', 1)[1].split('      - ', 1)[0]
        path = re.search(r'^          PYTHONPATH: (.+)$', step, re.MULTILINE)
        env = dict(os.environ)
        env.pop('PYTHONPATH', None)
        if path:
            env['PYTHONPATH'] = path[1].replace('${{ github.workspace }}', str(Path.cwd()))
        # 子程序只載入測試，不執行，避免此回歸遞迴呼叫自己。
        source = '''import sys, unittest
loader = unittest.TestLoader()
suite = loader.loadTestsFromNames(sys.argv[1:])
if loader.errors:
    raise SystemExit("\\n".join(loader.errors))
assert suite.countTestCases() > 0, '未載入任何測試'
'''
        tests = sorted('.'.join(p.with_suffix('').parts) for p in Path('scripts').glob('test_*.py')
                       if p.name != 'test_html_acceptance.py')
        result = subprocess.run([sys.executable, '-B', '-c', source, *tests],
                                env=env, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0,
                         'CI 啟動方式無法載入相鄰模組：\n' + result.stderr.decode('utf-8'))
        self.assertIsNotNone(path, '模組路徑必須明確設定於原生檢查步驟')
        self.assertEqual(path[1], '${{ github.workspace }}/scripts')

    def test_html_checks_fail_independently_of_native_tests(self):
        text = Path('.github/workflows/ci.yml').read_text(encoding='utf-8')
        jobs = dict(re.findall(r'^  ([a-z-]+):\n(.*?)(?=^  [a-z-]+:|\Z)',
                               text.split('jobs:\n', 1)[1], re.MULTILINE | re.DOTALL))
        self.assertIn('html-acceptance', jobs, 'HTML 驗收必須有獨立工作')
        native, html = jobs['native'], jobs['html-acceptance']
        self.assertIn('needs: packages', native)
        self.assertNotIn('html-acceptance', native, 'HTML 失敗不得阻擋核心測試')
        self.assertNotIn('needs:', html, 'HTML 驗收必須可獨立執行')
        self.assertIn('macos-15, macos-15-intel, windows-2025', html)
        self.assertIn('fail-fast: false', html)
        self.assertIn('pwsh -NoProfile -NonInteractive', html)
        self.assertIn('python3 -B -m unittest -v scripts/test_html_acceptance.py', html)
        self.assertIn('"$file" != scripts/test_html_acceptance.py', native,
                      '核心工作必須排除已獨立執行的 HTML 回歸')
        self.assertIn('python3 -B -m unittest -v "${tests[@]}"', native,
                      '其他腳本回歸仍須執行')
        self.assertNotRegex(native + html, r'continue-on-error|\|\|\s*true',
                            '不得隱藏任一工作的失敗')

    def test_native_requires_fresh_named_powershell_passes_and_keeps_events(self):
        text = Path('.github/workflows/ci.yml').read_text(encoding='utf-8')
        native = text.split('\n  packages:\n', 1)[0]
        self.assertIn('pwsh -NoProfile -NonInteractive', native, 'CI 必須確認 PowerShell 可執行')
        self.assertIn('set -o pipefail', native, 'tee 不得遮蔽 Go 失敗')
        for flags, file in [('-json', 'go-test.jsonl'), ('-race -json', 'go-test-race.jsonl')]:
            self.assertIn('go test ' + flags + ' -count=1 ./... | tee ' + file, native,
                          '普通與 race 必須保留新鮮 JSON 事件')
            self.assertIn('set -o pipefail\n          go test ' + flags, native,
                          '每個測試步驟都必須保留 Go 失敗結束碼')
        command = 'python3 -B scripts/check_go_test_events.py go-test.jsonl go-test-race.jsonl'
        self.assertIn(command, native, '必須分別驗證普通與 race 的必要具名結果')
        steps = re.findall(r'^      - .*?(?=^      - |\Z)', native, re.MULTILINE | re.DOTALL)
        uploads = [step for step in steps if 'name: go-test-events-${{ matrix.os }}' in step]
        self.assertEqual(len(uploads), 1, '每個平台必須保留唯一測試事件產物')
        upload = uploads[0]
        self.assertIn('uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02', upload)
        self.assertRegex(upload, r'(?m)^        if: always\(\)$', '失敗也必須保留原始事件')
        self.assertRegex(upload, r'(?m)^          path: \|\n            go-test\.jsonl\n            go-test-race\.jsonl\n',
                         '只允許上傳指定事件，不得整個 workspace 打包')
        self.assertIn('retention-days: 7', upload)

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

    def test_tag_release_cannot_implicitly_update_package_repositories(self):
        text = Path('.github/workflows/release.yml').read_text(encoding='utf-8')
        self.assertRegex(text, r'(?m)^      update_packages:\n(?:        [^\n]*\n)*        default: false$',
                         '套件更新必須有預設關閉的手動選項')
        update = text.split('      - name: 成功發佈後更新穩定套件\n', 1)[1]
        self.assertIn("if: github.event_name == 'workflow_dispatch' && inputs.update_packages == true", update,
                      'tag發佈不得自動寫入Homebrew或Scoop')
        self.assertIn('python3 scripts/release.py update --tag "$RELEASE_TAG" --execute', update)
        self.assertIn('vars.ENABLE_RELEASE', text, '原本發佈開關不得移除')
        self.assertIn('environment: release', text, '原本環境核准不得移除')


if __name__ == '__main__':
    unittest.main()
