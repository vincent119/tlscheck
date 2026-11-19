"""驗證事件閘門不把 Skip、套件成功或不完整資料當成具名通過。"""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import check_go_test_events as gate

PACKAGE = 'github.com/vincent119/tlscheck/internal/app'
MAIN = 'TestPowerShellEmptyCandidatesDoNotFallbackToFiles'
CHILDREN = [MAIN + '/包含描述', MAIN + '/不含描述']


def event(action, test=None, package=PACKAGE):
    item = {'Action': action, 'Package': package}
    if test is not None:
        item['Test'] = test
    return item


def passing_events():
    items = [event('start'), event('run', MAIN)]
    for child in CHILDREN:
        items += [event('run', child), event('pass', child)]
    return items + [event('pass', MAIN), event('pass')]


class GoTestEventTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / '測試事件.jsonl'

    def write_events(self, items):
        self.path.write_text(''.join(json.dumps(x, ensure_ascii=False) + '\n' for x in items), encoding='utf-8')
        return self.path

    def test_named_passes_with_unrelated_skips_are_accepted(self):
        items = passing_events()
        items[1:1] = [event('run', 'TestOther'), event('skip', 'TestOther')]
        items += [event('start', package='example.org/other'), event('skip', package='example.org/other')]
        gate.verify_log(self.write_events(items))

    def test_required_skip_or_failure_is_rejected(self):
        for name in [MAIN] + CHILDREN:
            for action in ['skip', 'fail']:
                with self.subTest(name=name, action=action):
                    items = [dict(x, Action=action) if x.get('Test') == name and x['Action'] == 'pass' else x
                             for x in passing_events()]
                    with self.assertRaises(ValueError, msg='必要案例不得跳過或失敗'):
                        gate.verify_log(self.write_events(items))

    def test_missing_lifecycle_events_are_rejected(self):
        items = passing_events()
        for index in range(len(items)):
            with self.subTest(index=index):
                with self.assertRaises(ValueError, msg='缺少開始、主子案例或套件終結事件必須失敗'):
                    gate.verify_log(self.write_events(items[:index] + items[index + 1:]))

    def test_wrong_package_and_wrong_subcase_are_rejected(self):
        variants = [[dict(x, Package='example.org/wrong') for x in passing_events()],
                    [dict(x, Test=MAIN + '/其他描述') if x.get('Test') == CHILDREN[0] else x
                     for x in passing_events()]]
        for items in variants:
            with self.assertRaises(ValueError, msg='不得用其他套件或子案例補足必要證據'):
                gate.verify_log(self.write_events(items))

    def test_duplicates_and_out_of_order_events_are_rejected(self):
        items = passing_events()
        variants = [items[:index] + [items[index]] + items[index:] for index in range(len(items))]
        variants.append(items[:-2] + [items[-1], items[-2]])
        for items in variants:
            with self.assertRaises(ValueError, msg='重複或順序不符的事件不得通過'):
                gate.verify_log(self.write_events(items))

    def test_skip_in_an_additional_descendant_is_rejected(self):
        items = passing_events()
        items[-2:-2] = [event('run', MAIN + '/其他'), event('skip', MAIN + '/其他')]
        with self.assertRaises(ValueError, msg='必要主測試子樹不得藏有 Skip'):
            gate.verify_log(self.write_events(items))

    def test_failure_after_target_pass_and_build_failure_are_rejected(self):
        for failure in [event('fail', package='example.org/other'), {'Action': 'build-fail', 'ImportPath': 'example.org/other'}]:
            with self.assertRaises(ValueError, msg='不得只看到目標通過就忽略後續失敗'):
                gate.verify_log(self.write_events(passing_events() + [failure]))

    def test_output_text_is_not_a_pass_event(self):
        items = [event('start')] + [dict(event('output', name), Output='--- PASS: ' + name)
                                   for name in [MAIN] + CHILDREN] + [event('pass')]
        with self.assertRaises(ValueError, msg='文字中的 PASS 不得冒充結構化事件'):
            gate.verify_log(self.write_events(items))

    def test_malformed_utf8_json_and_event_types_are_rejected(self):
        invalid = [b'', b'\xff\n', b'{"Action":', b'[]\n', b'null\n',
                   b'{"Action":"skip","Action":"pass"}\n', b'{"Action":NaN}\n']
        invalid += [(json.dumps(x) + '\n').encode('utf-8') for x in [
            {'Action': 'PASS'}, {'Action': 1}, {'Action': 'run', 'Package': []},
            {'Action': 'run', 'Package': PACKAGE, 'Test': []}]]
        for data in invalid:
            with self.subTest(data=data):
                self.path.write_bytes(data)
                with self.assertRaises(ValueError, msg='損壞或不合法事件必須拒絕'):
                    gate.verify_log(self.path)

    def test_oversized_records_and_logs_are_rejected(self):
        self.write_events(passing_events())
        for name in ['MAX_EVENT_BYTES', 'MAX_LOG_BYTES']:
            with patch.object(gate, name, 16):
                with self.assertRaises(ValueError, msg='事件與日誌須有大小上限'):
                    gate.verify_log(self.path)

    def test_cli_requires_every_log_to_pass(self):
        good = self.write_events(passing_events())
        second = Path(self.temp.name) / 'race.jsonl'
        second.write_bytes(good.read_bytes())
        command = [sys.executable, '-B', str(Path(__file__).with_name('check_go_test_events.py')), str(good), str(second)]
        result = subprocess.run(command, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, '普通與 race 合法事件應成功')
        self.assertIn('包含描述'.encode('utf-8'), result.stdout)
        second.write_text(json.dumps(event('skip', MAIN)) + '\n', encoding='utf-8')
        result = subprocess.run(command, capture_output=True, timeout=10)
        self.assertNotEqual(result.returncode, 0, '任一份有 Skip 必須失敗')
        self.assertIn('跳過'.encode('utf-8'), result.stderr)

    def test_cli_rejects_missing_files(self):
        command = [sys.executable, '-B', str(Path(__file__).with_name('check_go_test_events.py')), str(self.path)]
        result = subprocess.run(command, capture_output=True, timeout=10)
        self.assertNotEqual(result.returncode, 0, '缺事件檔不得通過')


if __name__ == '__main__':
    unittest.main()
