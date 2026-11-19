"""檢查 Go JSONL 的具名 PowerShell 證據，不以套件成功代替測試執行。"""
import argparse
import json
from pathlib import Path
import sys

PACKAGE = 'github.com/vincent119/tlscheck/internal/app'
MAIN = 'TestPowerShellEmptyCandidatesDoNotFallbackToFiles'
REQUIRED = (MAIN, MAIN + '/包含描述', MAIN + '/不含描述')
MAX_EVENT_BYTES = 1024 * 1024
MAX_LOG_BYTES = 64 * 1024 * 1024
ACTIONS = {'start', 'run', 'pause', 'cont', 'pass', 'bench', 'fail', 'output', 'skip',
           'build-start', 'build-output', 'build-fail'}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('事件含重複欄位')
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError('事件含不合法數值')


def verify_log(path):
    states = dict.fromkeys(REQUIRED)
    package_state = None
    total = 0
    with path.open('rb') as stream:
        while True:
            raw = stream.readline(MAX_EVENT_BYTES + 1)
            if not raw:
                break
            total += len(raw)
            if len(raw) > MAX_EVENT_BYTES or total > MAX_LOG_BYTES:
                raise ValueError('測試事件超過大小上限')
            try:
                item = json.loads(raw.decode('utf-8'), object_pairs_hook=unique_object,
                                  parse_constant=reject_constant)
            except (UnicodeError, ValueError, RecursionError) as error:
                raise ValueError('測試事件不是合法 UTF-8 JSON') from error
            if not isinstance(item, dict) or not isinstance(item.get('Action'), str):
                raise ValueError('測試事件格式不合法')
            action = item['Action']
            if action not in ACTIONS or any(key in item and not isinstance(item[key], str)
                                            for key in ('Package', 'Test')):
                raise ValueError('測試事件欄位不合法')
            if action in ('fail', 'build-fail'):
                raise ValueError('測試或建置失敗')
            if item.get('Package') != PACKAGE:
                continue
            name = item.get('Test', '')
            target = name == MAIN or name.startswith(MAIN + '/')
            if action == 'skip' and (target or not name):
                raise ValueError('必要 PowerShell 測試或套件被跳過')
            if not name and action in ('start', 'pass'):
                if action == 'start' and package_state is None:
                    package_state = 'start'
                elif action == 'pass' and package_state == 'start' and all(
                        state == 'pass' for state in states.values()):
                    package_state = 'pass'
                else:
                    raise ValueError('套件事件重複、順序錯誤或缺少具名通過')
            elif name in states and action in ('run', 'pass'):
                if package_state != 'start':
                    raise ValueError('必要案例不在有效套件生命週期內')
                if action == 'run' and states[name] is None:
                    if name != MAIN and states[MAIN] != 'run':
                        raise ValueError('子案例缺少執行中的主測試')
                    states[name] = 'run'
                elif action == 'pass' and states[name] == 'run':
                    if name == MAIN and any(states[child] != 'pass' for child in REQUIRED[1:]):
                        raise ValueError('主測試缺少子案例通過證據')
                    states[name] = 'pass'
                else:
                    raise ValueError('必要案例事件重複或順序錯誤')
    if package_state != 'pass' or any(state != 'pass' for state in states.values()):
        raise ValueError('缺少必要套件或主子案例的完整具名 PASS 證據')


def main():
    parser = argparse.ArgumentParser(description='驗證 PowerShell 主測試與兩子案例均具名通過且未跳過')
    parser.add_argument('logs', nargs='+', type=Path, help='Go JSONL 事件檔')
    args = parser.parse_args()
    try:
        for path in args.logs:
            verify_log(path)
    except OSError:
        print('驗證失敗：無法讀取測試事件檔', file=sys.stderr)
        return 1
    except ValueError as error:
        print('驗證失敗：' + str(error), file=sys.stderr)
        return 1
    for index in range(len(args.logs)):
        for name in REQUIRED:
            print(f'事件檔 {index + 1}：{name} 具名 PASS，未跳過')
    return 0


if __name__ == '__main__':
    sys.exit(main())
