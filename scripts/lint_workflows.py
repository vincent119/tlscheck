"""補驗 GitHub 新佇列契約；其他 Actionlint 診斷一律保留。"""
import json
from pathlib import Path
import re
import subprocess
import sys

QUEUE_MESSAGE = 'unexpected key "queue" for "concurrency" section. expected one of "cancel-in-progress", "group"'


def remaining_errors(text, diagnostics):
    blocks = list(re.finditer(r'^concurrency:\n((?:[ \t]+[^\n]*\n)+)',text,re.MULTILINE))
    if len(blocks) != 1 or not re.fullmatch(
        r'  group: tlscheck-stable-release\n  cancel-in-progress: false\n  queue: max\n',blocks[0][1]):
        raise ValueError('發佈佇列必須保留 max、固定群組及禁止取消執行中版本')
    queue_line=text[:blocks[0].start()].count('\n')+4
    result=[]
    for error in diagnostics:
        # 不吞掉其他檔案、位置、類型或內容的錯誤。
        if (Path(error['filepath']).as_posix()=='.github/workflows/release.yml'
                and error['line']==queue_line and error['column']==3
                and error['kind']=='syntax-check' and error['message']==QUEUE_MESSAGE):
            continue
        result.append(error)
    return result


def main():
    tool=sys.argv[1] if len(sys.argv)>1 else 'actionlint'
    result=subprocess.run([tool,'-format','{{json .}}'],capture_output=True,text=True)
    if result.stderr:
        print(result.stderr,end='',file=sys.stderr)
    try:
        errors=json.loads(result.stdout or '[]') or []
        if result.returncode and not errors:
            raise ValueError('非零結束碼但沒有可核對診斷')
        errors=remaining_errors(Path('.github/workflows/release.yml').read_text(),errors)
    except (ValueError,KeyError,TypeError):
        raise SystemExit('Workflow 或 lint 輸出無法驗證')
    if result.returncode not in [0,1] or result.returncode==1 and not result.stdout.strip():
        raise SystemExit('Actionlint 執行失敗')
    if errors:
        print(json.dumps(errors,ensure_ascii=False,indent=2))
        raise SystemExit(1)
    print('Actionlint 與官方 queue:max 契約檢查通過')

if __name__=='__main__':
    main()
