"""只在暫存目錄解壓本機架構執行檔，確認升級與設定唯讀。"""
import os
from pathlib import Path
import platform
import subprocess
import tempfile

from release import archives


def main():
    items=archives(Path('dist'))
    system={'Darwin':'darwin','Windows':'windows'}.get(platform.system())
    arch={'arm64':'arm64','aarch64':'arm64','AMD64':'amd64','x86_64':'amd64'}.get(platform.machine())
    if (system,arch) not in items:
        raise ValueError('此主機不是可驗證的原生目標')
    item=items[(system,arch)]
    if system=='darwin':
        config=Path.home()/'Library/Application Support/tlscheck/config.json'
    else:
        config=Path(os.environ['APPDATA'])/'tlscheck/config.json'
    before=config.read_bytes() if config.exists() else None
    with tempfile.TemporaryDirectory(prefix='tlscheck-install-') as root:
        path=Path(root)/('tlscheck.exe' if system=='windows' else 'tlscheck')
        sentinel=Path(root)/'config.json'
        sentinel.write_text('{"language":"zh-TW"}\n')
        for stage in ['安裝','重裝升級']:
            temporary=path.with_suffix('.new')
            temporary.write_bytes(item['binary']);temporary.chmod(0o755)
            temporary.replace(path)
            result=subprocess.run([str(path),'--version'],capture_output=True,text=True,check=True)
            if item['version'] not in result.stdout:
                raise ValueError('版本資訊不符')
            if sentinel.read_text()!='{"language":"zh-TW"}\n':
                raise ValueError('隔離設定被改寫')
            print(stage+'：原生 '+system+'/'+arch+' --version 通過')
    after=config.read_bytes() if config.exists() else None
    if after != before:
        raise ValueError('使用者設定被改寫')
    print('使用者設定及隔離設定保持不變；此為手動壓縮檔安裝，不是套件管理器升級')

if __name__=='__main__':
    main()
