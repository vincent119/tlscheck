"""分階段發佈；預設命令只作本機驗證，不隱含遠端寫入。"""
import re

def version(tag):
    match = re.fullmatch(r'v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?', tag)
    if not match:
        raise ValueError('版本格式無效')
    if match[4] and any(part.isdigit() and len(part)>1 and part.startswith('0') for part in match[4][1:].split('.')):
        raise ValueError('預發佈數字不可有前導零')
    return tuple(int(match[i]) for i in (1, 2, 3)), match[4]

def decision(tag, current, same):
    target, pre = version(tag)
    if pre:
        return 'skip'
    if current:
        old, oldpre = version(current)
        if oldpre:
            raise ValueError('穩定套件狀態包含預發佈版本')
        if old > target:
            return 'skip'
        if old == target:
            if not same:
                raise ValueError('相同版本內容不同，停止更新')
            return 'unchanged'
    return 'update'

def destination(value):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]*/[A-Za-z0-9][A-Za-z0-9_.-]*', value) or 'OWNER' in value or 'REPOSITORY' in value or '..' in value:
        raise ValueError('套件目的地尚未確認或格式無效')
    return value

def asset_action(local, remote):
    if remote is None:
        return 'upload'
    if local != remote:
        raise ValueError('既有產物內容不同，禁止覆寫')
    return 'unchanged'

def verified_asset(local, remote):
    if remote is None:
        raise ValueError('遠端資產不存在，不能視為已驗證')
    asset_action(local,remote)

def verify_identity(existing, tag, commit):
    if existing['tag_name'] != tag or existing.get('body', '').splitlines()[0:1] != ['tlscheck source: '+commit]:
        raise ValueError('既有 Release 來源無法核對')

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile

REPOSITORY = 'vincent119/tlscheck'
REQUIRED = {'LICENSE', 'README.md', 'README.zh-TW.md', 'docs/releasing.md', 'docs/releasing.zh-TW.md'}

def digest(data):
    return hashlib.sha256(data).hexdigest()

def archives(dist):
    """只接受四個指定目標，重算 checksum 並檢查安全壓縮路徑。"""
    hashes = {}
    for line in (dist / 'checksums.txt').read_text(encoding='utf-8').splitlines():
        sha, name = line.split(maxsplit=1)
        name = name.lstrip('*')
        if Path(name).name != name or name in hashes or not re.fullmatch('[0-9a-f]{64}', sha):
            raise ValueError('校驗清單無效')
        hashes[name] = sha
    if len(hashes) != 4:
        raise ValueError('必須剛好有四個產物')
    result = {}
    for name, sha in hashes.items():
        match = re.fullmatch(r'tlscheck_(.+)_(darwin|windows)_(amd64|arm64)\.(tar\.gz|zip)', name)
        if not match or (match[2] == 'windows') != (match[4] == 'zip'):
            raise ValueError('產物名稱或格式無效')
        path = dist / name
        if digest(path.read_bytes()) != sha:
            raise ValueError('產物校驗失敗')
        binary = 'tlscheck.exe' if match[2] == 'windows' else 'tlscheck'
        if match[4] == 'zip':
            with zipfile.ZipFile(path) as archive:
                names = archive.namelist()
                binary_data = archive.read(binary)
                documents = {name:archive.read(name) for name in REQUIRED}
        else:
            with tarfile.open(path) as archive:
                names = archive.getnames()
                if any(not member.isfile() for member in archive.getmembers()):
                    raise ValueError('壓縮檔包含非一般檔案')
                binary_data = archive.extractfile(binary).read()
                documents = {name:archive.extractfile(name).read() for name in REQUIRED}
        if set(names) != REQUIRED | {binary} or len(names) != len(set(names)):
            raise ValueError('壓縮檔內容不符合契約')
        if any(data != Path(name).read_bytes() for name,data in documents.items()):
            raise ValueError('壓縮檔文件與來源不一致')
        target = (match[2], match[3])
        if target in result:
            raise ValueError('重複目標')
        result[target] = {'name':name, 'sha256':sha, 'version':match[1], 'binary':binary_data}
    if set(result) != {(system, arch) for system in ['darwin','windows'] for arch in ['amd64','arm64']}:
        raise ValueError('缺少目標')
    if len({item['version'] for item in result.values()}) != 1:
        raise ValueError('版本不一致')
    return result

def packages(items, tag):
    version(tag)
    number = tag[1:]
    if any(item['version'] != number for item in items.values()):
        raise ValueError('套件版本與產物不一致，snapshot 不可作為正式套件')
    def url(system, arch):
        return f'https://github.com/{REPOSITORY}/releases/download/{tag}/'+items[(system, arch)]['name']
    def sha(system, arch):
        return items[(system, arch)]['sha256']
    formula = f'''class Tlscheck < Formula
  desc "TLS certificate and local key diagnostics"
  homepage "https://github.com/{REPOSITORY}"
  version "{number}"
  license "Apache-2.0"
  on_macos do
    on_arm do
      url "{url('darwin','arm64')}"
      sha256 "{sha('darwin','arm64')}"
    end
    on_intel do
      url "{url('darwin','amd64')}"
      sha256 "{sha('darwin','amd64')}"
    end
  end
  def install
    bin.install "tlscheck"
  end
  test do
    assert_match version.to_s, shell_output("#{{bin}}/tlscheck --version")
  end
end
'''
    manifest = {'version':number,'description':'TLS certificate and local key diagnostics','homepage':'https://github.com/'+REPOSITORY,'license':'Apache-2.0','bin':'tlscheck.exe','architecture':{key:{'url':url('windows',arch),'hash':sha('windows',arch)} for key,arch in [('64bit','amd64'),('arm64','arm64')]}}
    return {'homebrew':formula.encode(), 'scoop':(json.dumps(manifest,indent=2)+'\n').encode()}

class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        if urllib.parse.urlparse(newurl).scheme != 'https':
            raise ValueError('拒絕非 HTTPS 重新導向')
        redirected = super().redirect_request(request,fp,code,message,headers,newurl)
        if redirected and urllib.parse.urlparse(newurl).hostname != urllib.parse.urlparse(request.full_url).hostname:
            redirected.remove_header('Authorization')
        return redirected

class API:
    """只使用固定 GitHub API，錯誤不輸出 token 或 response body。"""
    def __init__(self, token):
        if not token:
            raise ValueError('缺少 GitHub 授權')
        self.token = token

    def request(self, path, method='GET', data=None, raw=False, upload=False):
        host = 'https://uploads.github.com' if upload else 'https://api.github.com'
        headers = {'Authorization':'Bearer '+self.token,'Accept':'application/octet-stream' if raw else 'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'}
        body = data if isinstance(data, bytes) else json.dumps(data).encode() if data is not None else None
        if body is not None:
            headers['Content-Type'] = 'application/octet-stream' if isinstance(data, bytes) else 'application/json'
        request = urllib.request.Request(host+path, data=body, headers=headers, method=method)
        try:
            with urllib.request.build_opener(SafeRedirect()).open(request, timeout=60) as response:
                result = response.read()
                return result if raw else json.loads(result) if result else None
        except urllib.error.HTTPError as error:
            if error.code == 404 and method == 'GET':
                return None
            raise ValueError(f'GitHub API 階段失敗，HTTP {error.code}') from None


def find_release(api, tag):
    # 按 tag endpoint 不能找到 draft；列舉授權可見的全部頁面並拒絕歧義。
    matches = []
    page = 1
    seen = set()
    while True:
        entries = api.request(f'/repos/{REPOSITORY}/releases?per_page=100&page={page}')
        if not isinstance(entries, list):
            raise ValueError('無法確認既有 Release 清單')
        for entry in entries:
            if entry['id'] in seen:
                raise ValueError('Release 分頁狀態不一致')
            seen.add(entry['id'])
            if entry['tag_name'] == tag:
                matches.append(entry)
        if len(entries) < 100:
            break
        page += 1
    if len(matches) > 1:
        raise ValueError('同一 tag 有多個 Release，需人工核對')
    return matches[0] if matches else None


def make_latest(api, tag):
    target, pre = version(tag)
    if pre:
        return 'false'
    latest = api.request(f'/repos/{REPOSITORY}/releases/latest')
    if latest is None:
        return 'true'
    current, current_pre = version(latest['tag_name'])
    if latest.get('draft') or latest.get('prerelease') or current_pre:
        raise ValueError('最新穩定版狀態無法確認')
    return 'true' if target > current else 'false'


def publish(api, dist, tag, commit):
    """只補齊缺少資產；任何同名不同內容都停止，不使用覆寫。"""
    items = archives(dist)
    if any(x['version'] != tag[1:] for x in items.values()):
        raise ValueError('產物與 tag 不一致')
    path = f'/repos/{REPOSITORY}/releases'
    existing = find_release(api,tag)
    if existing:
        verify_identity(existing, tag, commit)
    else:
        existing = api.request(path, 'POST', {'tag_name':tag,'target_commitish':commit,'name':tag,'body':'tlscheck source: '+commit,'draft':True,'prerelease':bool(version(tag)[1])})
    release_id = existing['id']
    assets = api.request(path+f'/{release_id}/assets?per_page=100')
    local_names = {x['name'] for x in items.values()} | {'checksums.txt'}
    if any(asset['name'] not in local_names for asset in assets):
        raise ValueError('Release 含非預期資產，需人工核對')
    remote = {asset['name']:asset for asset in assets}
    # 先核對全部既有資產，再進行任何補傳。
    missing = []
    starters = []
    for name in sorted(local_names):
        data = (dist/name).read_bytes()
        asset = remote.get(name)
        if asset and asset.get('state') == 'starter':
            if not existing.get('draft') or asset.get('size') != 0:
                raise ValueError('不能清理已發佈或非空的失敗資產')
            starters.append(asset)
            missing.append((name,data))
            continue
        if asset and asset.get('state') != 'uploaded':
            raise ValueError('既有資產狀態無法確認')
        current = api.request(f'/repos/{REPOSITORY}/releases/assets/'+str(asset['id']), raw=True) if asset else None
        if asset_action(data, current) == 'upload':
            missing.append((name,data))
    if starters:
        current_release = api.request(path+f'/{release_id}')
        verify_identity(current_release,tag,commit)
        if not current_release.get('draft'):
            raise ValueError('Release 已發佈，禁止清理資產')
        for asset in starters:
            endpoint = f'/repos/{REPOSITORY}/releases/assets/'+str(asset['id'])
            current = api.request(endpoint)
            if not current or current.get('state') != 'starter' or current.get('size') != 0 or current.get('name') != asset['name']:
                raise ValueError('失敗資產狀態已改變，停止清理')
            api.request(endpoint,'DELETE')
    for name,data in missing:
        api.request(path+f'/{release_id}/assets?'+urllib.parse.urlencode({'name':name}), 'POST', data, upload=True)
        print('Release 資產已補齊：'+name)
    # 再次從 GitHub 下載核對，套件更新只能在此階段成功後執行。
    verified = api.request(path+f'/{release_id}/assets?per_page=100')
    if {a['name'] for a in verified} != local_names:
        raise ValueError('Release 資產不完整')
    for asset in verified:
        verified_asset((dist/asset['name']).read_bytes(), api.request(f'/repos/{REPOSITORY}/releases/assets/'+str(asset['id']),raw=True))
    if existing.get('draft'):
        api.request(path+f'/{release_id}', 'PATCH', {'draft':False,'make_latest':make_latest(api,tag)})
    print('Release 階段已驗證完成')


def update_packages(api, release_api, dist, tag, commit):
    if version(tag)[1]:
        print('預發佈略過穩定套件')
        return
    existing = release_api.request(f'/repos/{REPOSITORY}/releases/tags/{tag}')
    if not existing or existing.get('draft') or existing.get('prerelease'):
        raise ValueError('正式 Release 尚未成功')
    verify_identity(existing,tag,commit)
    items = archives(dist)
    remote = release_api.request(f'/repos/{REPOSITORY}/releases/{existing["id"]}/assets?per_page=100')
    by_name = {a['name']:a for a in remote}
    for name in [x['name'] for x in items.values()]+['checksums.txt']:
        if name not in by_name:
            raise ValueError('Release 缺少必要資產')
        verified_asset((dist/name).read_bytes(),release_api.request(f'/repos/{REPOSITORY}/releases/assets/{by_name[name]["id"]}',raw=True))
    targets = json.loads(Path('packaging/targets.json').read_text(encoding='utf-8'))
    for value in targets.values():
        destination(value)
    contents = packages(items, tag)
    for kind,path in [('homebrew','Formula/tlscheck.rb'),('scoop','bucket/tlscheck.json')]:
        target = targets[kind]
        endpoint = f'/repos/{target}/contents/{path}'
        old = api.request(endpoint)
        previous = base64.b64decode(old['content']) if old else None
        current = None
        if previous:
            current = 'v'+(json.loads(previous)['version'] if kind=='scoop' else re.search(rb'  version "([^"]+)"',previous)[1].decode())
        action = decision(tag,current,previous == contents[kind])
        print(kind+'：'+action)
        if action == 'update':
            payload = {'message':f'更新 tlscheck 至 {tag}','content':base64.b64encode(contents[kind]).decode()}
            if old:
                payload['sha'] = old['sha']
            # Contents API SHA 條件更新，並行衝突時失敗，不重試覆蓋。
            api.request(endpoint,'PUT',payload)
            print(kind+'：更新成功')


def main():
    parser = argparse.ArgumentParser(description='驗證、套件產生與明確授權的分階段發佈')
    parser.add_argument('stage',choices=['verify','packages','publish','update'])
    parser.add_argument('--dist',type=Path,default=Path('dist'))
    parser.add_argument('--tag')
    parser.add_argument('--execute',action='store_true')
    args = parser.parse_args()
    items = archives(args.dist)
    if args.stage == 'verify':
        print('四目標壓縮檔與 SHA-256 已驗證')
        return
    version(args.tag or '')
    if args.stage == 'packages':
        for name,data in packages(items,args.tag).items():
            output=args.dist/('tlscheck.rb' if name=='homebrew' else 'tlscheck.json')
            output.write_bytes(data)
        print('僅產生本機套件檔案')
        return
    if not args.execute or os.environ.get('RELEASE_APPROVED') != args.tag:
        raise ValueError('遠端寫入需要明確 execute 與指定 tag 核准')
    commit = subprocess.check_output(['git','rev-parse',args.tag+'^{commit}'],text=True,encoding='utf-8').strip()
    head = subprocess.check_output(['git','rev-parse','HEAD'],text=True,encoding='utf-8').strip()
    if not re.fullmatch('[0-9a-f]{40}',commit) or commit != head or subprocess.check_output(['git','status','--porcelain'],text=True,encoding='utf-8').strip():
        raise ValueError('正式發佈需要乾淨且與 tag 相同的來源')
    metadata = json.loads((args.dist/'metadata.json').read_text(encoding='utf-8'))
    if metadata.get('commit') != commit or metadata.get('version') != args.tag[1:]:
        raise ValueError('建置來源與 tag 不一致')
    if args.stage == 'update' and version(args.tag)[1]:
        print('預發佈略過穩定套件，不需要跨 repository 授權')
        return
    api = API(os.environ.get('GH_TOKEN'))
    if args.stage == 'publish':
        publish(api,args.dist,args.tag,commit)
    else:
        update_packages(API(os.environ.get('PACKAGE_REPOSITORY_TOKEN')),api,args.dist,args.tag,commit)

if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as error:
        # 不輸出例外原文，避免底層資料或環境值進入日誌。
        print('發佈階段失敗：請檢查目的地、版本、來源與產物一致性；未完成階段不可視為成功')
        raise SystemExit(1)
