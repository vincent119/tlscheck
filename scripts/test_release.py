import unittest
import release

class ReleaseTests(unittest.TestCase):
    def test_versions_and_retry_policy(self):
        self.assertEqual(release.decision('v1.0.0', 'v1.0.0', True), 'unchanged')
        self.assertEqual(release.decision('v1.0.0', 'v2.0.0', False), 'skip')
        self.assertEqual(release.decision('v1.0.0-rc.1', 'v0.9.0', False), 'skip')
        self.assertEqual(release.decision('v1.1.0', 'v1.0.0', False), 'update')
        with self.assertRaises(ValueError):
            release.decision('v1.0.0', 'v1.0.0', False)
        for value in ['v1.0', '1.0.0', 'v01.0.0', 'v1.0.0/evil']:
            with self.assertRaises(ValueError):
                release.version(value)

    def test_destinations_fail_closed(self):
        for value in ['TAP_OWNER/TAP_REPOSITORY', '', 'a/b/c', 'a/../b']:
            with self.assertRaises(ValueError):
                release.destination(value)

    def test_release_assets_are_immutable(self):
        self.assertEqual(release.asset_action(b'abc', None), 'upload')
        self.assertEqual(release.asset_action(b'abc', b'abc'), 'unchanged')
        with self.assertRaises(ValueError):
            release.asset_action(b'abc', b'changed')

    def test_release_commit_is_pinned(self):
        release.verify_identity({'tag_name':'v1.0.0','body':'tlscheck source: '+('a'*40)}, 'v1.0.0', 'a'*40)
        with self.assertRaises(ValueError):
            release.verify_identity({'tag_name':'v1.0.0','body':'unknown'}, 'v1.0.0', 'a'*40)


import base64
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import zipfile
from unittest.mock import patch

class FakeAPI:
    def __init__(self):
        self.release = None
        self.assets = {}
        self.contents = {}
        self.writes = []
        self.fail_name = None
        self.latest = None

    def request(self, path, method='GET', data=None, raw=False, upload=False):
        self.writes.extend([(method,path)] if method != 'GET' else [])
        if '/contents/' in path:
            if method == 'GET':
                return self.contents.get(path)
            old = self.contents.get(path)
            if old and data.get('sha') != old['sha']:
                raise ValueError('並行衝突')
            self.contents[path] = {'content':data['content'],'sha':hashlib.sha256(data['content'].encode()).hexdigest()}
            return self.contents[path]
        if '/assets/' in path:
            identifier=int(path.rsplit('/',1)[1])
            if method=='DELETE':
                del self.assets[identifier]
                return None
            return self.assets[identifier]['data'] if raw else self.assets[identifier]
        if '/assets?' in path and method == 'POST':
            name = release.urllib.parse.parse_qs(release.urllib.parse.urlparse(path).query)['name'][0]
            if name == self.fail_name:
                raise ValueError('合成上傳失敗')
            if any(a['name']==name for a in self.assets.values()):
                raise ValueError('禁止重複上傳')
            identifier=max(self.assets,default=0)+1
            self.assets[identifier]={'id':identifier,'name':name,'data':data,'state':'uploaded','size':len(data)}
            return self.assets[identifier]
        if '/assets?' in path:
            return list(self.assets.values())
        if path.endswith('/releases/latest'):
            return self.latest
        if '/tags/' in path:
            return self.release if self.release and not self.release.get('draft') else None
        if '/releases?' in path:
            return [self.release] if self.release else []
        if method == 'POST':
            if self.release:
                raise ValueError('不應重複建立 Release')
            self.release = dict(data,id=1)
        elif method == 'PATCH':
            self.release.update(data)
        return self.release

class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.dist=Path(self.temp.name)
        self.tag='v1.0.0'
        self.commit='a'*40
        lines=[]
        for system in ['darwin','windows']:
            for arch in ['amd64','arm64']:
                suffix='zip' if system=='windows' else 'tar.gz'
                name=f'tlscheck_1.0.0_{system}_{arch}.{suffix}'
                path=self.dist/name
                files={x:Path(x).read_bytes() for x in release.REQUIRED}
                files['tlscheck.exe' if system=='windows' else 'tlscheck']=b'synthetic executable'
                if system=='windows':
                    with zipfile.ZipFile(path,'w') as archive:
                        for filename,data in files.items():
                            archive.writestr(filename,data)
                else:
                    with tarfile.open(path,'w:gz') as archive:
                        for filename,data in files.items():
                            info=tarfile.TarInfo(filename);info.size=len(data)
                            archive.addfile(info,io.BytesIO(data))
                lines.append(release.digest(path.read_bytes())+'  '+name)
        (self.dist/'checksums.txt').write_text('\n'.join(lines)+'\n',encoding='utf-8')

    def test_archives_and_packages(self):
        items=release.archives(self.dist)
        built=release.packages(items,self.tag)
        manifest=json.loads(built['scoop'])
        self.assertEqual(set(manifest['architecture']),{'64bit','arm64'})
        self.assertEqual(manifest['bin'],'tlscheck.exe')
        self.assertIn(b'Apache-2.0',built['homebrew'])
        self.assertNotIn(b'config.json',built['homebrew'])
        file=self.dist/items[('darwin','arm64')]['name']
        file.write_bytes(b'changed')
        with self.assertRaises(ValueError):
            release.archives(self.dist)

    def test_partial_upload_then_retry_is_idempotent(self):
        api=FakeAPI();api.fail_name='tlscheck_1.0.0_windows_amd64.zip'
        with self.assertRaises(ValueError):
            release.publish(api,self.dist,self.tag,self.commit)
        self.assertTrue(api.release['draft'])
        count=len(api.assets)
        self.assertGreater(count,0)
        api.fail_name=None
        release.publish(api,self.dist,self.tag,self.commit)
        self.assertFalse(api.release['draft'])
        self.assertEqual(len(api.assets),5)
        writes=len(api.writes)
        release.publish(api,self.dist,self.tag,self.commit)
        self.assertEqual(len(api.writes),writes)
        next(iter(api.assets.values()))['data']=b'changed'
        with self.assertRaises(ValueError):
            release.publish(api,self.dist,self.tag,self.commit)
        self.assertEqual(len(api.writes),writes)

    def test_disappearing_asset_prevents_publication(self):
        api=FakeAPI()
        original=api.request
        def disappearing(path, method='GET', data=None, raw=False, upload=False):
            if raw:
                return None
            return original(path,method,data,raw,upload)
        api.request=disappearing
        with self.assertRaises(ValueError):
            release.publish(api,self.dist,self.tag,self.commit)
        self.assertTrue(api.release['draft'])

    def test_packages_only_after_release_and_retry(self):
        repo=FakeAPI();api=FakeAPI()
        with self.assertRaises(ValueError):
            release.update_packages(api,repo,self.dist,self.tag,self.commit)
        release.publish(repo,self.dist,self.tag,self.commit)
        release.update_packages(api,repo,self.dist,self.tag,self.commit)
        self.assertEqual(len(api.contents),2)
        writes=len(api.writes)
        release.update_packages(api,repo,self.dist,self.tag,self.commit)
        self.assertEqual(len(api.writes),writes)
        release.update_packages(api,repo,self.dist,'v1.1.0-rc.1',self.commit)
        self.assertEqual(len(api.writes),writes)

    def test_publish_without_approval_never_calls_api(self):
        with patch('sys.argv',['release.py','publish','--dist',str(self.dist),'--tag',self.tag]), patch.object(release,'API') as api:
            with self.assertRaises(ValueError):
                release.main()
            api.assert_not_called()

    def test_snapshot_cannot_use_stable_package_version(self):
        items=release.archives(self.dist)
        for item in items.values():
            item['version']='0.0.0-snapshot-synthetic-dirty'
        with self.assertRaises(ValueError):
            release.packages(items,'v1.0.0')

    def test_second_package_failure_resumes_without_duplicate_first_update(self):
        repo=FakeAPI();api=FakeAPI()
        release.publish(repo,self.dist,self.tag,self.commit)
        original=api.request
        failed=[False]
        def partial(path,method='GET',data=None,raw=False,upload=False):
            if method=='PUT' and 'scoop-bucket' in path and not failed[0]:
                failed[0]=True
                raise ValueError('合成第二套件階段失敗')
            return original(path,method,data,raw,upload)
        api.request=partial
        with self.assertRaises(ValueError):
            release.update_packages(api,repo,self.dist,self.tag,self.commit)
        self.assertEqual(len(api.contents),1)
        release.update_packages(api,repo,self.dist,self.tag,self.commit)
        self.assertEqual(len(api.contents),2)
        self.assertEqual(len(api.writes),2)

    def test_draft_starter_is_recovered_but_published_conflict_is_not_deleted(self):
        api=FakeAPI()
        api.release={'id':1,'tag_name':self.tag,'body':'tlscheck source: '+self.commit,'draft':True}
        api.assets[1]={'id':1,'name':'checksums.txt','data':b'','state':'starter','size':0}
        release.publish(api,self.dist,self.tag,self.commit)
        self.assertFalse(api.release['draft'])
        self.assertIn(('DELETE','/repos/'+release.REPOSITORY+'/releases/assets/1'),api.writes)
        api.assets[1]={'id':1,'name':'checksums.txt','data':b'','state':'starter','size':0}
        before=len(api.writes)
        with self.assertRaises(ValueError):
            release.publish(api,self.dist,self.tag,self.commit)
        self.assertEqual(len(api.writes),before)

    def test_old_release_does_not_replace_latest(self):
        api=FakeAPI();api.latest={'tag_name':'v2.0.0','draft':False,'prerelease':False}
        release.publish(api,self.dist,self.tag,self.commit)
        self.assertEqual(api.release['make_latest'],'false')

    def test_new_release_explicitly_becomes_latest(self):
        api=FakeAPI();api.latest={'tag_name':'v0.9.0','draft':False,'prerelease':False}
        release.publish(api,self.dist,self.tag,self.commit)
        self.assertEqual(api.release['make_latest'],'true')

    def test_queue_compatibility_rejects_invalid_queue_and_other_errors(self):
        import lint_workflows
        text=Path('.github/workflows/release.yml').read_text(encoding='utf-8')
        line=next(i for i,s in enumerate(text.splitlines(),1) if s=='  queue: max')
        diagnostic={'filepath':'.github/workflows/release.yml','line':line,'column':3,'kind':'syntax-check','message':lint_workflows.QUEUE_MESSAGE}
        self.assertEqual(lint_workflows.remaining_errors(text,[diagnostic]),[])
        other=dict(diagnostic,message='其他錯誤')
        self.assertEqual(lint_workflows.remaining_errors(text,[other]),[other])
        with self.assertRaises(ValueError):
            lint_workflows.remaining_errors(text.replace('queue: max','queue: single'),[diagnostic])
        with self.assertRaises(ValueError):
            lint_workflows.remaining_errors(text.replace('cancel-in-progress: false','cancel-in-progress: true'),[diagnostic])

    def test_release_workflow_preserves_pending_runs(self):
        text=Path('.github/workflows/release.yml').read_text(encoding='utf-8')
        block=text.split('concurrency:',1)[1].split('jobs:',1)[0]
        self.assertIn('queue: max',block)
        self.assertIn('cancel-in-progress: false',block)

    def test_release_lookup_paginates_and_rejects_duplicate_tags(self):
        first=[{'id':i,'tag_name':'v0.0.1'} for i in range(100)]
        wanted={'id':101,'tag_name':self.tag,'draft':True}
        class Pages:
            def request(self,path):
                return first if path.endswith('page=1') else [wanted]
        self.assertEqual(release.find_release(Pages(),self.tag),wanted)
        first[0]={'id':0,'tag_name':self.tag,'draft':False}
        with self.assertRaises(ValueError):
            release.find_release(Pages(),self.tag)

    def test_conflicting_draft_is_not_modified(self):
        api=FakeAPI();api.release={'id':1,'tag_name':self.tag,'body':'unconfirmed','draft':True}
        with self.assertRaises(ValueError):
            release.publish(api,self.dist,self.tag,self.commit)
        self.assertEqual(api.writes,[])

    def test_nonempty_starter_is_not_deleted(self):
        api=FakeAPI();api.release={'id':1,'tag_name':self.tag,'body':'tlscheck source: '+self.commit,'draft':True}
        api.assets[1]={'id':1,'name':'checksums.txt','data':b'x','state':'starter','size':1}
        with self.assertRaises(ValueError):
            release.publish(api,self.dist,self.tag,self.commit)
        self.assertEqual(api.writes,[])

    def test_prerelease_never_changes_latest(self):
        api=FakeAPI()
        self.assertEqual(release.make_latest(api,'v3.0.0-rc.1'),'false')
        self.assertEqual(api.writes,[])

    def test_redirect_does_not_forward_credentials(self):
        request=release.urllib.request.Request('https://api.github.com/asset',headers={'Authorization':'Bearer synthetic'})
        redirected=release.SafeRedirect().redirect_request(request,None,302,'',{},'https://example.com/asset')
        self.assertIsNone(redirected.get_header('Authorization'))

if __name__ == '__main__':
    unittest.main()
