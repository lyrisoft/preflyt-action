import base64
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch, MagicMock

spec = importlib.util.spec_from_file_location('preflyt_coverage', Path(__file__).with_name('coverage.py'))
cov = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cov)
LCOV = b'SF:src/app.ts\nDA:1,1\nDA:2,0\nLF:2\nLH:1\nend_of_record\n'

class CoverageTests(unittest.TestCase):
    def test_namespaces_packages_and_unions_only_matching_physical_lines(self):
        result = cov.merge_lcov([(LCOV,'apps/api'),(LCOV,'apps/web')],Path('/repo')).decode()
        self.assertIn('SF:apps/api/src/app.ts',result)
        self.assertIn('SF:apps/web/src/app.ts',result)
        self.assertEqual(result.count('LF:2'),2)
        union = cov.merge_lcov([(LCOV,'apps/api'),(LCOV.replace(b'DA:2,0',b'DA:2,1').replace(b'LH:1',b'LH:2'),'apps/api')],Path('/repo'))
        self.assertEqual(union.count(b'SF:'),1)
        self.assertIn(b'LH:2',union)
        normalized = cov.merge_lcov([(LCOV,'apps/api'),(LCOV.replace(b'src/app.ts',b'src/./app.ts'),'apps/api')],Path('/repo'))
        self.assertEqual(normalized.count(b'SF:'),1)
    def test_rejects_malformed_counters_and_paths_without_fabricating_coverage(self):
        for raw in [LCOV.replace(b'LF:2',b'LF:3'),LCOV.replace(b'LH:1',b'LH:2'),LCOV.replace(b'end_of_record',b''),
                    LCOV.replace(b'src/app.ts',b'../outside'),LCOV.replace(b'DA:2,0',b'DA:1,0'),
                    LCOV.replace(b'DA:2,0',b'DA:2,-1'),LCOV.replace(b'src/app.ts',b'/outside/app.ts')]:
            with self.subTest(raw=raw),self.assertRaises((ValueError,UnicodeError)):
                cov.merge_lcov([(raw,'apps/api')],Path('/repo'))
        zero=b'SF:types.ts\nLF:0\nLH:0\nend_of_record\n'
        self.assertEqual(cov.merge_lcov([(LCOV+zero,'apps/api')],Path('/repo')),cov.merge_lcov([(LCOV,'apps/api')],Path('/repo')))
    def fixture(self,root):
        web=root/'web.info'; web.write_bytes(LCOV)
        artifact=root/'artifact';artifact.mkdir()
        (artifact/'lcov.info').write_bytes(LCOV)
        metadata={'version':1,'repositoryId':'51','sourceSha':'a'*40,'runId':'12','runAttempt':2,
                  'prefix':'apps/api','sha256':hashlib.sha256(LCOV).hexdigest()}
        (artifact/'metadata.json').write_text(json.dumps(metadata))
        bundle={'headSha':'a'*40,'sourceSha':'b'*40,'repositoryId':'51','runId':'12','runAttempt':2,
                'results':[{'ruleId':'frontend.components','status':'passed','required':True}], 'reports':[]}
        path=root/'bundle.json';path.write_text(json.dumps(bundle))
        return path,web,artifact,metadata,bundle
    def test_attaches_original_digest_compressed_bytes_without_changing_verdict(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);path,web,artifact,_,bundle=self.fixture(root)
            cov.attach(path,[{'path':'web.info','prefix':'apps/web'}],artifact,time.time()-1,root)
            saved=json.loads(path.read_text());report=saved['reports'][0]
            raw=gzip.decompress(base64.b64decode(report['content']))
            self.assertEqual(report['sha256'],hashlib.sha256(raw).hexdigest())
            self.assertEqual(report['format'],'lcov');self.assertEqual(report['ruleId'],'tests.coverage')
            self.assertEqual(saved['results'],bundle['results'])
            self.assertEqual(raw.count(b'SF:'),2)
    def test_stale_wrong_attempt_corrupt_and_failed_reports_leave_bundle_unchanged(self):
        for change in ['stale','attempt','source','hash','failed','missing','duplicate']:
            with self.subTest(change=change),tempfile.TemporaryDirectory() as d:
                root=Path(d);path,web,artifact,metadata,bundle=self.fixture(root)
                if change=='stale':os.utime(web,(1,1))
                if change=='attempt':metadata['runAttempt']=1
                if change=='source':metadata['sourceSha']='c'*40
                if change=='hash':metadata['sha256']='0'*64
                if change=='missing':web.unlink()
                if change=='failed':bundle['results'][0]['status']='failed'
                if change=='duplicate':bundle['reports']=[{'ruleId':'tests.coverage'}]
                (artifact/'metadata.json').write_text(json.dumps(metadata));path.write_text(json.dumps(bundle))
                before=path.read_bytes()
                with self.assertRaises((ValueError,OSError)):
                    cov.attach(path,[{'path':'web.info','prefix':'apps/web'}],artifact,time.time()-1,root)
                self.assertEqual(path.read_bytes(),before)
    def test_artifact_lookup_binds_exact_run_and_never_exposes_the_read_token(self):
        with tempfile.TemporaryDirectory() as d:
            env={'GITHUB_REPOSITORY':'org/repo','GITHUB_RUN_ID':'12','GITHUB_RUN_ATTEMPT':'2',
                 'PREFLYT_COVERAGE_TOKEN':'fixture-token','GITHUB_OUTPUT':str(Path(d)/'out')}
            response=MagicMock();response.__enter__.return_value=response
            response.read.return_value=json.dumps({'total_count':1,'artifacts':[{'name':'api-12-2','id':44,'size_in_bytes':100,
                                                        'expired':False,'workflow_run':{'id':12}}]}).encode()
            with patch('urllib.request.urlopen',return_value=response) as request:
                cov.wait_for_artifact('api-12-2',env)
            self.assertEqual((Path(d)/'out').read_text(),'artifact-id=44\n')
            self.assertEqual(request.call_args.args[0].full_url,'https://api.github.com/repos/org/repo/actions/runs/12/artifacts?per_page=100')
            self.assertNotIn('fixture-token',(Path(d)/'out').read_text())
