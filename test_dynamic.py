"""Execute successive published policies against a disposable exact-commit checkout."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import run as runner
import tools


class DynamicPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)
        (self.root / 'source.txt').write_text('tracked source')
        subprocess.run(['git', '-C', str(self.root), 'add', 'source.txt'], check=True)
        subprocess.run(['git', '-C', str(self.root), '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'fixture'], check=True)
        self.sha = subprocess.check_output(['git', '-C', str(self.root), 'rev-parse', 'HEAD'], text=True).strip()
        self.env = {**os.environ, 'GITHUB_WORKSPACE': str(self.root), 'GITHUB_SHA': self.sha,
                    'GITHUB_REPOSITORY_ID': '1', 'GITHUB_RUN_ID': '2', 'GITHUB_RUN_ATTEMPT': '1',
                    'GITHUB_WORKFLOW_REF': 'fixture/project/.github/workflows/ci.yml@refs/pull/1/merge',
                    'RUNNER_TEMP': str(self.root), 'GITHUB_OUTPUT': str(self.root / 'outputs'),
                    'GITHUB_STEP_SUMMARY': str(self.root / 'summary'), 'PREFLYT_POLICY_PATH': str(self.root / 'policy.json')}

    def policy(self, checks):
        return {'schemaVersion': 1, 'executionVersion': 1, 'state': 'PUBLISHED',
                'sourceSha': self.sha, 'headSha': self.sha, 'repositoryId': '1',
                'id': 'approved-policy', 'definitionHash': 'approved-hash', 'checks': checks}

    def execute(self, checks, **changes):
        policy = {**self.policy(checks), **changes}
        (self.root / 'policy.json').write_text(json.dumps(policy))
        (self.root / 'outputs').write_text('')
        result = subprocess.run([sys.executable, str(Path(runner.__file__).resolve())], env=self.env,
                                cwd=self.root, capture_output=True, text=True)
        outputs = dict(line.split('=', 1) for line in (self.root / 'outputs').read_text().splitlines())
        bundle = json.loads(Path(outputs['bundle']).read_text()) if 'bundle' in outputs else None
        return result, outputs, bundle

    def check(self, code=0, report='reports/build.xml'):
        return {'id': 'build.required', 'title': 'Build', 'required': True,
                'execution': {'report': report, 'argv': [sys.executable, '-c', f'raise SystemExit({code})']}}

    def test_policy_changes_run_new_commands_without_workflow_inputs(self):
        result, outputs, bundle = self.execute([self.check()])
        self.assertEqual(result.returncode, 0)
        self.assertEqual(outputs['result'], 'passed')
        self.assertEqual(bundle['headSha'], self.sha)
        _, outputs, bundle = self.execute([self.check(1)])
        self.assertEqual(outputs['result'], 'failed')
        self.assertIn('<failure', bundle['reports'][0]['content'])
        # A newly added required check with no approved command blocks this same bootstrap.
        _, outputs, bundle = self.execute([self.check(), {'id': 'frontend.components', 'title': 'Components', 'required': True, 'execution': None}])
        self.assertEqual(outputs['result'], 'incomplete')
        self.assertEqual(bundle['results'][1]['status'], 'incomplete')

    def test_custom_report_is_generated_by_the_approved_command(self):
        rule = {'id': 'custom-junit-fixture', 'title': 'Contract tests', 'required': True,
                'execution': {'report': 'reports/contract.xml', 'argv': [sys.executable, '-c',
                    "from pathlib import Path; p=Path('reports/contract.xml'); p.parent.mkdir(exist_ok=True); p.write_text('<testsuite><testcase name=\"contract\"/></testsuite>')"]}}
        _, outputs, bundle = self.execute([rule])
        self.assertEqual(outputs['result'], 'passed')
        self.assertEqual(bundle['reports'][0]['ruleId'], rule['id'])
        rule['execution']['argv'] = [sys.executable, '-c', 'pass']
        _, outputs, _ = self.execute([rule])
        self.assertEqual(outputs['result'], 'incomplete')  # Old passing report removed.

    def test_never_uses_explicit_report_mappings_or_tracked_output(self):
        check = self.check()
        check['execution'].pop('argv')
        result, outputs, _ = self.execute([check])
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(outputs)
        result, _, _ = self.execute([self.check(report='source.txt')])
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.root / 'source.txt').read_text(), 'tracked source')

    def test_rejects_wrong_commit_execution_version_and_escaping_reports(self):
        for changes in [{'headSha': 'a' * 40}, {'sourceSha': 'b' * 40}, {'executionVersion': 2}, {'repositoryId': '999'}]:
            result, outputs, _ = self.execute([self.check()], **changes)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(outputs)
        for path in ['../outside.xml', '/tmp/out.xml', '', 'reports\\out.xml']:
            result, _, _ = self.execute([self.check(report=path)])
            self.assertNotEqual(result.returncode, 0)

    def test_rejects_duplicate_paths_and_mismatched_recipe(self):
        rule = {'id': 'types.required', 'title': 'Types', 'required': True, 'execution': self.check()['execution']}
        result, _, _ = self.execute([self.check(), rule])
        self.assertNotEqual(result.returncode, 0)
        rule['execution'] = {'report': 'reports/types.xml', 'argv': ['preflyt-recipe', 'build.required', 'reports/types.xml']}
        result, _, _ = self.execute([rule])
        self.assertNotEqual(result.returncode, 0)


class ManagedScannerTests(unittest.TestCase):
    def test_pulls_only_pinned_images_without_credentials_and_mounts_no_socket(self):
        with tempfile.TemporaryDirectory() as root, patch.dict(os.environ, {'GITHUB_WORKSPACE': root, 'RUNNER_TEMP': root,
                'GITHUB_TOKEN': 'fixture-secret', 'ACTIONS_ID_TOKEN_REQUEST_TOKEN': 'fixture-secret'}, clear=False), \
                patch.object(tools.shutil, 'which', return_value='/usr/bin/docker'), patch.object(tools.subprocess, 'run') as run:
            run.return_value.returncode = 0
            self.assertEqual(tools.scan('gitleaks', ['dir', '.'], 'reports/scan.sarif'), 0)
            pull, invocation = [call.args[0] for call in run.call_args_list]
            self.assertEqual(pull[-1], tools.IMAGES['gitleaks'])
            for flag in ['--read-only', '--cap-drop', '--security-opt', '--network', '--user']:
                self.assertIn(flag, invocation)
            self.assertIn('none', invocation)
            self.assertNotIn('docker.sock', ' '.join(invocation))
            for call in run.call_args_list:
                self.assertNotIn('GITHUB_TOKEN', call.kwargs['env'])
                self.assertNotIn('ACTIONS_ID_TOKEN_REQUEST_TOKEN', call.kwargs['env'])
                self.assertEqual(call.kwargs['stdout'], subprocess.DEVNULL)

    def test_failed_install_unknown_tool_and_mount_injection_are_incomplete(self):
        with tempfile.TemporaryDirectory() as root, patch.dict(os.environ, {'GITHUB_WORKSPACE': root}), \
                patch.object(tools.shutil, 'which', return_value='/usr/bin/docker'), patch.object(tools.subprocess, 'run') as run:
            run.return_value.returncode = 1
            self.assertEqual(tools.scan('gitleaks', [], 'scan.sarif'), 78)
            self.assertEqual(tools.scan('unknown', [], 'other.sarif'), 78)
            self.assertEqual(tools.scan('gitleaks', [], 'file,readonly.sarif'), 78)
            self.assertEqual(run.call_count, 1)


if __name__ == '__main__':
    unittest.main()
