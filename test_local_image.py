"""A workflow-built image crosses scanner isolation as a read-only archive."""
import os
import json
import uuid
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import tools


class LocalImageTests(unittest.TestCase):
    def invoke(self, *, local=True, saved=0, empty=False, timeout=False):
        calls = []
        def run(argv, **kwargs):
            calls.append((argv, kwargs))
            code = 0
            if argv[1:3] == ['image', 'inspect']:
                code = 0 if local else 1
            if argv[1:3] == ['image', 'save']:
                if timeout:
                    raise subprocess.TimeoutExpired(argv, 180)
                Path(argv[4]).write_bytes(b'' if empty else b'fixture Docker archive')
                code = saved
            return subprocess.CompletedProcess(argv, code)
        with tempfile.TemporaryDirectory() as root, patch.dict(os.environ, {
                'GITHUB_WORKSPACE': root, 'RUNNER_TEMP': root,
                'GITHUB_TOKEN': 'never-forward', 'ACTIONS_ID_TOKEN_REQUEST_TOKEN': 'never-forward'}), \
                patch.object(tools.shutil, 'which', return_value='/usr/bin/docker'), \
                patch.object(tools.subprocess, 'run', side_effect=run):
            code = tools.scan('trivy', ['image', '--scanners', 'vuln', '--format', 'sarif', 'preflyt-pr:commit'], 'reports/image.sarif')
        return code, calls

    def test_local_image_is_exported_and_mounted_readonly_without_daemon_access(self):
        code, calls = self.invoke()
        self.assertEqual(code, 0)
        commands = [args for args, _ in calls]
        self.assertEqual(commands[1][1:3], ['image', 'inspect'])
        self.assertEqual(commands[2][1:3], ['image', 'save'])
        scanner = commands[-1]
        self.assertIn('--input', scanner)
        self.assertEqual(scanner[-1], '/preflyt-image.tar')
        self.assertNotIn('preflyt-pr:commit', scanner)
        self.assertNotIn('docker.sock', ' '.join(scanner))
        archive = commands[2][4]
        self.assertIn(f'type=bind,src={archive},dst=/preflyt-image.tar,readonly', scanner)
        cache_mount = next(arg for arg in scanner if arg.endswith('dst=/cache'))
        self.assertNotIn(str(Path(archive).parent) + ',dst=/cache', cache_mount)
        self.assertFalse(Path(archive).exists())
        for _, options in calls:
            self.assertNotIn('GITHUB_TOKEN', options['env'])
            self.assertNotIn('ACTIONS_ID_TOKEN_REQUEST_TOKEN', options['env'])

    def test_remote_image_keeps_the_existing_registry_scan(self):
        code, calls = self.invoke(local=False)
        self.assertEqual(code, 0)
        self.assertEqual(calls[-1][0][-1], 'preflyt-pr:commit')
        self.assertNotIn('--input', calls[-1][0])
        self.assertFalse(any(args[1:3] == ['image', 'save'] for args, _ in calls))

    def test_export_errors_empty_archives_and_timeouts_stay_incomplete(self):
        for changes in [{'saved': 1}, {'empty': True}, {'timeout': True}]:
            code, calls = self.invoke(**changes)
            self.assertEqual(code, 78)
            self.assertFalse(any(args[1] == 'run' for args, _ in calls))

    def test_image_references_cannot_inject_scanner_flags(self):
        with tempfile.TemporaryDirectory() as root, patch.dict(os.environ, {'GITHUB_WORKSPACE': root}), \
                patch.object(tools.shutil, 'which', return_value='/usr/bin/docker'), \
                patch.object(tools.subprocess, 'run') as run:
            run.return_value.returncode = 0
            for image in ['--input=/host/file.tar', 'image\nother', 'x' * 513]:
                self.assertEqual(tools.scan('trivy', ['image', image], f'{len(image)}.sarif'), 78)
            self.assertTrue(all(args.args[0][1] == 'pull' for args in run.call_args_list))


@unittest.skipUnless(os.environ.get('PREFLYT_SCANNER_SMOKE') == '1', 'Opt-in real Docker scanners')
class RealLocalImageTests(unittest.TestCase):
    def test_runner_built_image_produces_genuine_sarif_through_archive(self):
        import recipes
        from run import report_result
        tag = 'preflyt-local-image-test:' + uuid.uuid4().hex
        env = tools.clean_environment()
        try:
            with tempfile.TemporaryDirectory(prefix='preflyt-image-fixture-') as directory:
                root = Path(directory).resolve()
                (root / 'Dockerfile').write_text('FROM scratch\nCOPY package-lock.json /app/package-lock.json\n')
                (root / 'package-lock.json').write_text(json.dumps({
                    'name': 'fixture', 'version': '1.0.0', 'lockfileVersion': 3,
                    'packages': {'': {'name': 'fixture', 'version': '1.0.0'}}}))
                subprocess.run(['docker', 'build', '--platform', 'linux/amd64', '--network', 'none',
                                '--tag', tag, directory], env=env, check=True, timeout=120,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                report = root / 'reports/image.sarif'
                with patch.dict(os.environ, {'GITHUB_WORKSPACE': directory, 'RUNNER_TEMP': directory,
                                              'CONTAINER_IMAGE': tag}), \
                        patch.object(tools.subprocess, 'run', wraps=subprocess.run) as commands:
                    self.assertEqual(recipes.main('containers.scan', str(report)), 0)
                args = [call.args[0] for call in commands.call_args_list]
                self.assertTrue(any(command[1:3] == ['image', 'save'] for command in args))
                self.assertTrue(any('--input' in command and '/preflyt-image.tar' in command for command in args))
                content = report.read_text()
                self.assertEqual(json.loads(content)['version'], '2.1.0')
                self.assertEqual(report_result('sarif', content), 'passed')
        finally:
            subprocess.run(['docker', 'image', 'rm', tag], env=env, check=False, timeout=30,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == '__main__':
    unittest.main()
