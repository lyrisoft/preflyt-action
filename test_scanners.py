import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from recipes import compact_sarif
from run import report_result, MAX_REPORT


class SarifCompactionTests(unittest.TestCase):
    def test_preserves_every_finding_invocation_and_referenced_rule(self):
        findings = [{'ruleId': 'unsafe', 'ruleIndex': 1, 'level': 'error', 'message': {'text': 'actual issue'}}]
        invocation = [{'executionSuccessful': True, 'toolExecutionNotifications': [{'message': {'text': 'diagnostic'}}]}]
        report = {'runs': [{'tool': {'driver': {'rules': [{'id': 'unused'}, {'id': 'unsafe', 'defaultConfiguration': {'level': 'error'}}]}}, 'results': findings, 'invocations': invocation}]}
        compact_sarif(report)
        run = report['runs'][0]
        self.assertEqual(run['tool']['driver']['rules'][0]['id'], 'unsafe')
        self.assertEqual(run['results'][0]['ruleIndex'], 0)
        self.assertEqual(run['results'][0]['message']['text'], 'actual issue')
        self.assertEqual(run['invocations'], invocation)


@unittest.skipUnless(os.environ.get('PREFLYT_SCANNER_SMOKE') == '1', 'Opt-in real Docker scanners')
class RealScannerTests(unittest.TestCase):
    def test_real_tools_produce_bounded_reports_and_actual_findings(self):
        with tempfile.TemporaryDirectory(prefix='preflyt-scanner-fixture-') as directory:
            root = Path(directory)
            (root / 'app.py').write_text('print("hello")\n')
            (root / 'package-lock.json').write_text(json.dumps({'name': 'fixture', 'version': '1.0.0', 'lockfileVersion': 3, 'packages': {'': {'name': 'fixture', 'version': '1.0.0'}}}))
            (root / 'Dockerfile').write_text('FROM alpine:3.20\nUSER root\n')
            env = {**os.environ, 'GITHUB_WORKSPACE': directory, 'RUNNER_TEMP': directory}
            for check in ['secrets.scan', 'security.dependencies', 'iac.policy', 'security.sast']:
                with self.subTest(check=check):
                    report = f'reports/{check}.sarif'
                    process = subprocess.run([sys.executable, str(Path(__file__).with_name('recipes.py')), check, report], cwd=root, env=env, capture_output=True, timeout=480)
                    self.assertEqual(process.returncode, 0, check)
                    content = (root / report).read_text()
                    self.assertLessEqual(len(content.encode()), MAX_REPORT, check)
                    result = report_result('sarif', content)
                    self.assertIn(result, ['passed', 'failed'])
                    if check in ['secrets.scan', 'security.dependencies']:
                        self.assertEqual(result, 'passed')
                    if check == 'iac.policy':
                        self.assertEqual(result, 'failed')

class PartialScannerTests(unittest.TestCase):
    def test_partial_scan_keeps_findings_and_compacts_rules_without_claiming_success(self):
        from unittest.mock import patch
        import recipes
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'partial.sarif'
            def partial(*args):
                path.write_text(json.dumps({'version': '2.1.0', 'runs': [{'tool': {'driver': {'name': 'Semgrep', 'rules': [{'id': 'unused', 'help': {'text': 'x' * 300000}}, {'id': 'issue'}]}}, 'invocations': [{'executionSuccessful': True, 'toolExecutionNotifications': [{'level': 'error', 'message': {'text': 'Parser error'}}]}], 'results': [{'ruleId': 'issue', 'ruleIndex': 1, 'level': 'warning', 'message': {'text': 'Actual finding'}}]}]}))
                return 3
            with patch.object(recipes, 'scan', side_effect=partial):
                self.assertEqual(recipes.main('security.sast', str(path)), 78)
            content = path.read_text()
            self.assertLess(len(content.encode()), MAX_REPORT)
            data = json.loads(content)['runs'][0]
            self.assertEqual(len(data['results']), 1)
            self.assertEqual(data['results'][0]['message']['text'], 'Actual finding')
            self.assertFalse(data['invocations'][0]['executionSuccessful'])
            self.assertEqual(len(data['invocations'][0]['toolExecutionNotifications']), 1)
            self.assertEqual(report_result('sarif', content), 'incomplete')
