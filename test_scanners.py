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
    def test_owned_rules_detect_vulnerable_cases_and_leave_safe_cases_unflagged(self):
        import re
        with tempfile.TemporaryDirectory(prefix='preflyt-owned-cases-') as directory:
            root = Path(directory)
            expected = set()
            safe = set()
            for fixture in Path(__file__).parent.joinpath('rules', 'tests').iterdir():
                target = root / fixture.name
                target.write_bytes(fixture.read_bytes())
                for number, line in enumerate(target.read_text().splitlines(), start=1):
                    match = re.search(r'(ruleid|ok): ([a-z0-9-]+)', line)
                    if match:
                        (expected if match[1] == 'ruleid' else safe).add((fixture.name, number + 1, match[2]))
            env = {**os.environ, 'GITHUB_WORKSPACE': directory, 'RUNNER_TEMP': directory}
            result = subprocess.run([sys.executable, str(Path(__file__).with_name('recipes.py')), 'security.sast', 'output/report.sarif'], cwd=root, env=env, timeout=480)
            self.assertEqual(result.returncode, 0)
            data = json.loads(root.joinpath('output/report.sarif').read_text())
            found = {(Path(item['locations'][0]['physicalLocation']['artifactLocation']['uri']).name,
                      item['locations'][0]['physicalLocation']['region']['startLine'], item['ruleId'])
                     for scan in data['runs'] for item in scan['results']}
            self.assertEqual(found, expected)
            self.assertTrue(found.isdisjoint(safe))
            self.assertEqual(len({case[2] for case in expected}), 18)
            self.assertEqual(report_result('sarif', json.dumps(data)), 'failed')
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
            def partial(*args, **kwargs):
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
