import os
from pathlib import Path
import subprocess
import unittest


class CollectionResultTests(unittest.TestCase):
    def test_collection_reports_negative_results_without_bypassing_final_gate(self):
        action = Path(__file__).with_name('action.yml').read_text()
        section = action.split('    - name: Record policy result\n')[1].split('    - name:')[0]
        script = '\n'.join(line[8:] for line in section.split('      run: |\n')[1].splitlines())
        for result in ('passed', 'failed', 'incomplete'):
            with self.subTest(result=result):
                code = subprocess.run(['bash', '-e', '-c', script], env={**os.environ, 'PREFLYT_RESULT': result}, capture_output=True).returncode
                self.assertEqual(code, 0)
        for result in ('', 'unrecognized'):
            code = subprocess.run(['bash', '-e', '-c', script], env={**os.environ, 'PREFLYT_RESULT': result}, capture_output=True).returncode
            self.assertNotEqual(code, 0)
        self.assertIn('run: python3 "$PREFLYT_ACTION_PATH/transport.py" gate', action)
