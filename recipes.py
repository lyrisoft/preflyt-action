"""Reviewed defaults executed only in the repository's GitHub runner."""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from tools import scan


def run(argv, env=None):
    return subprocess.run(argv, env=env, check=False).returncode


def installed(name):
    tool = shutil.which(name)
    if not tool:
        raise ValueError('Use a tool already installed by this workflow, or add your own check command.')
    return tool


def node_script(script):
    package = json.loads(Path('package.json').read_text())
    if not package.get('scripts', {}).get(script):
        raise ValueError('No matching package script. Add a custom workflow command to this check.')
    manager = 'pnpm' if Path('pnpm-lock.yaml').exists() else 'yarn' if Path('yarn.lock').exists() else 'npm'
    return [installed(manager), 'run', script]


def compact_sarif(data):
    """Drop unused rule descriptions, never findings or invocation diagnostics."""
    for scan_run in data.get('runs', []):
        driver = scan_run.get('tool', {}).get('driver', {})
        rules = driver.get('rules', [])
        referenced = {result.get('ruleId') for result in scan_run.get('results', [])}
        indices = {result.get('ruleIndex') for result in scan_run.get('results', [])}
        retained = [(index, rule) for index, rule in enumerate(rules)
                    if rule.get('id') in referenced or index in indices]
        remap = {old: new for new, (old, _) in enumerate(retained)}
        if 'rules' in driver:
            driver['rules'] = [rule for _, rule in retained]
        for result in scan_run.get('results', []):
            if 'ruleIndex' in result:
                result['ruleIndex'] = remap[result['ruleIndex']]
    return data


def main(check, report):
    output = Path(report)
    output.parent.mkdir(parents=True, exist_ok=True)
    if check in ('types.required', 'build.required'):
        return run(node_script('typecheck' if check == 'types.required' else 'build'))
    if check == 'tests.required':
        if Path('node_modules/.bin/vitest').exists():
            return run(['node_modules/.bin/vitest', 'run', '--reporter=default', '--reporter=junit', f'--outputFile={report}'])
        if Path('node_modules/.bin/jest').exists():
            if not Path('node_modules/jest-junit').exists():
                raise ValueError('Use your existing JUnit test command, or install its reporter in your workflow.')
            env = {**os.environ, 'JEST_JUNIT_OUTPUT_FILE': str(output.resolve())}
            return run(['node_modules/.bin/jest', '--ci', '--reporters=default', '--reporters=jest-junit'], env)
        if Path('package.json').exists():
            package = json.loads(Path('package.json').read_text())
            if 'node --test' in package.get('scripts', {}).get('test', ''):
                return run(['node', '--test', '--test-reporter=junit', f'--test-reporter-destination={report}'])
            raise ValueError('Unsupported test runner. Add your JUnit-producing test command to this check.')
        return run([sys.executable, '-m', 'pytest', f'--junitxml={report}'])
    if check == 'security.sast':
        code = scan('semgrep', ['scan', '--config', 'p/default', '--metrics=off', '--disable-version-check', '--strict', '--sarif', '--output', report, '.'], report)
    elif check == 'secrets.scan':
        code = scan('gitleaks', ['dir', '.', '--redact', '--exit-code', '0', '--report-format', 'sarif', '--report-path', report], report)
    elif check in ('security.dependencies', 'containers.scan', 'iac.policy', 'iac.exposures'):
        if check == 'containers.scan':
            image = os.environ.get('CONTAINER_IMAGE')
            if not image: raise ValueError('Set CONTAINER_IMAGE to the image produced by your build.')
            command = ['image', '--scanners', 'vuln']
            target = image
        else:
            command = ['fs', '--scanners', 'vuln' if check == 'security.dependencies' else 'misconfig']
            target = '.'
        code = scan('trivy', [*command, '--cache-dir', '/cache', '--offline-scan', '--format', 'sarif', '--output', report, target], report)
    elif check == 'lint.required':
        if not Path('node_modules/.bin/eslint').exists():
            raise ValueError('No ESLint installation. Add your SARIF-producing lint command to this check.')
        if not Path('node_modules/@microsoft/eslint-formatter-sarif').exists():
            raise ValueError('Use your existing SARIF lint command, or install its formatter in your workflow.')
        code = run(['node_modules/.bin/eslint', '.', '--format', '@microsoft/eslint-formatter-sarif', '--output-file', report])
    else:
        raise ValueError('Add a custom workflow command for this check.')
    # Scanner formats sometimes omit invocation metadata. Record a successful
    # invocation only after this runner observed a successful real command.
    if output.is_file() and output.stat().st_size:
        data = json.loads(output.read_text())
        for scan_run in data.get('runs', []):
            if not scan_run.get('invocations'):
                scan_run['invocations'] = [{'executionSuccessful': code == 0}]
            elif code != 0:
                for invocation in scan_run['invocations']:
                    invocation['executionSuccessful'] = False
        output.write_text(json.dumps(compact_sarif(data), separators=(',', ':')))
    if check != 'lint.required' and code not in (0, 1):
        return 78  # Partial/error output is retained but cannot establish completed coverage.
    return code


if __name__ == '__main__':
    try:
        raise SystemExit(main(sys.argv[1], sys.argv[2]))
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        # No invented results or echoed secrets when a recipe cannot execute.
        print('::error::This check needs a repository-specific workflow command or installed test dependencies. Edit the check in Standards.')
        raise SystemExit(78)
