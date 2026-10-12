"""Policy execution on the user's GitHub runner. No platform credentials or shell commands."""
import hashlib
import json
import os
import signal
import subprocess
import sys
import tempfile
from pathlib import Path
import xml.etree.ElementTree as ET

MAX_REPORT = 262144
MAX_BUNDLE = 900000
COMMAND_CONTROLS = {'types.required', 'build.required'}
FORMATS = {
    'tests.required': 'junit', 'types.required': 'junit', 'build.required': 'junit',
    'frontend.components': 'junit', 'service.resilience': 'junit',
    'lint.required': 'sarif', 'security.sast': 'sarif', 'secrets.scan': 'sarif',
    'security.dependencies': 'sarif', 'containers.scan': 'sarif',
    'iac.policy': 'sarif', 'iac.exposures': 'sarif',
}


def bounded_json(path, limit=MAX_BUNDLE):
    data = Path(path).read_bytes()
    if len(data) > limit:
        raise ValueError('Configuration exceeds size limit')
    return json.loads(data)


def within_workspace(value):
    if (not isinstance(value, str) or not value or len(value) > 512 or
            Path(value).is_absolute() or any(part in ('..', '.git') for part in Path(value).parts) or
            any(ord(c) < 32 for c in value) or '\\' in value):
        raise ValueError('Use a relative report path inside the repository')
    root = Path(os.environ['GITHUB_WORKSPACE']).resolve()
    target = (root / value).resolve()
    if not target.is_relative_to(root) or target == root or target.is_dir():
        raise ValueError('Report path must remain inside the repository')
    return target


def report_result(fmt, content):
    if fmt == 'junit':
        if '<!DOCTYPE' in content.upper() or '<!ENTITY' in content.upper():
            raise ValueError('XML declarations are unsupported')
        root = ET.fromstring(content)
        cases = list(root.iter('testcase'))
        if root.tag not in ('testsuite', 'testsuites') or not cases or len(cases) > 5000:
            return 'incomplete'
        if any(list(case.iter('failure')) or list(case.iter('error')) for case in cases):
            return 'failed'
        if not any(case.find('skipped') is None for case in cases):
            return 'incomplete'
        return 'passed'
    report = json.loads(content)
    runs = report.get('runs')
    if report.get('version') != '2.1.0' or not isinstance(runs, list) or not runs or len(runs) > 10:
        return 'incomplete'
    for run in runs:
        if run.get('externalPropertyFileReferences') or not isinstance(run.get('results'), list):
            return 'incomplete'
        invocations = run.get('invocations', [])
        if not invocations or not all(v.get('executionSuccessful') is True for v in invocations):
            return 'incomplete'
        if len(run['results']) > 5000:
            return 'incomplete'
        if any(result.get('level', 'warning') in ('error', 'warning') for result in run['results']):
            return 'failed'
    return 'passed'


def recipe_command(argv):
    if isinstance(argv, list) and argv and argv[0] == 'preflyt-recipe':
        if len(argv) != 3 or argv[1] not in FORMATS:
            raise ValueError('Invalid Preflyt recipe')
        return [sys.executable, str(Path(__file__).resolve().with_name('recipes.py')), *argv[1:]]
    return argv


def is_recipe(argv):
    return isinstance(argv, list) and argv[:1] == ['preflyt-recipe']


def execution_config(rules):
    config, paths = {}, set()
    for rule in rules:
        execution = rule.get('execution')
        if execution is None:
            continue
        if not isinstance(execution, dict) or set(execution) != {'report', 'argv'}:
            raise ValueError('Policy execution configuration is invalid')
        path = within_workspace(execution['report'])
        argv = execution['argv']
        if (not isinstance(argv, list) or not argv or len(argv) > 65 or
                any(not isinstance(a, str) or '\0' in a or len(a) > 4096 for a in argv) or not argv[0]):
            raise ValueError('Policy commands must use arguments arrays')
        if is_recipe(argv) and argv != ['preflyt-recipe', rule['id'], execution['report']]:
            raise ValueError('Recipe must match its check and output file')
        if path in paths:
            raise ValueError('Checks need independent report files')
        relative = path.relative_to(Path(os.environ['GITHUB_WORKSPACE']).resolve())
        tracked = subprocess.check_output(['git', 'ls-files', '--', str(relative)],
                                          cwd=os.environ['GITHUB_WORKSPACE'])
        if tracked:
            raise ValueError('A result file must not overwrite repository source')
        paths.add(path)
        config[rule['id']] = execution
    if len(config) > 10:
        raise ValueError('At most 10 execution reports per workflow run')
    return config


def command_run(argv):
    if not isinstance(argv, list) or not argv or len(argv) > 65 or any(not isinstance(a, str) or '\0' in a or len(a) > 4096 for a in argv):
        raise ValueError('Use an executable and arguments array, not a shell string')
    env = {k: v for k, v in os.environ.items() if not k.startswith(('ACTIONS_ID_TOKEN_', 'PREFLYT_')) and k not in ('GITHUB_TOKEN', 'GH_TOKEN')}
    process = subprocess.Popen(recipe_command(argv), cwd=os.environ['GITHUB_WORKSPACE'], env=env, start_new_session=True)
    try:
        return process.wait(timeout=285)
    except subprocess.TimeoutExpired:
        return None
    finally:
        # Commands cannot leave a background process alive after evaluation.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def main():
    policy = bounded_json(os.environ['PREFLYT_POLICY_PATH'])
    if policy.get('schemaVersion') != 1 or policy.get('state') != 'PUBLISHED' or not isinstance(policy.get('checks'), list) or not policy['checks'] or len(policy['checks']) > 64:
        raise ValueError('Export a published Preflyt policy before running checks')
    if policy.get('sourceSha') != os.environ.get('GITHUB_SHA'):
        raise ValueError('Policy workflow commit differs from this run')
    checkout = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=os.environ['GITHUB_WORKSPACE'], text=True).strip()
    if checkout != policy.get('headSha'):
        raise ValueError('Check out the pull request head commit before running the policy')
    rules = policy['checks']
    ids = [rule['id'] for rule in rules]
    if len(ids) != len(set(ids)) or policy.get('executionVersion') != 1:
        raise ValueError('Fetch a published policy with supported execution configuration')
    config = execution_config(rules)
    if str(policy['repositoryId']) != os.environ.get('GITHUB_REPOSITORY_ID'):
        raise ValueError('Policy belongs to another repository')
    if any(type(rule.get('required')) is not bool for rule in rules):
        raise ValueError('Policy requirements are invalid')
    proof_paths = json.loads(os.environ.get('PREFLYT_PROOFS', '{}'))
    if not isinstance(proof_paths, dict):
        raise ValueError('Proofs must map report paths to signed bundles')
    results, reports, details = [], [], {}
    for rule in rules:
        status = 'incomplete'
        detail = 'No command configured in the published policy.'
        try:
            if rule['id'] == 'ci.configured':
                status = 'passed' if any(Path('.github/workflows').glob('*.y*ml')) else 'failed'
            elif rule['id'] == 'dependencies.locked':
                status = 'passed' if any(Path(name).is_file() for name in ('pnpm-lock.yaml', 'package-lock.json', 'yarn.lock', 'poetry.lock', 'Pipfile.lock', 'Cargo.lock', 'go.sum', 'Gemfile.lock', 'composer.lock')) else 'failed'
            elif rule['id'] in config:
                check = config[rule['id']]
                if not isinstance(check, dict):
                    raise ValueError('Invalid check configuration')
                path = within_workspace(check['report'])
                fmt = FORMATS.get(rule['id'])
                if not fmt and rule['id'].startswith('custom-junit-'):
                    fmt = 'junit'
                if not fmt and rule['id'].startswith('custom-sarif-'):
                    fmt = 'sarif'
                if fmt not in ('junit', 'sarif'):
                    raise ValueError('This check has no supported execution adapter')
                # A fresh command cannot accidentally reuse an old successful report.
                if 'argv' in check:
                    path.unlink(missing_ok=True)
                    code = command_run(check['argv'])
                    if code == 78 and is_recipe(check['argv']):
                        code = None  # Unsupported recipe is not evaluated, never a fabricated pass.
                    if rule['id'] in COMMAND_CONTROLS:
                        path.parent.mkdir(parents=True, exist_ok=True)
                        suite = ET.Element('testsuite', tests='0' if code is None else '1')
                        if code is not None:
                            case = ET.SubElement(suite, 'testcase', name=rule['id'])
                            if code != 0:
                                ET.SubElement(case, 'failure', message='Command failed')
                        path.write_bytes(ET.tostring(suite, encoding='utf-8', xml_declaration=True))
                with path.open('rb') as report_stream:
                    data = report_stream.read(MAX_REPORT + 1)
                if not data or len(data) > MAX_REPORT:
                    detail = 'Report is empty or exceeds the 256 KiB limit.'
                    raise ValueError('Report exceeds the supported size')
                content = data.decode('utf-8')
                status = report_result(fmt, content)
                detail = 'Scanner reported findings.' if status == 'failed' and fmt == 'sarif' else 'Reported tests failed.' if status == 'failed' else 'Report contains incomplete execution evidence.' if status == 'incomplete' else ''
                if code is None:
                    status = 'incomplete'
                    detail = 'Execution was unavailable, timed out or returned partial scanner output.'
                elif code != 0:
                    status = 'failed'
                    detail = f'Command exited with status {code}.'
                entry = {'ruleId': rule['id'], 'format': fmt, 'content': content, 'sha256': hashlib.sha256(data).hexdigest()}
                proof_path = proof_paths.get(check['report'])
                if proof_path:
                    bundle = within_workspace(proof_path).read_text()
                    if len(bundle.encode()) > 524288:
                        raise ValueError('Proof exceeds size limit')
                    entry['proof'] = bundle
                if len(reports) >= 10:
                    raise ValueError('At most 10 execution reports per workflow run')
                reports.append(entry)
        except (OSError, ValueError, TypeError, KeyError, ET.ParseError):
            status = 'incomplete'
            if detail == 'No command configured in the published policy.':
                detail = 'A fresh report could not be read or evaluated.'
        details[rule['id']] = detail if status != 'passed' else ''
        results.append({'ruleId': rule['id'], 'title': rule['title'], 'required': rule['required'], 'status': status})
    required = [item for item in results if item['required']]
    overall = 'failed' if any(item['status'] == 'failed' for item in required) else 'incomplete' if any(item['status'] != 'passed' for item in required) or not required else 'passed'
    bundle = {'schemaVersion': 1, 'verificationScope': 'jobs', 'jobName': os.environ.get('PREFLYT_JOB_NAME', os.environ.get('GITHUB_JOB', '')),  'repositoryId': os.environ['GITHUB_REPOSITORY_ID'], 'sourceSha': os.environ['GITHUB_SHA'], 'headSha': policy['headSha'], 'runId': os.environ['GITHUB_RUN_ID'], 'runAttempt': int(os.environ['GITHUB_RUN_ATTEMPT']), 'signerWorkflow': os.environ['GITHUB_WORKFLOW_REF'].split('@')[0], 'policyId': policy['id'], 'policyHash': policy['definitionHash'], 'results': results, 'reports': reports}
    encoded = json.dumps(bundle).encode()
    if len(encoded) > MAX_BUNDLE:
        raise ValueError('Combined results exceed size limit')
    directory = Path(tempfile.mkdtemp(prefix='preflyt-', dir=os.environ['RUNNER_TEMP']))
    output = directory / 'preflyt-results.json'
    output.write_bytes(encoded)
    with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
        stream.write(f'result={overall}\nbundle={output}\n')
    with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as stream:
        stream.write(f'## Preflyt policy: {overall}\n\n| Check | Required | Result | Details |\n|---|---|---|---|\n')
        for item in results:
            title = str(item['title']).replace('|', ' ').replace('\n', ' ').replace('<', '&lt;').replace('>', '&gt;')
            stream.write(f"| {title} | {'Yes' if item['required'] else 'No'} | {item['status']} | {details[item['ruleId']] or '—'} |\n")


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # Paths, commands and configuration may contain secrets; never echo them.
        print('::error::Preflyt could not evaluate this policy. Check the policy and check configuration files.')
        raise SystemExit(1)
