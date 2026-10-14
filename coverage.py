"""Bounded, exact-run LCOV attachment. No test execution or source upload outside Preflyt."""
import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
import urllib.request

MAX_RAW = 8 * 1024 * 1024
MAX_LCOV = 2 * 1024 * 1024
MAX_COMPRESSED = 262144
MAX_BUNDLE = 900000


def bounded_file(path, maximum):
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= maximum:
        raise ValueError('Invalid coverage file')
    return path.read_bytes()


def same_context(metadata, bundle):
    return (metadata.get('version') == 1 and
            all(metadata.get(key) == bundle.get(key) for key in ('repositoryId', 'runId', 'runAttempt')) and
            metadata.get('sourceSha') == bundle.get('headSha'))


def merge_lcov(inputs, workspace):
    files = {}
    for raw, prefix in inputs:
        if len(raw) > MAX_RAW or not re.fullmatch(r'[\w.-]+(?:/[\w.-]+)*', prefix) or '..' in prefix.split('/'):
            raise ValueError('Invalid coverage scope')
        current = None
        for line in raw.decode('utf8').splitlines():
            if line.startswith('SF:'):
                if current is not None:
                    raise ValueError('Incomplete LCOV record')
                name = line[3:]
                path = Path(name)
                if path.is_absolute():
                    name = path.relative_to(workspace / prefix).as_posix()
                if (not name or len(name) > 1024 or '\\' in name or
                        any(ord(c) < 32 for c in name) or '..' in Path(name).parts or Path(name).is_absolute()):
                    raise ValueError('Invalid LCOV path')
                name = (Path(prefix) / name).as_posix()
                current = {'name': name, 'lines': {}}
            elif line.startswith('DA:'):
                match = re.fullmatch(r'DA:(\d+),(\d+)(?:,[^,\r\n]+)?', line)
                if current is None or not match:
                    raise ValueError('Invalid LCOV counter')
                number, hits = map(int, match.groups())
                if not 1 <= number <= 50000000 or hits > 9007199254740991 or number in current['lines']:
                    raise ValueError('Invalid LCOV counter')
                current['lines'][number] = hits > 0
            elif re.match(r'L[HF]:', line):
                match = re.fullmatch(r'L([HF]):(\d+)', line)
                if current is None or not match or match[1] in current:
                    raise ValueError('Invalid LCOV total')
                current[match[1]] = int(match[2])
            elif line == 'end_of_record':
                if (current is None or current.get('F') != len(current['lines']) or
                        current.get('H') != sum(current['lines'].values())):
                    raise ValueError('LCOV totals do not match')
                if not current['lines']:
                    current = None
                    continue
                saved = files.setdefault(current['name'], {})
                for number, hit in current['lines'].items():
                    saved[number] = saved.get(number, False) or hit
                current = None
            elif line and not re.match(r'^(TN:|FN:|FNDA:|FNF:|FNH:|BRDA:|BRF:|BRH:|VER:)', line):
                raise ValueError('Unsupported LCOV record')
        if current is not None:
            raise ValueError('Incomplete LCOV report')
    if not 0 < len(files) <= 10000:
        raise ValueError('Missing LCOV records')
    lines = []
    for name, counters in sorted(files.items()):
        lines.append('SF:' + name)
        lines.extend(f'DA:{number},{int(hit)}' for number, hit in sorted(counters.items()))
        lines.extend((f'LF:{len(counters)}', f'LH:{sum(counters.values())}', 'end_of_record'))
    result = ('\n'.join(lines) + '\n').encode()
    if len(result) > MAX_LCOV:
        raise ValueError('Coverage exceeds report limit')
    return result


def attach(bundle_path, local_reports, artifact_directory, since, workspace):
    workspace = workspace.resolve()
    bundle_path = Path(bundle_path)
    bundle = json.loads(bounded_file(bundle_path, MAX_BUNDLE))
    if bundle.get('result') not in (None, 'passed') or any(r.get('required') and r.get('status') != 'passed' for r in bundle['results']):
        raise ValueError('Coverage requires successful policy execution')
    if any(r['ruleId'] == 'tests.coverage' for r in bundle['reports']):
        raise ValueError('Coverage report already attached')
    inputs = []
    for spec in local_reports:
        if set(spec) != {'path', 'prefix'}:
            raise ValueError('Invalid local coverage configuration')
        path = (workspace / spec['path']).resolve()
        if not path.is_relative_to(workspace) or path.stat().st_mtime < since:
            raise ValueError('Stale coverage output')
        inputs.append((bounded_file(path, MAX_RAW), spec['prefix']))
    if artifact_directory:
        directory = Path(artifact_directory)
        metadata = json.loads(bounded_file(directory / 'metadata.json', 4096))
        raw = bounded_file(directory / 'lcov.info', MAX_RAW)
        if not same_context(metadata, bundle) or metadata.get('sha256') != hashlib.sha256(raw).hexdigest():
            raise ValueError('Coverage artifact context mismatch')
        inputs.append((raw, metadata['prefix']))
    content = merge_lcov(inputs, workspace)
    compressed = gzip.compress(content, mtime=0)
    if len(compressed) > MAX_COMPRESSED or len(bundle['reports']) >= 10:
        raise ValueError('Coverage exceeds transport limits')
    bundle['reports'].append({'ruleId': 'tests.coverage', 'format': 'lcov', 'encoding': 'gzip-base64',
                              'content': base64.b64encode(compressed).decode(), 'sha256': hashlib.sha256(content).hexdigest()})
    encoded = json.dumps(bundle).encode()
    if len(encoded) > MAX_BUNDLE:
        raise ValueError('Combined reports exceed transport limit')
    temporary = bundle_path.with_suffix('.coverage.tmp')
    temporary.write_bytes(encoded)
    os.replace(temporary, bundle_path)
    print('Attached current-run API/browser line coverage.', flush=True)


def wait_for_artifact(name, env=os.environ, timeout=120):
    repo, run, attempt = env['GITHUB_REPOSITORY'], env['GITHUB_RUN_ID'], env['GITHUB_RUN_ATTEMPT']
    if not re.fullmatch(r'[\w.-]+/[\w.-]+', repo) or not run.isdigit() or not attempt.isdigit():
        raise ValueError('Invalid workflow context')
    # Only GitHub's API receives the token. Artifact downloads use the official
    # pinned download-artifact action, never a token-bearing redirect here.
    url = f'https://api.github.com/repos/{repo}/actions/runs/{run}/artifacts?per_page=100'
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        req = urllib.request.Request(url, headers={'authorization': 'Bearer ' + env['PREFLYT_COVERAGE_TOKEN'],
                                                   'accept': 'application/vnd.github+json'})
        with urllib.request.urlopen(req, timeout=15) as response:
            data = json.loads(response.read(1048577))
        if data.get('total_count', 101) > 100:
            raise ValueError('Ambiguous artifact collection')
        matches = [a for a in data.get('artifacts', []) if a.get('name') == name and not a.get('expired')]
        if len(matches) == 1:
            artifact = matches[0]
            if artifact.get('workflow_run', {}).get('id') != int(run) or not 0 < artifact.get('size_in_bytes', 0) <= MAX_RAW:
                raise ValueError('Artifact identity or size mismatch')
            with open(env['GITHUB_OUTPUT'], 'a') as out:
                out.write(f'artifact-id={int(artifact["id"])}\n')
            return
        if matches:
            raise ValueError('Ambiguous coverage artifact')
        time.sleep(3)
    raise ValueError('Current coverage artifact unavailable')


if __name__ == '__main__':
    try:
        if sys.argv[1] == 'wait':
            wait_for_artifact(os.environ['PREFLYT_COVERAGE_ARTIFACT'])
        else:
            if os.environ.get('PREFLYT_COVERAGE_ARTIFACT_REQUIRED') == 'true' and not os.environ.get('PREFLYT_COVERAGE_DIRECTORY'):
                raise ValueError('Required coverage artifact was not downloaded')
            attach(os.environ['PREFLYT_BUNDLE_PATH'], json.loads(os.environ.get('PREFLYT_COVERAGE_REPORTS', '[]')),
                   os.environ.get('PREFLYT_COVERAGE_DIRECTORY') or None,
                   float(os.environ['PREFLYT_COVERAGE_SINCE']), Path(os.environ['GITHUB_WORKSPACE']).resolve())
    except Exception:
        print('::error::Coverage reporting failed: check current test reports, artifact identity and report limits.')
        sys.exit(1)
