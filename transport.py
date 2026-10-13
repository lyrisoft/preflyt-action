"""Short-lived GitHub OIDC policy fetch/result submission. Never logs tokens or bodies."""
import json
import os
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit, urlencode
from urllib.request import Request, build_opener, HTTPRedirectHandler
from urllib.error import HTTPError, URLError

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

opener = build_opener(NoRedirect())

def request(url, headers, body=None):
    data = json.dumps(body).encode() if body is not None else None
    if data is not None and len(data) > 900000:
        raise ValueError('Combined results exceed the submission limit')
    req = Request(url, data=data, headers={**headers, 'Content-Type': 'application/json', 'Accept': 'application/json'})
    with opener.open(req, timeout=30) as response:
        content = response.read(900001)
        if len(content) > 900000:
            raise ValueError('Response exceeds the supported size')
        return json.loads(content)

def token():
    url = os.environ['ACTIONS_ID_TOKEN_REQUEST_URL']
    parsed = urlsplit(url)
    if parsed.scheme != 'https' or parsed.username or parsed.password:
        raise ValueError('GitHub identity endpoint is invalid')
    separator = '&' if parsed.query else '?'
    return request(url + separator + urlencode({'audience': 'preflyt:policy'}), {'Authorization': 'Bearer ' + os.environ['ACTIONS_ID_TOKEN_REQUEST_TOKEN']})['value']

def api(path, body=None):
    base = os.environ['PREFLYT_API_URL'].rstrip('/')
    parsed = urlsplit(base)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError('Use the public HTTPS Preflyt API URL')
    for attempt in range(3):
        try:
            return request(base + '/pipeline/' + path, {'Authorization': 'Bearer ' + token()}, body)
        except HTTPError as error:
            if error.code not in (429, 502, 503, 504) or attempt == 2:
                raise
        except URLError:
            if attempt == 2:
                raise
        time.sleep(2 ** attempt)

GATE_STAGES = {
    'CHECK_JOBS': 'Waiting for completed CI jobs',
    'RESULT_SUBMISSION': 'Waiting for the result submission',
    'RESULT_VERIFICATION': 'Verifying submitted execution evidence',
    'GITHUB_PUBLICATION': 'Waiting for verified GitHub check publication',
    'AI_REVIEW': 'Waiting for the configured AI review',
    'AI_PUBLICATION': 'Waiting for AI feedback publication',
}
GATE_FAILURES = {
    'CONTEXT_CHANGED': 'The pull request or published policy changed. Rerun the checks workflow.',
    'RESULT_VERIFICATION_FAILED': 'The submitted run could not be verified. Review the saved assessment.',
    'POLICY_RESULT_FAILED': 'Required policy checks failed or evidence is incomplete. Review the saved assessment.',
    'GITHUB_PUBLICATION_FAILED': 'The GitHub check publication could not be verified.',
    'CHECK_JOBS_FAILED': 'One or more prerequisite CI jobs failed.',
    'AI_REVIEW_FAILED': 'The configured AI review could not complete.',
    'AI_PUBLICATION_FAILED': 'AI feedback could not be published to the pull request.',
    'INVALID_RESPONSE': 'The API returned an unrecognized gate response. Verification remains unconfirmed.',
}

class GateError(ValueError):
    pass

class GateTimeout(TimeoutError):
    pass

def gate_error_message(error):
    # Never interpolate API bodies, URLs, exception text or repository content.
    if isinstance(error, GateError):
        code = error.args[0] if error.args else None
        if not isinstance(code, str) or code not in GATE_FAILURES:
            return 'Preflyt policy or publication failed. Review the saved assessment and rerun checks.'
        return code + ': ' + GATE_FAILURES[code]
    if isinstance(error, GateTimeout):
        return 'GATE_TIMEOUT: Verification did not finish within fifteen minutes. Review the last waiting stage and rerun after resolving it.'
    if isinstance(error, HTTPError) and isinstance(error.code, int) and 400 <= error.code <= 599:
        return f'API_HTTP_{error.code}: Gate request was rejected. Check API availability, id-token permission and enabled PR checks.'
    if isinstance(error, (URLError, OSError)):
        return 'API_UNAVAILABLE: Could not reach the verification API. Check the API and tunnel, then rerun the workflow.'
    return 'GATE_UNCONFIRMED: Could not confirm gate verification. Check API availability and review the saved assessment.'

def wait_for_publication(run_id, attempt, timeout=900):
    if not run_id.isdigit() or not attempt.isdigit():
        raise GateError('INVALID_RESPONSE')
    started = time.monotonic()
    deadline = started + timeout
    last_stage, last_log = None, started
    while time.monotonic() < deadline:
        result = api('publication?' + urlencode({'run': run_id, 'attempt': attempt}))
        if not isinstance(result, dict):
            raise GateError('INVALID_RESPONSE')
        state = result.get('state')
        stage = result.get('stage')
        now = time.monotonic()
        elapsed = int(now - started)
        if state == 'PASSED':
            print(f'Preflyt gate: Verified GitHub publication and required review feedback ({elapsed}s elapsed).', flush=True)
            return
        if state == 'FAILED':
            raise GateError(stage if isinstance(stage, str) and stage in GATE_FAILURES else 'FAILED')
        if state != 'PENDING':
            raise GateError('INVALID_RESPONSE')
        safe_stage = stage if isinstance(stage, str) and stage in GATE_STAGES else 'VERIFICATION'
        if safe_stage != last_stage or now - last_log >= 30:
            message = GATE_STAGES.get(safe_stage, 'Waiting for verified Preflyt results')
            print(f'Preflyt gate: {message} ({elapsed}s elapsed).', flush=True)
            last_stage, last_log = safe_stage, now
        time.sleep(5)
    raise GateTimeout()

def main():
    if sys.argv[1] == 'fetch':
        policy = api('policy')
        if policy.get('schemaVersion') != 1 or policy.get('state') != 'PUBLISHED':
            raise ValueError('Published policy unavailable')
        directory = Path(tempfile.mkdtemp(prefix='preflyt-policy-', dir=os.environ['RUNNER_TEMP']))
        path = directory / 'policy.json'
        path.write_text(json.dumps(policy))
        path.chmod(0o600)
        with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
            output.write(f'policy={path}\n')
    elif sys.argv[1] == 'submit':
        path = Path(os.environ['PREFLYT_BUNDLE_PATH'])
        data = path.read_bytes()
        if len(data) > 900000:
            raise ValueError('Combined results exceed the submission limit')
        receipt = api('results', json.loads(data))
        if receipt.get('verification') != 'PENDING' or not receipt.get('id'):
            raise ValueError('Result submission was not confirmed')
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as output:
            output.write('\nResults received by Preflyt; completed-job verification and PR publication are pending.\n')
    elif sys.argv[1] == 'gate':
        wait_for_publication(os.environ['PREFLYT_SOURCE_RUN_ID'], os.environ['PREFLYT_SOURCE_RUN_ATTEMPT'])
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as output:
            output.write('Preflyt verified the source run and published a passing GitHub check.\n')
    else:
        raise ValueError('Unsupported transport operation')

if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        if len(sys.argv) > 1 and sys.argv[1] == 'gate':
            print('::error::' + gate_error_message(error))
            raise SystemExit(1)
        print('::error::Preflyt could not fetch the policy or submit results. Check API reachability, id-token permission, published policy and enabled PR checks.')
        raise SystemExit(1)
