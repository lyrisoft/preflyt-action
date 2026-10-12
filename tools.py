"""Image-pinned scanner provisioning. No host credentials or Docker socket in scans."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

IMAGES = {
    'semgrep': 'semgrep/semgrep@sha256:93963d9295a366f59e4850127b1550400ee7b388f04fe144e4a1f6325d96e01b',
    'gitleaks': 'zricethezav/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f',
    'trivy': 'aquasec/trivy@sha256:af6acf9a6b85dfe389a1941505c0ce9efef52a4719635e1a962f022a3d855daa',
}


def clean_environment():
    return {k: v for k, v in os.environ.items()
            if not k.startswith(('ACTIONS_ID_TOKEN_', 'PREFLYT_'))
            and k not in ('GITHUB_TOKEN', 'GH_TOKEN')}


def scan(tool, argv, report):
    """Pull only the reviewed image, mount the source read-only and one output file."""
    docker = shutil.which('docker')
    if not docker or tool not in IMAGES:
        return 78
    root = Path(os.environ['GITHUB_WORKSPACE']).resolve()
    output = (root / report).resolve()
    if (not output.is_relative_to(root) or output == root or
            any(',' in str(path) or any(ord(c) < 32 for c in str(path)) for path in (root, output))):
        return 78
    output.parent.mkdir(parents=True, exist_ok=True)
    output.touch(mode=0o600, exist_ok=False)
    env = clean_environment()
    try:
        pulled = subprocess.run([docker, 'pull', '--platform', 'linux/amd64', IMAGES[tool]],
                                env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=180, check=False)
        if pulled.returncode:
            return 78
        with tempfile.TemporaryDirectory(prefix='preflyt-tool-', dir=os.environ.get('RUNNER_TEMP')) as cache:
            if ',' in cache or any(ord(c) < 32 for c in cache):
                return 78
            command = [docker, 'run', '--rm', '--platform', 'linux/amd64', '--read-only',
                       '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                       '--user', f'{os.getuid()}:{os.getgid()}', '--pids-limit', '128',
                       '--memory', '2g', '--cpus', '2', '--tmpfs', '/tmp:rw,nosuid,nodev,size=512m',
                       '--env', 'HOME=/tmp', '--env', 'SEMGREP_SEND_METRICS=off',
                       '--mount', f'type=bind,src={root},dst={root},readonly',
                       '--mount', f'type=bind,src={output},dst={output}',
                       '--mount', f'type=bind,src={cache},dst=/cache',
                       '--workdir', str(root), '--entrypoint', tool]
            if tool == 'gitleaks':
                command += ['--network', 'none']
            command += [IMAGES[tool], *argv]
            return subprocess.run(command, env=env, stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL, timeout=270, check=False).returncode
    except (OSError, subprocess.TimeoutExpired):
        return 78
