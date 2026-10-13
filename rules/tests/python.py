# SPDX-License-Identifier: MIT
import pickle, yaml, requests, subprocess
value = "dummy"
# ruleid: preflyt-python-eval
eval(value)
# ruleid: preflyt-python-exec
exec(value)
# ruleid: preflyt-python-pickle
pickle.loads(value)
# ruleid: preflyt-python-unsafe-yaml
yaml.load(value)
# ruleid: preflyt-python-tls-verification-disabled
requests.get(value, verify=False)
# ruleid: preflyt-python-shell
subprocess.run(value, shell=True)
# ruleid: preflyt-python-sql-fstring
db.execute(f"SELECT * FROM users WHERE id={value}")
# ok: preflyt-python-unsafe-yaml
yaml.safe_load(value)
# ok: preflyt-python-tls-verification-disabled
requests.get(value, verify=True)
# ok: preflyt-python-shell
subprocess.run(["tool", value], shell=False)
# ok: preflyt-python-sql-fstring
db.execute("SELECT * FROM users WHERE id=?", [value])
