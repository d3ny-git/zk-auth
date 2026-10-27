#!/bin/sh
# One-command demo: builds and starts the stack, waits for it, then (unless
# NO_HEADLESS=1) logs in once with headless Chromium and a mock wallet, using
# the demo credential, and prints what the server returned.
#   ./demo.sh                     (DOCKER="sudo docker" ./demo.sh if needed)
#   CHROME=/path/to/chromium ./demo.sh
set -eu
cd "$(dirname "$0")"
${DOCKER:-docker} compose up --build -d
echo "waiting for http://localhost:8080 …"
until curl -sf http://localhost:8080/api/health >/dev/null; do sleep 2; done
echo "Zk-Auth is up: open http://localhost:8080 and load demo/cred.json + demo/path.json"
if [ -z "${NO_HEADLESS:-}" ]; then
    (cd tests/e2e && npm ci --silent --no-audit --no-fund)
    node tests/e2e/demo-login.mjs http://localhost:8080 "$PWD/demo/cred.json" "$PWD/demo/path.json"
fi
