#!/bin/bash
# Load tests: C++ (Crow) vs Node (Fastify) on /verify-proof and /verify-sig.
#
#   bench/run_load.sh [FIXTURES_DIR] [RESULTS_DIR]
#   (DOCKER="sudo docker" if you are not in the docker group)
#
# Servers are pinned to physical cores 0-5 (12 hardware threads) and the k6
# load generator to cores 6-7, so they never share a core. Configurations:
#   cpp-1      zkauth-server --threads 1
#   cpp-N      zkauth-server --threads 12
#   node-1     Fastify, single process
#   node-N     Fastify under node:cluster, 12 workers
# For each endpoint and concurrency (1, 8, 64 virtual users): one 5 s warm-up,
# then 3 measured 10 s runs (results/load/<config>_<endpoint>_<vus>_<run>.json).
set -euo pipefail
cd "$(dirname "$0")/.."
FIX=$(realpath "${1:-build/bench-fixtures}")
RES=$(realpath -m "${2:-build/bench-results}")
DOCKER=${DOCKER:-docker}
SERVER_CPUS=${SERVER_CPUS:-0-5,8-13}
LOAD_CPUS=${LOAD_CPUS:-6,7,14,15}
N=${N:-12}
DURATION=${DURATION:-10s}
NODE_IMAGE=node:24-bookworm-slim@sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205
K6_IMAGE=grafana/k6@sha256:3e4186aea62e11a45560bfc51e19eeafe82fc07ce069c78aff44b7ff893d9a5e
mkdir -p "$RES/load"
node baseline-node/convert.mjs keys/vk.json > "$RES/verification_key.json"

wait_health() {
    for _ in $(seq 100); do curl -sf "$1/health" >/dev/null && return 0; sleep 0.2; done
    echo "server at $1 did not come up" >&2; return 1
}

k6() { # endpoint url vus out
    $DOCKER run --rm --network host --cpuset-cpus "$LOAD_CPUS" -u "$(id -u):$(id -g)" \
        -v "$PWD/bench/k6:/scripts:ro" -v "$FIX:/fixtures:ro" -v "$RES/load:/out" \
        -e ENDPOINT="$1" -e URL="$2" -e VUS="$3" -e DURATION="$5" -e OUT="/out/$4" \
        "$K6_IMAGE" run --quiet --no-usage-report /scripts/load.js >/dev/null
}

measure() { # config url
    for ep in verify-proof verify-sig; do
        for vus in 1 8 64; do
            k6 "$ep" "$2" "$vus" "warmup.json" 5s
            for run in 1 2 3; do
                k6 "$ep" "$2" "$vus" "${1}_${ep}_${vus}_${run}.json" "$DURATION"
            done
            echo "  $1 $ep vus=$vus done"
        done
    done
}

run_cpp() { # config threads
    taskset -c "$SERVER_CPUS" build/native-release/server/zkauth-server --port 8081 --bind 127.0.0.1 \
        --threads "$2" --domain bench.local --uri https://bench.local --vk keys/vk.bin \
        --roots "$FIX/issuer/roots.json" --session-key "$RES/session.pem" --mode production 2>"$RES/$1.log" &
    local pid=$!
    wait_health http://127.0.0.1:8081
    measure "$1" http://127.0.0.1:8081
    kill "$pid"; wait "$pid" 2>/dev/null || true
}

run_node() { # config workers
    $DOCKER run -d --rm --name zk-baseline --network host --cpuset-cpus "$SERVER_CPUS" \
        -e PORT=8082 -e HOST=127.0.0.1 -e WORKERS="$2" -e VK=/res/verification_key.json \
        -v "$PWD/baseline-node:/app:ro" -v "$RES:/res:ro" -w /app "$NODE_IMAGE" node server.mjs >/dev/null
    wait_health http://127.0.0.1:8082
    measure "$1" http://127.0.0.1:8082
    $DOCKER stop zk-baseline >/dev/null
}

echo "server CPUs $SERVER_CPUS, load CPUs $LOAD_CPUS, N=$N, $DURATION per run"
run_cpp cpp-1 1
run_cpp "cpp-$N" "$N"
run_node node-1 0
run_node "node-$N" "$N"
echo "results in $RES/load"
