#!/bin/bash
# Runs all three libFuzzer targets in parallel for SECONDS (default 600) each,
# growing fuzz-corpus/<target>/ from the committed seeds in tests/fuzz/seeds/.
#   cmake --preset native-fuzz && cmake --build --preset native-fuzz && tests/fuzz/run.sh
set -euo pipefail
cd "$(dirname "$0")/../.."
SECONDS_EACH=${1:-600}
for t in proof_json siwe signature; do
    mkdir -p "fuzz-corpus/$t"
    build/native-fuzz/tests/fuzz/fuzz_$t "fuzz-corpus/$t" "tests/fuzz/seeds/$t" \
        -max_total_time="$SECONDS_EACH" -timeout=10 -print_final_stats=1 \
        > "fuzz-corpus/$t.log" 2>&1 &
done
wait
for t in proof_json siwe signature; do
    printf '%-12s corpus %5s files  ' "$t" "$(ls "fuzz-corpus/$t" | wc -l)"
    grep -E "stat::number_of_executed_units|stat::peak_rss_mb" "fuzz-corpus/$t.log" | tr '\n' ' '
    grep -qE "ERROR|deadly signal|Test unit written" "fuzz-corpus/$t.log" && echo " CRASH (see fuzz-corpus/$t.log)" || echo " no crashes"
done
