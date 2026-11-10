#!/usr/bin/env bash
# First (cold, no JIT warm-up) buildLadder() call: a fresh Node process per run.
# Usage: ./node-cold.sh [RUNS=15]
cd "$(dirname "$0")"
RUNS=${1:-15}
for i in $(seq "$RUNS"); do node node-bench.mjs cold; sleep 1; done
