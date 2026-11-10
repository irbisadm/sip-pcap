#!/usr/bin/env bash
# Full run: capture, Node.js (warm and cold), browser variants, DevTools trace, live page.
# Needs Node >= 20, the library built (npm run build in the repository root),
# npm install in this folder, and Google Chrome or Chromium (set BROWSER to its path
# if it is not /usr/bin/google-chrome-stable or /usr/bin/chromium).
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p results
node gen-capture.mjs 4000 1000 > results/capture-4000.json
node node-bench.mjs warm 30 5 > results/node-warm.json
./node-cold.sh 15 > results/node-cold.jsonl
node browser-bench.mjs chrome 20 2 2> results/browser-chrome.log > /dev/null
node trace-bench.mjs chrome 6     2> results/trace-chrome.log   > /dev/null
node live-bench.mjs chrome 10 1   2> results/live-chrome.log    > /dev/null
