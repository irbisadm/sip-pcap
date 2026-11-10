// buildLadder() timing in Node.js.
// Mode "warm" (default): WARMUP runs discarded, then N timed runs in one process.
// Mode "cold": one timed run in this process (used by node-cold.sh: a fresh process per run).
// Also times summarizeLadder() and structuredClone() of the full result vs the summary
// (structuredClone is the same serializer postMessage uses).
// Usage: node node-bench.mjs [warm|cold] [N=30] [WARMUP=5] [file]
import { readFileSync } from "node:fs";
import { performance } from "node:perf_hooks";
import { buildLadder, summarizeLadder } from "../dist/index.js";

const mode = process.argv[2] ?? "warm";
const N = +(process.argv[3] ?? 30);
const WARMUP = +(process.argv[4] ?? 5);
const file = process.argv[5] ?? new URL("./capture-4000.pcap", import.meta.url).pathname;
const bytes = new Uint8Array(readFileSync(file));

const stats = (a) => {
  const s = [...a].sort((x, y) => x - y);
  const q = (p) => { const i = (s.length - 1) * p, lo = Math.floor(i), hi = Math.ceil(i); return s[lo] + (s[hi] - s[lo]) * (i - lo); };
  return { n: s.length, median: +q(0.5).toFixed(2), min: +s[0].toFixed(2), max: +s[s.length - 1].toFixed(2), p25: +q(0.25).toFixed(2), p75: +q(0.75).toFixed(2) };
};

if (mode === "cold") {
  const t = performance.now();
  const l = buildLadder(bytes);
  const dt = performance.now() - t;
  console.log(JSON.stringify({ buildLadderMs: +dt.toFixed(2), calls: l.calls.length }));
  process.exit(0);
}

const times = [];
let last;
for (let i = 0; i < WARMUP + N; i++) {
  const t = performance.now();
  last = buildLadder(bytes);
  const dt = performance.now() - t;
  if (i >= WARMUP) times.push(dt);
}
const sumT = [], cloneFull = [], cloneSum = [];
for (let i = 0; i < 10; i++) {
  let t = performance.now(); const s = summarizeLadder(last); sumT.push(performance.now() - t);
  t = performance.now(); structuredClone(s); cloneSum.push(performance.now() - t);
}
for (let i = 0; i < 5; i++) {
  const t = performance.now(); structuredClone(last); cloneFull.push(performance.now() - t);
}
console.log(JSON.stringify({
  node: process.version, file, fileBytes: bytes.length, calls: last.calls.length, sipMessages: last.sipMessages,
  warmup: WARMUP, buildLadderMs: stats(times), raw: times.map((x) => +x.toFixed(2)),
  summarizeLadderMs: stats(sumT), structuredCloneSummaryMs: stats(cloneSum), structuredCloneFullMs: stats(cloneFull),
  heapUsedMiB: +(process.memoryUsage().heapUsed / 1048576).toFixed(1),
}, null, 1));
