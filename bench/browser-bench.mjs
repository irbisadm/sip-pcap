// Browser bench: variants (a) "whole" and (b) "kept" on the local bench page.
// Bundles src/worker.js with esbuild, serves www/ from a local HTTP server in this
// process, drives a headless browser with its own --user-data-dir.
// Each run is a fresh tab (fresh document, fresh worker). Warm-up runs are discarded,
// then ROUNDS rounds, each round runs both variants, the order alternates per round.
// Usage: node browser-bench.mjs [chrome|chromium] [ROUNDS=20] [WARMUP=2]
import { createServer } from "node:http";
import { readFileSync, writeFileSync, mkdirSync, copyFileSync, existsSync } from "node:fs";
import { join, extname } from "node:path";
import { build } from "esbuild";
import puppeteer from "puppeteer-core";

const DIR = new URL(".", import.meta.url).pathname;
mkdirSync(join(DIR, "results"), { recursive: true });
const which = process.argv[2] ?? "chrome";
const ROUNDS = +(process.argv[3] ?? 20);
const WARMUP = +(process.argv[4] ?? 2);
const EXE = process.env.BROWSER ?? { chrome: "/usr/bin/google-chrome-stable", chromium: "/usr/bin/chromium" }[which];

await build({ entryPoints: [join(DIR, "src/worker.js")], bundle: true, format: "esm", outfile: join(DIR, "www/worker.js"), logLevel: "warning" });
if (!existsSync(join(DIR, "www/capture-4000.pcap"))) copyFileSync(join(DIR, "capture-4000.pcap"), join(DIR, "www/capture-4000.pcap"));

const TYPES = { ".html": "text/html", ".js": "text/javascript", ".pcap": "application/octet-stream" };
const server = createServer((req, res) => {
  const p = join(DIR, "www", new URL(req.url, "http://x").pathname.replace(/^\/$/, "/index.html"));
  if (!p.startsWith(join(DIR, "www")) || !existsSync(p)) { res.writeHead(404).end(); return; }
  res.writeHead(200, { "content-type": TYPES[extname(p)] ?? "application/octet-stream", "cache-control": "no-store" });
  res.end(readFileSync(p));
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const base = `http://127.0.0.1:${server.address().port}/`;

const profile = join(DIR, `profile-${which}`);
mkdirSync(profile, { recursive: true });
const browser = await puppeteer.launch({
  executablePath: EXE, headless: true, userDataDir: profile,
  args: ["--no-first-run", "--no-default-browser-check", "--window-size=1440,900"],
  defaultViewport: { width: 1440, height: 900, deviceScaleFactor: 1 },
});
const pid = browser.process()?.pid;
writeFileSync(join(DIR, `browser-${which}.pid`), String(pid));
const version = await browser.version();
const ua = await browser.userAgent();
console.error(`browser ${version} pid ${pid} at ${base}`);

async function one(mode) {
  const page = await browser.newPage();
  await page.goto(`${base}?mode=${mode}`, { waitUntil: "load" });
  const r = await page.evaluate(() => window.__bench);
  await page.close();
  if (r.error || !r.ok) throw new Error(`${mode}: ${JSON.stringify(r).slice(0, 500)}`);
  return r;
}

const runs = [];
try {
  for (let i = 0; i < WARMUP; i++) for (const m of ["whole", "kept"]) { await one(m); console.error(`warmup ${m}`); }
  for (let i = 0; i < ROUNDS; i++) {
    const order = i % 2 ? ["kept", "whole"] : ["whole", "kept"];
    for (const m of order) {
      const r = await one(m);
      r.round = i;
      runs.push(r);
      console.error(`${i} ${m} drawn=${r.drawnMs} lt=${r.longTaskMaxMs} hb=${r.heartbeatMaxGapMs} loaf=${r.loafMaxMs} et=${r.elementTimingRenderMs}`);
    }
  }
} finally {
  await browser.close();
  server.close();
}

const stats = (a) => {
  const s = a.filter((x) => x != null).sort((x, y) => x - y);
  if (!s.length) return null;
  const q = (p) => { const i = (s.length - 1) * p, lo = Math.floor(i), hi = Math.ceil(i); return s[lo] + (s[hi] - s[lo]) * (i - lo); };
  return { n: s.length, median: +q(0.5).toFixed(2), min: +s[0].toFixed(2), max: +s[s.length - 1].toFixed(2), p25: +q(0.25).toFixed(2), p75: +q(0.75).toFixed(2) };
};
const summary = {};
for (const m of ["whole", "kept"]) {
  const rs = runs.filter((r) => r.mode === m);
  summary[m] = {
    drawnMs: stats(rs.map((r) => r.drawnMs)),
    elementTimingRenderMs: stats(rs.map((r) => r.elementTimingRenderMs)),
    longTaskMaxMs: stats(rs.map((r) => r.longTaskMaxMs)),
    heartbeatMaxGapMs: stats(rs.map((r) => r.heartbeatMaxGapMs)),
    loafMaxMs: stats(rs.map((r) => r.loafMaxMs)),
    loafMaxBlockingMs: stats(rs.map((r) => r.loafMaxBlockingMs)),
    longTaskSumMs: stats(rs.map((r) => r.longTaskSumMs)),
    resultMsgMs: stats(rs.map((r) => r.resultMsgMs)),
    workerBuildLadderMs: stats(rs.map((r) => r.worker?.buildLadderMs)),
    workerPostMessageMs: stats(rs.map((r) => r.worker?.postMessageMs)),
    resultArrivesAfterPostMs: stats(rs.map((r) => r.resultMsgMs - (r.worker ? r.worker.parsedMs : 0))),
    callRoundTripMs: stats(rs.map((r) => (r.callReceivedMs == null ? null : r.callReceivedMs - r.listInDomMs))),
    jsHeapMiB: stats(rs.map((r) => r.jsHeapMiB)),
  };
}
const out = { browser: version, userAgent: ua, executable: EXE, rounds: ROUNDS, warmup: WARMUP, date: new Date().toISOString(), summary, runs };
writeFileSync(join(DIR, `results/browser-${which}.json`), JSON.stringify(out, null, 1));
console.log(JSON.stringify({ browser: version, summary }, null, 1));
