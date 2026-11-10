// Cross-check of the main-thread pause with a DevTools trace: the longest task
// (top-level RunTask / ThreadControllerImpl::RunTask on the page's CrRendererMain
// thread) between console.timeStamp("bench-t0") and "bench-end". Unlike Long Tasks
// this also sees tasks < 50 ms. Tracing adds overhead, so these runs are separate
// from browser-bench.mjs and fewer.
// Usage: node trace-bench.mjs [chrome|chromium] [RUNS=6]
import { createServer } from "node:http";
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { join, extname } from "node:path";
import puppeteer from "puppeteer-core";

const DIR = new URL(".", import.meta.url).pathname;
const which = process.argv[2] ?? "chrome";
const RUNS = +(process.argv[3] ?? 6);
const EXE = process.env.BROWSER ?? { chrome: "/usr/bin/google-chrome-stable", chromium: "/usr/bin/chromium" }[which];
if (!existsSync(join(DIR, "www/worker.js"))) throw new Error("run browser-bench.mjs first (it bundles www/worker.js)");

const TYPES = { ".html": "text/html", ".js": "text/javascript" };
const server = createServer((req, res) => {
  const p = join(DIR, "www", new URL(req.url, "http://x").pathname.replace(/^\/$/, "/index.html"));
  if (!p.startsWith(join(DIR, "www")) || !existsSync(p)) { res.writeHead(404).end(); return; }
  res.writeHead(200, { "content-type": TYPES[extname(p)] ?? "application/octet-stream", "cache-control": "no-store" });
  res.end(readFileSync(p));
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const base = `http://127.0.0.1:${server.address().port}/`;
const profile = join(DIR, `profile-trace-${which}`);
mkdirSync(profile, { recursive: true });
mkdirSync(join(DIR, "results/traces"), { recursive: true });
const browser = await puppeteer.launch({
  executablePath: EXE, headless: true, userDataDir: profile,
  args: ["--no-first-run", "--no-default-browser-check", "--window-size=1440,900"],
  defaultViewport: { width: 1440, height: 900, deviceScaleFactor: 1 },
});
writeFileSync(join(DIR, `browser-trace-${which}.pid`), String(browser.process()?.pid));

function analyze(trace) {
  const ev = trace.traceEvents;
  const t0 = ev.find((e) => e.name === "TimeStamp" && e.args?.data?.message === "bench-t0");
  const t1 = ev.find((e) => e.name === "TimeStamp" && e.args?.data?.message === "bench-end");
  if (!t0 || !t1) throw new Error("markers not found");
  const main = ev.find((e) => e.name === "thread_name" && e.args?.name === "CrRendererMain" && e.pid === t0.pid && e.tid === t0.tid);
  if (!main) throw new Error("bench-t0 is not on CrRendererMain");
  const tasks = ev.filter((e) => e.ph === "X" && e.pid === t0.pid && e.tid === t0.tid && (e.name === "RunTask" || e.name === "ThreadControllerImpl::RunTask") && e.ts + e.dur >= t0.ts && e.ts <= t1.ts);
  // keep top-level tasks only
  tasks.sort((a, b) => a.ts - b.ts);
  const top = [];
  for (const t of tasks) if (!top.length || t.ts >= top[top.length - 1].ts + top[top.length - 1].dur) top.push(t);
  top.sort((a, b) => b.dur - a.dur);
  const gcIn = (t) => ev.filter((e) => e.ph === "X" && e.pid === t0.pid && e.tid === t0.tid && /^(MinorGC|MajorGC|V8\.GC_)/.test(e.name) && e.ts >= t.ts && e.ts < t.ts + t.dur).reduce((s, e) => s + e.dur, 0) / 1000;
  return {
    maxTaskMs: +(top[0].dur / 1000).toFixed(2),
    maxTaskAtMs: +((top[0].ts - t0.ts) / 1000).toFixed(1),
    maxTaskGcMs: +gcIn(top[0]).toFixed(2),
    top5: top.slice(0, 5).map((t) => ({ at: +((t.ts - t0.ts) / 1000).toFixed(1), dur: +(t.dur / 1000).toFixed(2) })),
  };
}

const runs = [];
try {
  for (let i = 0; i < RUNS + 1; i++) {
    for (const mode of i % 2 ? ["kept", "whole"] : ["whole", "kept"]) {
      const page = await browser.newPage();
      await page.tracing.start({ categories: ["devtools.timeline", "disabled-by-default-devtools.timeline", "v8", "disabled-by-default-v8.gc"] });
      await page.goto(`${base}?mode=${mode}`, { waitUntil: "load" });
      const r = await page.evaluate(() => window.__bench);
      const buf = Buffer.from(await page.tracing.stop());
      await page.close();
      if (i === 0) continue; // warm-up
      const trace = JSON.parse(buf.toString());
      const a = analyze(trace);
      if (i === 1) writeFileSync(join(DIR, `results/traces/${which}-${mode}.json`), buf);
      runs.push({ mode, drawnMs: r.drawnMs, longTaskMaxMs: r.longTaskMaxMs, heartbeatMaxGapMs: r.heartbeatMaxGapMs, ...a });
      console.error(mode, JSON.stringify(runs.at(-1)));
    }
  }
} finally {
  await browser.close();
  server.close();
}
const stats = (a) => {
  const s = [...a].sort((x, y) => x - y);
  const q = (p) => { const i = (s.length - 1) * p, lo = Math.floor(i), hi = Math.ceil(i); return s[lo] + (s[hi] - s[lo]) * (i - lo); };
  return { n: s.length, median: +q(0.5).toFixed(2), min: +s[0].toFixed(2), max: +s[s.length - 1].toFixed(2) };
};
const summary = {};
for (const m of ["whole", "kept"]) {
  const rs = runs.filter((r) => r.mode === m);
  summary[m] = { traceMaxTaskMs: stats(rs.map((r) => r.maxTaskMs)), traceMaxTaskGcMs: stats(rs.map((r) => r.maxTaskGcMs)), drawnMsUnderTracing: stats(rs.map((r) => r.drawnMs)) };
}
writeFileSync(join(DIR, `results/trace-${which}.json`), JSON.stringify({ browser: await Promise.resolve(EXE), summary, runs }, null, 1));
console.log(JSON.stringify(summary, null, 1));
