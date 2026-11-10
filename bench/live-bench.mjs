// Live https://webrtc.page/tools/sip-ladder on the same capture, headless, own profile.
// Instruments are injected before any page script (evaluateOnNewDocument):
//   t0      = the file input's "change" event (capture phase, before the page's handler).
//             Unlike the local bench this includes File.arrayBuffer() of the 26 MB file.
//   drawn   = first `svg.ladder` with its rows in the DOM (MutationObserver), then
//             rAF + MessageChannel, the same "frame produced" rule as the local bench.
//   pauses  = Long Tasks, Long Animation Frames, a 16 ms setInterval heartbeat,
//             window [t0, drawn + 1 s].
// Usage: node live-bench.mjs [chrome|chromium] [RUNS=10] [WARMUP=1]
import { writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import puppeteer from "puppeteer-core";

const DIR = new URL(".", import.meta.url).pathname;
mkdirSync(join(DIR, "results"), { recursive: true });
const which = process.argv[2] ?? "chrome";
const RUNS = +(process.argv[3] ?? 10);
const WARMUP = +(process.argv[4] ?? 1);
const EXE = process.env.BROWSER ?? { chrome: "/usr/bin/google-chrome-stable", chromium: "/usr/bin/chromium" }[which];
const URL_ = "https://webrtc.page/tools/sip-ladder";
const FILE = join(DIR, "capture-4000.pcap");

const inject = () => {
  const B = (window.__lb = { longtasks: [], loafs: [], ticks: [], t0: null, drawn: null, workers: 0 });
  try { new PerformanceObserver((l) => B.longtasks.push(...l.getEntries().map((e) => ({ s: e.startTime, d: e.duration })))).observe({ type: "longtask", buffered: true }); } catch {}
  try { new PerformanceObserver((l) => B.loafs.push(...l.getEntries().map((e) => ({ s: e.startTime, d: e.duration, b: e.blockingDuration })))).observe({ type: "long-animation-frame", buffered: true }); } catch {}
  const W = window.Worker;
  window.Worker = function (...a) { B.workers++; return new W(...a); };
  window.Worker.prototype = W.prototype;
  document.addEventListener("change", (e) => {
    if (e.target?.type !== "file") return;
    B.t0 = performance.now();
    B.ticks = [B.t0];
    B.hb = setInterval(() => B.ticks.push(performance.now()), 16);
    const mo = new MutationObserver(() => {
      const svg = document.querySelector("svg.ladder");
      if (!svg || !svg.querySelector("g.row")) return;
      mo.disconnect();
      B.inDom = performance.now();
      B.rows = svg.querySelectorAll("g.row").length;
      requestAnimationFrame(() => { const ch = new MessageChannel(); ch.port1.onmessage = () => { B.drawn = performance.now(); setTimeout(() => { clearInterval(B.hb); B.done = performance.now(); }, 1000); }; ch.port2.postMessage(0); });
    });
    mo.observe(document.body, { childList: true, subtree: true });
  }, true);
};

const profile = join(DIR, `profile-live-${which}`);
mkdirSync(profile, { recursive: true });
const browser = await puppeteer.launch({
  executablePath: EXE, headless: true, userDataDir: profile,
  args: ["--no-first-run", "--no-default-browser-check", "--window-size=1440,900"],
  defaultViewport: { width: 1440, height: 900, deviceScaleFactor: 1 },
});
writeFileSync(join(DIR, `browser-live-${which}.pid`), String(browser.process()?.pid));
const version = await browser.version();

async function one() {
  const page = await browser.newPage();
  await page.evaluateOnNewDocument(inject);
  await page.goto(URL_, { waitUntil: "networkidle0", timeout: 60000 });
  await new Promise((r) => setTimeout(r, 2000));
  const input = await page.$('input[type="file"]');
  await input.uploadFile(FILE);
  await page.waitForFunction(() => window.__lb.done, { timeout: 120000, polling: 100 });
  const r = await page.evaluate(() => {
    const B = window.__lb, t0 = B.t0, end = B.done;
    let gap = 0, at = 0;
    for (let i = 1; i < B.ticks.length; i++) if (B.ticks[i] - B.ticks[i - 1] > gap) { gap = B.ticks[i] - B.ticks[i - 1]; at = B.ticks[i - 1] - t0; }
    const win = (e) => e.s + e.d >= t0 && e.s <= end;
    const lt = B.longtasks.filter(win), lf = B.loafs.filter(win);
    return {
      drawnMs: +(B.drawn - t0).toFixed(2), inDomMs: +(B.inDom - t0).toFixed(2), rows: B.rows, workersCreated: B.workers,
      summaryText: document.querySelector(".summary")?.textContent?.trim(), callButtons: document.querySelectorAll(".call-item").length,
      heartbeatMaxGapMs: +gap.toFixed(2), heartbeatMaxGapAtMs: +at.toFixed(2),
      longTaskMaxMs: lt.length ? Math.max(...lt.map((e) => e.d)) : 0, longTasks: lt.map((e) => ({ start: +(e.s - t0).toFixed(1), dur: e.d })),
      loafMaxMs: lf.length ? Math.max(...lf.map((e) => e.d)) : 0, loafMaxBlockingMs: lf.length ? Math.max(...lf.map((e) => e.b)) : 0,
    };
  });
  await page.close();
  return r;
}

const runs = [];
try {
  for (let i = 0; i < WARMUP; i++) { const r = await one(); console.error("warmup", JSON.stringify(r)); }
  for (let i = 0; i < RUNS; i++) { const r = await one(); runs.push(r); console.error(i, JSON.stringify(r).slice(0, 400)); }
} finally {
  await browser.close();
}
const stats = (a) => {
  const s = [...a].sort((x, y) => x - y);
  const q = (p) => { const i = (s.length - 1) * p, lo = Math.floor(i), hi = Math.ceil(i); return s[lo] + (s[hi] - s[lo]) * (i - lo); };
  return { n: s.length, median: +q(0.5).toFixed(2), min: +s[0].toFixed(2), max: +s[s.length - 1].toFixed(2), p25: +q(0.25).toFixed(2), p75: +q(0.75).toFixed(2) };
};
const summary = Object.fromEntries(["drawnMs", "inDomMs", "longTaskMaxMs", "heartbeatMaxGapMs", "loafMaxMs", "loafMaxBlockingMs"].map((k) => [k, stats(runs.map((r) => r[k]))]));
writeFileSync(join(DIR, `results/live-${which}.json`), JSON.stringify({ url: URL_, browser: version, date: new Date().toISOString(), summary, runs }, null, 1));
console.log(JSON.stringify({ browser: version, summary }, null, 1));
