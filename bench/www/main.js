// Bench page. ?mode=whole -> variant (a), ?mode=kept -> variant (b).
// Both variants build exactly the same DOM: the summary line, the first LIST_PAGE
// (200) call buttons + "Show more", and call #0 (header, SVG ladder like
// the SIP ladder on webrtc.page, raw message #1 and its SDP table).
// (a) gets the whole Ladder in one message and renders list + call #0 from it in the
//     same task (no second round trip, list rows are mapped only for the 200 shown).
// (b) gets the summary, renders the list, asks the worker for call #0, renders it.
//
// Clocks: t0 = right before bytes.slice() + postMessage to the worker (the bytes are
// already in memory, file reading is not part of the measurement, same as the
// real page after `await f.arrayBuffer()`).
// "Drawn" = the first frame that contains the ladder SVG has been produced: after the
// ladder is in the DOM we wait for requestAnimationFrame (style/layout/paint of that
// frame run right after the rAF callbacks) and then for a MessageChannel message,
// which is delivered as the next task, i.e. after that frame's rendering step.
// Cross-check: Element Timing (`elementtiming` on the call header text) gives the
// paint/presentation time of that frame as seen by the compositor.
const LIST_PAGE = 200;
const mode = new URLSearchParams(location.search).get("mode") || "kept";
const now = () => performance.now();
const toLocal = (abs) => abs - performance.timeOrigin;

// ---- main-thread pause instruments ---------------------------------------------
const longtasks = [], loafs = [], elementTimings = [];
try { new PerformanceObserver((l) => longtasks.push(...l.getEntries())).observe({ type: "longtask", buffered: true }); } catch {}
try { new PerformanceObserver((l) => loafs.push(...l.getEntries())).observe({ type: "long-animation-frame", buffered: true }); } catch {}
try { new PerformanceObserver((l) => elementTimings.push(...l.getEntries())).observe({ type: "element", buffered: true }); } catch {}
const ticks = [];
let hb = null;
const startHeartbeat = () => { ticks.length = 0; ticks.push(now()); hb = setInterval(() => ticks.push(now()), 16); };
const stopHeartbeat = () => clearInterval(hb);

// ---- rendering (identical for both variants) -----------------------------------
const $ = (tag, props = {}, ...kids) => {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) k === "class" ? (el.className = v) : el.setAttribute(k, v);
  for (const c of kids) el.append(c);
  return el;
};
const NS = "http://www.w3.org/2000/svg";
const S = (tag, attrs = {}, ...kids) => {
  const el = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, String(v));
  for (const c of kids) el.append(c);
  return el;
};
const fmtMs = (ms) => ms == null ? "—" : ms < 1000 ? `${Math.round(ms)} ms` : ms < 60000 ? `${(ms / 1000).toFixed(2)} s` : `${Math.floor(ms / 60000)} min ${Math.round((ms % 60000) / 1000)} s`;
const userOf = (uri) => (uri ?? "?").replace(/^sips?:/, "");
const codecLabel = (c) => c.encodingName ? `${c.encodingName}/${c.clockRate ?? ""}` : `PT${c.payloadType}`;

function renderSummary(s) {
  document.getElementById("summary").textContent =
    `${s.packets} packets · ${s.sipMessages} SIP messages · ${s.total} ${s.total === 1 ? "call" : "calls"}`;
}
function renderList(items, total) {
  const aside = document.getElementById("calls");
  aside.replaceChildren($("input", { type: "search", class: "cfilter", placeholder: "filter by user, Call-ID, status" }));
  for (const c of items) {
    aside.append($("button", { type: "button", class: "call-item" + (c.index === 0 ? " on" : "") },
      $("span", { class: "ci-top" }, $("b", {}, c.method), $("span", { class: `pill ${c.outcome}`, title: c.status }, c.status)),
      $("span", { class: "ci-who" }, `${userOf(c.from)} → ${userOf(c.to)}`),
      $("span", { class: "ci-meta" }, `${c.messages} messages · ${c.hosts} hosts · ${fmtMs(c.durationMs)}`)));
  }
  if (total > items.length) aside.append($("button", { type: "button", class: "more-calls" }, `Show ${Math.min(LIST_PAGE, total - items.length)} more of ${total - items.length}`));
}
function ladderSvg(endpoints, messages, boxW) {
  const GUTTER = 92, HEAD = 64, ROW = 38;
  const LANE = Math.max(190, Math.floor((boxW - GUTTER) / Math.max(1, endpoints.length)));
  const width = GUTTER + endpoints.length * LANE, height = HEAD + messages.length * ROW + 24;
  const laneX = (addr) => GUTTER + endpoints.findIndex((e) => e.addr === addr) * LANE + LANE / 2;
  const cls = (m) => m.kind === "request" ? "req" : (m.statusCode ?? 0) < 200 ? "prov" : (m.statusCode ?? 0) < 300 ? "ok" : "err";
  const fmtRel = (ms) => ms < 1000 ? `+${ms.toFixed(0)} ms` : `+${(ms / 1000).toFixed(3)} s`;
  const short = (s, n = 26) => !s ? "" : s.length > n ? s.slice(0, n - 1) + "…" : s;
  const svg = S("svg", { viewBox: `0 0 ${width} ${height}`, width, height, class: "ladder", role: "list", "aria-label": "SIP messages" });
  const defs = S("defs");
  for (const c of ["req", "prov", "ok", "err"]) defs.append(S("marker", { id: `lh-${c}`, viewBox: "0 0 10 10", refX: 9, refY: 5, markerWidth: 7, markerHeight: 7, orient: "auto-start-reverse" }, S("path", { d: "M0 1L10 5L0 9z", class: `mk ${c}` })));
  svg.append(defs);
  endpoints.forEach((e, k) => {
    const cx = GUTTER + k * LANE + LANE / 2;
    const ag = S("text", { class: "agent", x: cx, y: 41, "text-anchor": "middle" });
    if (e.agent) ag.append(S("title", {}, e.agent));
    ag.append(short(e.agent, Math.floor((LANE - 24) / 6.7)) || "—");
    svg.append(S("g", {},
      S("line", { class: "life", x1: cx, y1: HEAD - 6, x2: cx, y2: height - 8 }),
      S("rect", { class: "lane-head", x: GUTTER + k * LANE + 10, y: 6, width: LANE - 20, height: 44, rx: 3 }),
      S("text", { class: "addr", x: cx, y: 25, "text-anchor": "middle" }, e.addr), ag));
  });
  messages.forEach((m, i) => {
    const x1 = laneX(m.src), x2 = laneX(m.dst), dir = x2 >= x1 ? 1 : -1, y = HEAD + i * ROW + ROW / 2 + 6, c = cls(m);
    const lbl = S("text", { class: "lbl", x: (x1 + x2) / 2, y: y - 7, "text-anchor": "middle" }, m.label);
    if (m.sdpRole) lbl.append(S("tspan", { class: "sdp" }, ` · SDP ${m.sdpRole}`));
    else if (m.rejectedOfferStep !== null) lbl.append(S("tspan", { class: "sdp" }, " · SDP offer rejected"));
    if (m.retransmission) lbl.append(S("tspan", { class: "rt" }, " · retransmit"));
    svg.append(S("g", { class: `row ${c}${i === 0 ? " sel" : ""}${m.retransmission ? " retx" : ""}`, "data-row": i, role: "listitem", tabindex: 0,
      "aria-label": `${m.label} from ${m.src} to ${m.dst}${m.sdpRole ? ", SDP " + m.sdpRole : ""}` },
      S("rect", { class: "band", x: 0, y: y - ROW / 2 - 6, width, height: ROW }),
      S("text", { class: "rel", x: 8, y: y + 4 }, fmtRel(m.rel)),
      S("line", { class: "arrow", x1: x1 + dir * 3, y1: y, x2: x2 - dir * 5, y2: y, "marker-end": `url(#lh-${c})` }),
      lbl));
  });
  return svg;
}
function renderCall(call) {
  const main = document.getElementById("main");
  const box = $("div", { class: "ladder-scroll" });
  main.replaceChildren(
    $("div", { class: "call-head" },
      $("div", {}, $("h2", { elementtiming: "call-head" }, `${userOf(call.from)} → ${userOf(call.to)}`), $("p", { class: "cid" }, "Call-ID ", $("code", {}, call.id))),
      $("dl", { class: "timings" },
        $("div", {}, $("dt", {}, "Status"), $("dd", {}, $("span", { class: `pill ${call.outcome}` }, call.status))),
        $("div", {}, $("dt", {}, "Ringing after"), $("dd", {}, fmtMs(call.ringMs))),
        $("div", {}, $("dt", {}, "Answered after"), $("dd", {}, fmtMs(call.answerMs))),
        $("div", {}, $("dt", {}, "Talk time"), $("dd", {}, fmtMs(call.talkMs))))),
    box);
  // the webrtc.page ladder sizes lanes from the box width (ResizeObserver); read it once here
  box.append(ladderSvg(call.endpoints, call.messages, box.clientWidth));
  const msg = call.messages[0];
  const raw = msg.raw, cut = raw.search(/\r?\n\r?\n/);
  const head = cut === -1 ? raw : raw.slice(0, cut), body = cut === -1 ? "" : raw.slice(cut).replace(/^\r?\n\r?\n/, "");
  const lines = head.split(/\r?\n/);
  const pre = $("pre", { class: "sipraw" }, $("b", {}, lines[0] ?? ""), "\n");
  for (const l of lines.slice(1)) { const c = l.indexOf(":"); pre.append($("span", { class: "hn" }, c === -1 ? "" : l.slice(0, c)), (c === -1 ? l : ":" + l.slice(c + 1)) + "\n"); }
  if (body) pre.append("\n", $("span", { class: "body" }, body));
  const sdp = $("div", { class: "sdp-panel" });
  if (msg.sdp) {
    const tb = $("tbody");
    for (const m of msg.sdp.media) tb.append($("tr", {}, $("td", {}, m.type), $("td", {}, String(m.port ?? "—")), $("td", {}, m.direction), $("td", {}, m.codecs.map(codecLabel).join(", ") || "—")));
    sdp.append($("h3", {}, `SDP ${msg.sdpRole}`), $("table", { class: "sdpt" }, $("thead", {}, $("tr", {}, $("th", {}, "Media"), $("th", {}, "Port"), $("th", {}, "Direction"), $("th", {}, "Codecs"))), tb));
  } else sdp.append($("p", { class: "dim" }, "No SDP in this message."));
  main.append($("div", { class: "detail" },
    $("div", { class: "raw" }, $("div", { class: "dhead" }, $("h3", {}, `#${msg.index + 1} ${msg.label}`), $("span", { class: "dim" }, `${msg.src} → ${msg.dst} · ${msg.proto.toUpperCase()} · +${fmtMs(msg.rel)}`)), pre),
    sdp));
}
const frameDone = () => new Promise((resolve) => requestAnimationFrame((rafTs) => {
  const tRaf = now();
  const ch = new MessageChannel();
  ch.port1.onmessage = () => resolve({ rafTs, tRaf, tAfterFrame: now() });
  ch.port2.postMessage(0);
}));
const idle = (ms) => new Promise((r) => setTimeout(r, ms));

// ---- one run -------------------------------------------------------------------
async function run() {
  const bytes = new Uint8Array(await (await fetch("capture-4000.pcap", { cache: "no-store" })).arrayBuffer());
  const w = new Worker("worker.js", { type: "module" });
  // let the page settle (fetch, worker start-up) before measuring
  await idle(1000);
  const marks = {};
  let workerTiming = null, callPost = null;
  const pending = new Map();
  let seq = 0;
  w.onmessage = (e) => {
    if (e.data.id === -1) { workerTiming = e.data.timing; return; }
    if (e.data.id === -2) { callPost = e.data.timing.tCallPost; return; }
    const p = pending.get(e.data.id); pending.delete(e.data.id);
    e.data.ok ? p.resolve(e.data) : p.reject(new Error(e.data.error));
  };
  const ask = (msg, transfer = []) => new Promise((resolve, reject) => { const id = ++seq; pending.set(id, { resolve, reject }); w.postMessage({ ...msg, id }, transfer); });

  startHeartbeat();
  await idle(100);
  console.timeStamp("bench-t0");
  const t0 = now();
  marks.t0 = t0;
  const copy = bytes.slice(); // as the real page: keep the original, transfer the copy
  const parseP = ask({ type: "parse", mode, bytes: copy.buffer, sipPort: 5060 }, [copy.buffer]);
  marks.tPosted = now();
  const r = await parseP;
  marks.tResult = now(); // the message task (incl. deserialization) is running now
  if (mode === "whole") {
    const L = r.ladder;
    renderSummary({ packets: L.packets, sipMessages: L.sipMessages, total: L.calls.length });
    const items = L.calls.slice(0, LIST_PAGE).map((c, index) => ({ index, id: c.id, from: c.from, to: c.to, method: c.method, status: c.status, outcome: c.outcome, durationMs: c.durationMs, messages: c.messages.length, hosts: c.endpoints.length }));
    renderList(items, L.calls.length);
    marks.tListInDom = now();
    renderCall(L.calls[0]);
    marks.tCallInDom = now();
    window.__keep = L; // the page holds the result, as a real (a) page would
  } else {
    const s = r.summary;
    renderSummary({ packets: s.packets, sipMessages: s.sipMessages, total: s.calls.length });
    renderList(s.calls.slice(0, LIST_PAGE), s.calls.length);
    marks.tListInDom = now();
    const c = await ask({ type: "call", index: 0 });
    marks.tCallReceived = now();
    renderCall(c.call);
    marks.tCallInDom = now();
    window.__keep = s;
  }
  const f = await frameDone();
  Object.assign(marks, f);
  // keep watching the main thread for 1 s after the ladder is drawn (late GC etc.)
  await idle(1000);
  stopHeartbeat();
  const winEnd = now();
  console.timeStamp("bench-end");
  let maxGap = 0, maxGapAt = 0;
  for (let i = 1; i < ticks.length; i++) if (ticks[i] >= t0 && ticks[i] - ticks[i - 1] > maxGap) { maxGap = ticks[i] - ticks[i - 1]; maxGapAt = ticks[i - 1] - t0; }
  const inWin = (e) => e.startTime + e.duration >= t0 && e.startTime <= winEnd;
  const lt = longtasks.filter(inWin), lf = loafs.filter(inWin);
  const et = elementTimings.find((e) => e.identifier === "call-head");
  const rel = (x) => (x == null ? null : +(x - t0).toFixed(2));
  const res = {
    mode,
    ok: document.querySelectorAll("#main svg.ladder g.row").length === 13 && document.querySelectorAll("#calls .call-item").length === 200,
    drawnMs: rel(marks.tAfterFrame),
    rafMs: rel(marks.tRaf),
    elementTimingRenderMs: et ? rel(et.renderTime || et.loadTime) : null,
    resultMsgMs: rel(marks.tResult),
    listInDomMs: rel(marks.tListInDom),
    callReceivedMs: rel(marks.tCallReceived),
    callInDomMs: rel(marks.tCallInDom),
    postToWorkerMs: rel(marks.tPosted),
    worker: workerTiming && {
      recvMs: rel(toLocal(workerTiming.tRecv)), parsedMs: rel(toLocal(workerTiming.tParsed)),
      buildLadderMs: +(workerTiming.tParsed - workerTiming.tRecv).toFixed(2),
      payloadBuildMs: +(workerTiming.tBuilt - workerTiming.tParsed).toFixed(2),
      postMessageMs: +(workerTiming.tPosted - workerTiming.tBuilt).toFixed(2),
    },
    callPostMessageMs: callPost == null ? null : +callPost.toFixed(2),
    heartbeatMaxGapMs: +maxGap.toFixed(2), heartbeatMaxGapAtMs: +maxGapAt.toFixed(2), heartbeatTicks: ticks.length,
    longTaskMaxMs: lt.length ? Math.max(...lt.map((e) => e.duration)) : 0,
    longTaskCount: lt.length, longTaskSumMs: lt.reduce((s, e) => s + e.duration, 0),
    longTasks: lt.map((e) => ({ start: rel(e.startTime), dur: e.duration })),
    loafMaxMs: lf.length ? Math.max(...lf.map((e) => e.duration)) : 0,
    loafMaxBlockingMs: lf.length ? Math.max(...lf.map((e) => e.blockingDuration)) : 0,
    loafs: lf.map((e) => ({ start: rel(e.startTime), dur: e.duration, blocking: e.blockingDuration, render: +(e.startTime + e.duration - e.renderStart).toFixed(1) })),
    jsHeapMiB: performance.memory ? +(performance.memory.usedJSHeapSize / 1048576).toFixed(1) : null,
  };
  w.terminate();
  return res;
}
window.__bench = run().catch((e) => ({ error: String(e?.stack ?? e) }));
