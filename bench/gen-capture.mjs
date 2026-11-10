// Builds the synthetic capture: the proxyCallFlow() sample call repeated N times.
// Each copy gets its own Call-ID and is shifted in time by STEP_MS; all packets are
// sorted by timestamp (calls overlap, as in a real capture of a busy proxy).
// Usage: node gen-capture.mjs [N=4000] [STEP_MS=1000] [out=capture-4000.pcap]
import { writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { proxyCallFlow, proxyCallPcap, classicPcap, udp } from "../dist/testing/index.js";
import { buildLadder } from "../dist/index.js";

const N = +(process.argv[2] ?? 4000);
const STEP_MS = +(process.argv[3] ?? 1000);
const out = process.argv[4] ?? new URL("./capture-4000.pcap", import.meta.url).pathname;
const T0 = Date.UTC(2026, 10, 7, 12, 0, 0);
const ORIG_CALL_ID = "a84b4c76e66710@pc33.example.com";

const flow = proxyCallFlow();
const sample = proxyCallPcap();
const records = [];
let seq = 0;
for (let i = 0; i < N; i++) {
  const cid = `${String(i).padStart(5, "0")}-${ORIG_CALL_ID}`;
  for (const [dt, src, dst, text] of flow) {
    if (!text.includes(`Call-ID: ${ORIG_CALL_ID}`)) throw new Error("Call-ID not found in sample");
    const payload = text.replace(`Call-ID: ${ORIG_CALL_ID}`, `Call-ID: ${cid}`);
    const [sip4, sport] = src.split(":");
    const [dip4, dport] = dst.split(":");
    records.push({ ts: T0 + i * STEP_MS + dt, ord: seq, frame: udp({ src: sip4, dst: dip4, sport: +sport, dport: +dport, payload, id: seq & 0xffff }) });
    seq++;
  }
}
records.sort((a, b) => a.ts - b.ts || a.ord - b.ord);
const bytes = classicPcap(records.map(({ ts, frame }) => ({ ts, frame })));
writeFileSync(out, bytes);

const l = buildLadder(bytes);
const outcomes = {};
for (const c of l.calls) outcomes[c.status] = (outcomes[c.status] ?? 0) + 1;
const msgs = l.calls.reduce((s, c) => s + c.messages.length, 0);
console.log(JSON.stringify({
  out, sampleBytes: sample.length, sampleMessages: flow.length, copies: N, stepMs: STEP_MS,
  fileBytes: bytes.length, fileMiB: +(bytes.length / 1048576).toFixed(3),
  packets: l.packets, sipMessages: l.sipMessages, calls: l.calls.length, messagesInCalls: msgs,
  errors: l.errors.length, statuses: outcomes,
  sha256: createHash("sha256").update(bytes).digest("hex"),
  fullResultJsonBytes: JSON.stringify(l).length,
}, null, 1));
