// Bench worker. The same protocol as the worker of the SIP ladder on webrtc.page, plus
// a `mode` on "parse":
//   mode "whole": reply with the full buildLadder() result      -> variant (a)
//   mode "kept":  keep the result, reply with the summary only;   -> variant (b)
//                 one call's messages are sent on {type:"call"}
// Worker-side timings are sent back as absolute times (timeOrigin + now) so the page
// can put them on its own clock.
import { buildLadder } from "../../dist/index.js";
import { summarizeLadder } from "./summary.js";

let last = null;
const abs = () => performance.timeOrigin + performance.now();

self.onmessage = (e) => {
  const { id, type } = e.data;
  try {
    if (type === "parse") {
      const tRecv = abs();
      last = buildLadder(new Uint8Array(e.data.bytes), { sipPort: e.data.sipPort });
      const tParsed = abs();
      let msg;
      if (e.data.mode === "whole") msg = { id, ok: true, ladder: last };
      else msg = { id, ok: true, summary: summarizeLadder(last) };
      const tBuilt = abs();
      self.postMessage(msg); // structured clone (serialization) happens here, on the worker thread
      const tPosted = abs();
      self.postMessage({ id: -1, timing: { tRecv, tParsed, tBuilt, tPosted } });
    } else if (type === "call") {
      const call = last?.calls[e.data.index];
      if (!call) throw new Error(`no call #${e.data.index}`);
      const t = abs();
      self.postMessage({ id, ok: true, call });
      self.postMessage({ id: -2, timing: { tCallPost: abs() - t } });
    }
  } catch (err) {
    self.postMessage({ id, ok: false, error: String(err?.message ?? err) });
  }
};
