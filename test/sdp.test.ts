// parseSdp and negotiate: the glue around @irbisadm/simple-sdp. The resolve and
// offer/answer rules themselves are tested in simple-sdp.
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseSdp, negotiate } from "../src/index.js";
import type { SdpSession } from "../src/sdp.js";
import { sdpOffer, sdpAnswer, sipSdp } from "./lib/sdp-samples.js";

test("parseSdp: the resolved view, the model and warnings", () => {
  const p = parseSdp(sdpOffer);
  assert.deepEqual(Object.keys(p).sort(), ["bundle", "hold", "media", "model", "warnings"]);
  assert.deepEqual(p.bundle, ["0", "1"]);
  assert.equal(p.hold, false);
  assert.deepEqual(p.warnings, []);
  const [audio] = p.media;
  assert.equal(audio.mid, "0");
  assert.equal(audio.proto, "UDP/TLS/RTP/SAVPF");
  assert.deepEqual(audio.codecs.map((c) => [c.payloadType, c.encodingName, c.static ?? false]), [
    [111, "opus", false],
    [0, "PCMU", true],
  ]);
  assert.equal(audio.iceUfrag, "aaaa");
  assert.equal(audio.setup, "actpass");
  assert.equal(p.model.media[0].mid, "0");
});

test("parseSdp: the model keeps the lines that the resolved view leaves out", () => {
  const { model, media } = parseSdp(sipSdp);
  assert.equal(model.origin?.username, "alice");
  assert.equal(model.origin?.sessId, "2890844526");
  assert.equal(model.connectionInformation?.connectionAddress, "192.0.2.10");
  assert.equal(media[0].mid, undefined);
});

test("parseSdp: empty input throws", () => {
  assert.throws(() => parseSdp(""), /empty SDP/);
  assert.throws(() => parseSdp("   \r\n"), /empty SDP/);
  assert.throws(() => parseSdp(null as unknown as string), /empty SDP/);
});

test("negotiate: works on parseSdp results", () => {
  const n = negotiate(parseSdp(sdpOffer), parseSdp(sdpAnswer));
  assert.deepEqual(n.bundle, ["0", "1"]);
  const [audio, video] = n.media;
  assert.deepEqual(audio.codecs.map((c) => c.encodingName), ["opus"]);
  assert.equal(audio.offerIndex, 0);
  assert.equal(video.rejected, true);
});

test("negotiate: missing side throws", () => {
  assert.throws(() => negotiate(parseSdp(sdpOffer), null as unknown as SdpSession), /need both/);
});

// ─── lenient parsing of SDP that breaks RFC 8866 ─────────────────────────────
const base = "v=0\no=- 1 1 IN IP4 10.0.0.1\ns=-\nc=IN IP4 10.0.0.1\nt=0 0\nm=audio 4000 RTP/AVP 0 96\na=rtpmap:96 telephone-event/8000\n";

test("warning shape: code, reason, line number, line, action", () => {
  const [w] = parseSdp(base + "x=whatever\n").warnings;
  assert.deepEqual(Object.keys(w).sort(), ["action", "code", "line", "lineNumber", "reason"]);
  assert.equal(w.code, "unknown-line-type");
  assert.equal(w.lineNumber, 8);
  assert.equal(w.line, "x=whatever");
  assert.equal(w.action, "skipped");
});

test("broken SDP is still resolved, and reported", () => {
  const r = parseSdp(base.replace("s=-\n", "").replace("telephone-event/8000", "telephone-event") + "a=setup:client\n");
  assert.deepEqual(r.warnings.map((w) => w.code), ["malformed-attribute", "malformed-attribute", "missing-mandatory-line"]);
  assert.deepEqual(r.media[0].codecs.map((c) => c.encodingName), ["PCMU", "telephone-event"]);
  assert.equal(r.media[0].setup, "client");
});

test("text that is not SDP: an empty model and warnings, no exception", () => {
  const r = parseSdp("hello world\nthis is not sdp");
  assert.deepEqual(r.media, []);
  assert.equal(r.model.origin, undefined);
  assert.ok(r.warnings.some((w) => w.code === "missing-version"));
});
