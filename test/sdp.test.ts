// parseSdp (normalized media model) and negotiate (RFC 3264).
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseSdp, negotiate } from "../src/index.js";
import type { SdpSession } from "../src/sdp.js";
import { sdpOffer, sdpAnswer, sipSdp } from "./lib/sdp-samples.js";

// sipSdp with another payload list and no rtpmap/fmtp lines
const audioOnly = (pts: string) => sipSdp.replace("RTP/AVP 0 8 18 101", `RTP/AVP ${pts}`).replace(/a=(rtpmap|fmtp):.*\n/g, "");

test("parseSdp: codecs, extensions, bundle, ICE, DTLS", () => {
  const p = parseSdp(sdpOffer);
  assert.deepEqual(p.bundle, ["0", "1"]);
  assert.equal(p.hold, false);
  assert.equal(p.media.length, 2);
  const audio = p.media[0];
  assert.equal(audio.mid, "0");
  assert.equal(audio.type, "audio");
  assert.equal(audio.port, 49170);
  assert.equal(audio.rejected, false);
  assert.equal(audio.protocol, "UDP/TLS/RTP/SAVPF");
  assert.equal(audio.direction, "sendrecv");
  assert.deepEqual(audio.codecs.find((c) => c.codec === "opus"), {
    pt: 111, codec: "opus", rate: 48000, channels: 2, fmtp: "minptime=10;useinbandfec=1",
  });
  // static PT 0 without rtpmap
  assert.deepEqual(audio.codecs.find((c) => c.pt === 0), {
    pt: 0, codec: "PCMU", rate: 8000, channels: 1, fmtp: null, static: true,
  });
  assert.deepEqual(audio.extensions, [{ id: 1, uri: "urn:ietf:params:rtp-hdrext:ssrc-audio-level" }]);
  assert.deepEqual(audio.ice, { ufrag: "aaaa", pwd: "bbbbbbbbbbbbbbbbbbbbbb" });
  assert.deepEqual(audio.dtls, { setup: "actpass", fingerprint: "sha-256 AA:BB" });
  assert.equal(p.media[1].ice, null);
  assert.equal(p.media[1].dtls, null);
});

test("parseSdp: origin", () => {
  const { origin } = parseSdp(sipSdp);
  assert.equal(origin.username, "alice");
  assert.equal(origin.sessionId, 2890844526);
  assert.equal(origin.netType, "IN");
  assert.equal(origin.ipVer, 4);
  assert.equal(origin.address, "192.0.2.10");
});

test("parseSdp: SIP audio with static types, telephone-event fmtp, no mid", () => {
  const [m] = parseSdp(sipSdp).media;
  assert.equal(m.mid, "m0", "media without a=mid get a positional id");
  assert.equal(m.protocol, "RTP/AVP");
  assert.deepEqual(m.codecs.map((c) => [c.pt, c.codec, c.rate, c.static ?? false]), [
    [101, "telephone-event", 8000, false],
    [0, "PCMU", 8000, true],
    [8, "PCMA", 8000, true],
    [18, "G729", 8000, true],
  ]);
  assert.equal(m.codecs[0].fmtp, "0-16");
  assert.equal(m.codecs.find((c) => c.pt === 18).fmtp, "annexb=no");
  assert.equal(m.ice, null);
  assert.equal(m.dtls, null);
});

test("parseSdp: unknown static payload type", () => {
  const [m] = parseSdp(audioOnly("34")).media;
  assert.deepEqual(m.codecs, [{ pt: 34, codec: "PT34", rate: null, channels: 1, fmtp: null, static: true }]);
});

test("parseSdp: rejected stream and hold", () => {
  const a = parseSdp(sdpAnswer);
  assert.equal(a.media[1].port, 0);
  assert.equal(a.media[1].rejected, true);
  const held = parseSdp(sipSdp + "a=sendonly\n");
  assert.equal(held.media[0].direction, "sendonly");
  assert.equal(held.hold, true);
});

test("parseSdp: empty input throws", () => {
  assert.throws(() => parseSdp(""), /empty SDP/);
  assert.throws(() => parseSdp("   \r\n"), /empty SDP/);
  assert.throws(() => parseSdp(null as unknown as string), /empty SDP/);
});

test("negotiate: agreed codecs and extensions, DTLS and ICE per side, rejected video", () => {
  const n = negotiate(parseSdp(sdpOffer), parseSdp(sdpAnswer));
  assert.deepEqual(n.bundle, ["0", "1"]);
  assert.equal(n.hold, false);
  const [audio, video] = n.media;
  assert.deepEqual(Object.keys(audio).sort(), [
    "agreedCodecs", "agreedExtensions", "directionAnswer", "directionOffer", "dtlsAnswer", "dtlsOffer",
    "hold", "iceAnswer", "iceOffer", "mid", "rejected", "type",
  ]);
  assert.equal(audio.mid, "0");
  assert.deepEqual(audio.agreedCodecs.map((c) => c.codec), ["opus"]);
  assert.deepEqual(audio.agreedExtensions.map((e) => e.uri), ["urn:ietf:params:rtp-hdrext:ssrc-audio-level"]);
  assert.equal(audio.dtlsOffer, "actpass");
  assert.equal(audio.dtlsAnswer, "active");
  assert.equal(audio.iceOffer, "aaaa");
  assert.equal(audio.iceAnswer, null);
  assert.equal(audio.directionOffer, "sendrecv");
  assert.equal(audio.directionAnswer, "sendrecv");
  assert.equal(video.rejected, true);
  assert.deepEqual(video.agreedCodecs, []);
  assert.deepEqual(video.agreedExtensions, []);
});

test("negotiate: hold when either side stops a direction", () => {
  const offer = parseSdp(sdpOffer);
  const n = negotiate(offer, parseSdp(sdpAnswer.replace("a=sendrecv", "a=sendonly")));
  assert.equal(n.media[0].directionAnswer, "sendonly");
  assert.equal(n.media[0].hold, true);
  assert.equal(n.hold, true);
  const n2 = negotiate(parseSdp(sdpOffer.replace("a=sendrecv", "a=inactive")), parseSdp(sdpAnswer));
  assert.equal(n2.media[0].directionOffer, "inactive");
  assert.equal(n2.hold, true);
});

test("negotiate: codecs match by name, rate and channels, not payload type", () => {
  const offer = parseSdp(sipSdp);
  const answer = parseSdp(sipSdp.replace("RTP/AVP 0 8 18 101", "RTP/AVP 8 96").replace(/a=rtpmap:101 .*\n/, "a=rtpmap:96 telephone-event/8000\n").replace("a=fmtp:101", "a=fmtp:96"));
  const [m] = negotiate(offer, answer).media;
  assert.deepEqual(m.agreedCodecs.map((c) => `${c.pt} ${c.codec}`), ["96 telephone-event", "8 PCMA"]);
});

test("negotiate: media matched by mid, else by position", () => {
  const offer = parseSdp(sipSdp);
  const answer = parseSdp(audioOnly("0"));
  assert.equal(negotiate(offer, answer).media[0].mid, "m0");
  assert.deepEqual(negotiate(offer, answer).media[0].agreedCodecs.map((c) => c.codec), ["PCMU"]);
});

test("negotiate: missing side throws", () => {
  assert.throws(() => negotiate(parseSdp(sdpOffer), null as unknown as SdpSession), /need both/);
});

// ─── lenient parsing of SDP that breaks RFC 8866 ─────────────────────────────
const base = "v=0\no=- 1 1 IN IP4 10.0.0.1\ns=-\nc=IN IP4 10.0.0.1\nt=0 0\nm=audio 4000 RTP/AVP 0 96\na=rtpmap:96 telephone-event/8000\n";
const codes = (text: string) => parseSdp(text).warnings.map((w) => w.code);

test("clean SDP: no warnings", () => {
  assert.deepEqual(parseSdp(base).warnings, []);
  assert.deepEqual(parseSdp(sdpOffer).warnings, []);
});

test("warning shape: code, reason, line number, line, action", () => {
  const [w] = parseSdp(base + "x=whatever\n").warnings;
  assert.deepEqual(Object.keys(w).sort(), ["action", "code", "line", "lineNumber", "reason"]);
  assert.equal(w.code, "unknown-line-type");
  assert.equal(w.lineNumber, 8);
  assert.equal(w.line, "x=whatever");
  assert.equal(w.action, "skipped");
  assert.equal(typeof w.reason, "string");
});

test("lines out of order are kept", () => {
  const r = parseSdp("v=0\no=- 1 1 IN IP4 10.0.0.1\ns=-\nt=0 0\nc=IN IP4 10.0.0.1\nm=audio 4000 RTP/AVP 0\n");
  assert.deepEqual(r.warnings.map((w) => [w.code, w.lineNumber]), [["out-of-order", 5]]);
  assert.equal(r.media[0].codecs[0].codec, "PCMU");
});

test("missing s= line: still parsed, reported", () => {
  const r = parseSdp(base.replace("s=-\n", ""));
  assert.deepEqual(r.warnings.map((w) => [w.code, w.lineNumber, w.line]), [["missing-mandatory-line", 0, ""]]);
  assert.equal(r.media.length, 1);
});

test("a=setup with a non-RFC value is kept in dtls.setup", () => {
  const r = parseSdp(base + "a=setup:client\na=fingerprint:sha-1 AA:BB\n");
  assert.deepEqual(r.media[0].dtls, { setup: "client", fingerprint: "sha-1 AA:BB" });
  assert.deepEqual(codes(base + "a=setup:client\n"), ["malformed-attribute"]);
});

test("m= with an unreadable port: port null, not rejected, later lines still attach", () => {
  const r = parseSdp(base.replace("m=audio 4000", "m=audio abc") + "a=sendonly\n");
  assert.equal(r.media[0].port, null);
  assert.equal(r.media[0].rejected, false);
  assert.equal(r.media[0].direction, "sendonly");
  assert.deepEqual(r.warnings.map((w) => w.code), ["malformed-media"]);
});

test("a=rtpmap without a clock rate (old devices) still names the codec", () => {
  const r = parseSdp(base.replace("a=rtpmap:96 telephone-event/8000", "a=rtpmap:96 telephone-event"));
  assert.deepEqual(r.media[0].codecs.find((c) => c.pt === 96), { pt: 96, codec: "telephone-event", rate: null, channels: 1, fmtp: null });
  assert.deepEqual(r.warnings.map((w) => w.code), ["malformed-attribute"]);
});

test("a=rtpmap for a payload type that is not in m= adds no codec", () => {
  const r = parseSdp(base + "a=rtpmap:8 PCMA/8000\n");
  assert.deepEqual(r.media[0].codecs.map((c) => c.pt), [96, 0]);
});

test("CR-only line endings and trailing whitespace", () => {
  const cr = parseSdp(base.replace(/\n/g, "\r"));
  assert.deepEqual(cr.warnings, []);
  assert.deepEqual(cr.media[0].codecs.map((c) => c.codec), ["telephone-event", "PCMU"]);
  const ws = parseSdp(base.replace("telephone-event/8000", "telephone-event/8000  "));
  assert.deepEqual(ws.warnings.map((w) => [w.code, w.action]), [["trailing-whitespace", "repaired"]]);
  assert.equal(ws.media[0].codecs[0].rate, 8000);
});

test("text that is not SDP: an empty model and warnings, no exception", () => {
  const r = parseSdp("hello world\nthis is not sdp");
  assert.deepEqual(r.media, []);
  assert.equal(r.origin, null);
  assert.ok(r.warnings.some((w) => w.code === "missing-version"));
});

// ─── adapter edge cases (simple-sdp model -> normalized model) ───────────────
test("fmtp is the parameter string as written", () => {
  const [m] = parseSdp(base + "a=fmtp:96 0-15,16\n").media;
  assert.equal(m.codecs[0].fmtp, "0-15,16");
  const [o] = parseSdp(sdpOffer.replace("minptime=10;useinbandfec=1", "minptime=10; useinbandfec=1")).media;
  assert.equal(o.codecs[0].fmtp, "minptime=10; useinbandfec=1");
});

test("protocol comes from the m= proto field", () => {
  assert.equal(parseSdp(sdpOffer).media[0].protocol, "UDP/TLS/RTP/SAVPF");
  assert.equal(parseSdp(base).media[0].protocol, "RTP/AVP");
});

test("static payload type with an explicit a=rtpmap is not marked static", () => {
  const [m] = parseSdp(base.replace("RTP/AVP 0 96", "RTP/AVP 0") + "a=rtpmap:0 PCMU/8000\n").media;
  assert.deepEqual(m.codecs, [{ pt: 0, codec: "PCMU", rate: 8000, channels: 1, fmtp: null }]);
});
