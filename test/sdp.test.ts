// parseSdp (normalized media model) and negotiate (RFC 3264).
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseSdp, negotiate } from "../src/index.js";
import type { SdpSession } from "../src/sdp.js";

const sdpOffer = [
  "v=0", "o=- 1 2 IN IP4 127.0.0.1", "s=-", "t=0 0", "a=group:BUNDLE 0 1",
  "m=audio 49170 UDP/TLS/RTP/SAVPF 111 0", "c=IN IP4 0.0.0.0", "a=mid:0", "a=sendrecv",
  "a=ice-ufrag:aaaa", "a=ice-pwd:bbbbbbbbbbbbbbbbbbbbbb",
  "a=fingerprint:sha-256 AA:BB", "a=setup:actpass",
  "a=rtpmap:111 opus/48000/2", "a=fmtp:111 minptime=10;useinbandfec=1",
  "a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level",
  "m=video 49172 UDP/TLS/RTP/SAVPF 96", "a=mid:1", "a=sendrecv", "a=rtpmap:96 VP8/90000",
].join("\r\n") + "\r\n";

const sdpAnswer = [
  "v=0", "o=- 9 2 IN IP4 127.0.0.1", "s=-", "t=0 0", "a=group:BUNDLE 0 1",
  "m=audio 49180 UDP/TLS/RTP/SAVPF 111", "c=IN IP4 0.0.0.0", "a=mid:0", "a=sendrecv",
  "a=setup:active", "a=rtpmap:111 opus/48000/2",
  "a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level",
  "m=video 0 UDP/TLS/RTP/SAVPF 96", "a=mid:1", "a=rtpmap:96 VP8/90000",
].join("\r\n") + "\r\n";

const sipSdp = `v=0
o=alice 2890844526 2890844526 IN IP4 192.0.2.10
s=-
c=IN IP4 192.0.2.10
t=0 0
m=audio 49170 RTP/AVP 0 8 18 101
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=fmtp:18 annexb=no
`;

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
