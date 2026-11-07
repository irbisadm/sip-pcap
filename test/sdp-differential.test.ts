// parseSdp on @irbisadm/simple-sdp against the previous implementation on
// sdp-transform (test/lib/legacy-sdp.ts): for every real SDP in test/fixtures/sdp,
// every SDP in the test scenarios and a few SIP cases, the result is the same apart
// from the intended differences listed in the README ("SDP parsing"), which
// `intended()` applies to the old result. The inputs are valid SDP; how broken SDP
// is handled is covered in sdp.test.ts.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import sdpTransform from "sdp-transform";
import { parseSdp, parseSipMessage, type SdpSession } from "../src/index.js";
import { proxyCallFlow } from "../src/testing/index.js";
import { legacyParseSdp } from "./lib/legacy-sdp.js";
import { sdpOffer, sdpAnswer, sipSdp } from "./lib/sdp-samples.js";

type Model = Omit<SdpSession, "warnings">;

const str = (v: unknown): string | null => (v === null || v === undefined ? null : String(v));

/** The old result with the intended differences applied. */
function intended(old: Model, text: string): Model {
  const session = sdpTransform.parse(text);
  const out: Model = structuredClone(old);
  if (out.origin) out.origin.username = String(out.origin.username); // 3. strings stay strings
  out.media = out.media.map((m, i) => {
    const raw = session.media[i];
    // 1. non-RTP media (webrtc-datachannel) have no codecs, not a bogus "PTNaN" entry
    const codecs = /(^|\/)RTP\//.test(m.protocol)
      ? m.codecs.map((c) => ({ ...c, fmtp: str(c.fmtp) }))
      : [];
    // 2. session-level direction, ICE and DTLS attributes apply to media without their own
    const ufrag = raw.iceUfrag ?? session.iceUfrag;
    const pwd = raw.icePwd ?? session.icePwd;
    const fp = raw.fingerprint ?? session.fingerprint;
    const setup = raw.setup ?? session.setup;
    return {
      ...m,
      direction: raw.direction ?? session.direction ?? "sendrecv",
      codecs,
      ice: ufrag !== undefined || pwd !== undefined ? { ufrag: str(ufrag), pwd: str(pwd) } : null,
      dtls: fp !== undefined || setup !== undefined
        ? { setup: setup ?? null, fingerprint: fp ? `${fp.type} ${fp.hash}` : null }
        : null,
    };
  });
  out.hold = out.media.some((m) => m.direction !== "sendrecv");
  return out;
}

const fixturesDir = new URL("./fixtures/sdp/", import.meta.url);
const fixtures = readdirSync(fixturesDir).filter((f) => f.endsWith(".sdp")).sort();

const scenarioSdps = proxyCallFlow()
  .map(([, , , text]) => parseSipMessage(text))
  .filter((m) => m.sdp)
  .map((m, i): [string, string] => [`proxy scenario SDP ${i}`, m.body]);

const sipCases: [string, string][] = [
  ["session-level a=sendonly (SIP hold)", sipSdp.replace("t=0 0\n", "t=0 0\na=sendonly\n")],
  ["session-level a=inactive, media a=sendrecv", sipSdp.replace("t=0 0\n", "t=0 0\na=inactive\n") + "a=sendrecv\n"],
  ["numeric ICE ufrag", sdpOffer.replace("a=ice-ufrag:aaaa", "a=ice-ufrag:1234")],
  ["numeric username in o=", sipSdp.replace("o=alice", "o=1001")],
  ["fmtp with spaces and a numeric value", sipSdp.replace("a=fmtp:18 annexb=no", "a=fmtp:18 annexb=no; bitrate=8000\na=fmtp:101 15")
    .replace("a=fmtp:101 0-16\n", "")],
  ["64-bit session id", sipSdp.replace("2890844526 2890844526", "4611731400430051336 2")],
  ["IPv6 origin", sipSdp.replace("IN IP4 192.0.2.10\ns=", "IN IP6 2001:db8::10\ns=")],
  ["two BUNDLE groups, the last one wins", sdpOffer.replace("a=group:BUNDLE 0 1", "a=group:BUNDLE 0\r\na=group:BUNDLE 0 1")],
  ["encrypted header extension (RFC 6904)", sdpOffer.replace("a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level", "a=extmap:1 urn:ietf:params:rtp-hdrext:encrypt urn:ietf:params:rtp-hdrext:ssrc-audio-level")],
  ["static and dynamic types, rtpmap with channels", "v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\ns=-\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\nm=audio 4000 RTP/AVP 96 0 9 97 13\r\na=rtpmap:96 opus/48000/2\r\na=rtpmap:97 L16/16000/2\r\n"],
  ["LF line endings", sipSdp],
];

const cases: [string, string][] = [
  ...fixtures.map((f): [string, string] => [f, readFileSync(new URL(f, fixturesDir), "utf8")]),
  ...scenarioSdps,
  ["test sample: WebRTC offer", sdpOffer],
  ["test sample: WebRTC answer", sdpAnswer],
  ...sipCases,
];

test("there are fixtures to compare", () => {
  assert.equal(fixtures.length, 31);
  assert.ok(scenarioSdps.length >= 2);
});

for (const [name, text] of cases) {
  test(`same as the sdp-transform parser: ${name}`, () => {
    const { warnings, ...now } = parseSdp(text);
    assert.deepEqual(warnings, [], "valid SDP parses without warnings");
    assert.deepEqual(now, intended(legacyParseSdp(text), text));
  });
}

// The differences themselves, so that each one is checked to really happen.
test("difference 1: no bogus codec for non-RTP media", () => {
  const text = readFileSync(new URL("chrome-datachannel-offer.sdp", fixturesDir), "utf8");
  assert.equal(legacyParseSdp(text).media[0].codecs[0].codec, "PTNaN");
  assert.deepEqual(parseSdp(text).media[0].codecs, []);
});

test("difference 2: session-level attributes apply to media", () => {
  const text = readFileSync(new URL("firefox-audio-only-offer.sdp", fixturesDir), "utf8");
  assert.equal(legacyParseSdp(text).media[0].dtls.fingerprint, null);
  assert.match(parseSdp(text).media[0].dtls.fingerprint, /^sha-256 8E:FE/);
  const hold = sipCases[0][1];
  assert.equal(legacyParseSdp(hold).hold, false);
  assert.equal(parseSdp(hold).media[0].direction, "sendonly");
  assert.equal(parseSdp(hold).hold, true);
});

test("difference 3: integer-looking strings stay strings", () => {
  const text = sipCases[2][1];
  assert.equal(legacyParseSdp(text).media[0].ice.ufrag, 1234 as unknown as string);
  assert.equal(parseSdp(text).media[0].ice.ufrag, "1234");
  const fmtp = sipCases[4][1];
  assert.equal(legacyParseSdp(fmtp).media[0].codecs.find((c) => c.pt === 101).fmtp, 15 as unknown as string);
  assert.equal(parseSdp(fmtp).media[0].codecs.find((c) => c.pt === 101).fmtp, "15");
});
