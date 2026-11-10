// parseSipMessage: start lines, headers (compact forms, folding, repeats), tags,
// CSeq, SDP bodies (plain and multipart).
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseSipMessage } from "../src/index.js";

const sdpBody = [
  "v=0", "o=- 1 2 IN IP4 127.0.0.1", "s=-", "c=IN IP4 127.0.0.1", "t=0 0",
  "m=audio 49170 RTP/AVP 0", "a=sendrecv",
].join("\r\n") + "\r\n";

function sip(lines: string[], body = ""): string {
  return lines.join("\r\n") + "\r\nContent-Length: " + body.length + "\r\n\r\n" + body;
}

const invite = sip([
  "INVITE sip:bob@biloxi.com SIP/2.0",
  "Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds",
  "Via: SIP/2.0/UDP bigbox3.site3.atlanta.com;branch=z9hG4bK77ef4c2312983.1",
  "From: Alice <sip:alice@a.com>;tag=alice1",
  "To: Bob <sip:bob@biloxi.com>",
  "Call-ID: call-abc@pc",
  "CSeq: 1 INVITE",
  "User-Agent: Linphone/5.2",
  "Content-Type: application/sdp",
], sdpBody);

const ok200 = sip([
  "SIP/2.0 200 OK",
  "Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds",
  "From: Alice <sip:alice@a.com>;tag=alice1",
  "To: Bob <sip:bob@biloxi.com>;tag=bob1",
  "Call-ID: call-abc@pc",
  "CSeq: 1 INVITE",
  "Content-Type: application/sdp",
], sdpBody);

test("request: start line, tags, CSeq, headers, SDP", () => {
  const m = parseSipMessage(invite);
  assert.equal(m.kind, "request");
  assert.equal(m.method, "INVITE");
  assert.equal(m.requestUri, "sip:bob@biloxi.com");
  assert.equal(m.statusCode, null);
  assert.equal(m.reasonPhrase, null);
  assert.equal(m.callId, "call-abc@pc");
  assert.equal(m.fromUri, "sip:alice@a.com");
  assert.equal(m.fromTag, "alice1");
  assert.equal(m.toUri, "sip:bob@biloxi.com");
  assert.equal(m.toTag, null);
  assert.deepEqual(m.cseq, { seq: 1, method: "INVITE" });
  assert.equal(m.contentType, "application/sdp");
  assert.equal(m.headers.via.length, 2, "Via is always an array, in order");
  assert.equal(m.headers["user-agent"], "Linphone/5.2");
  assert.equal(m.sdp.media[0].codecs[0].encodingName, "PCMU");
  assert.equal(m.body, sdpBody.replace(/\r\n/g, "\n"));
});

test("response: status code, reason phrase, To tag", () => {
  const m = parseSipMessage(ok200);
  assert.equal(m.kind, "response");
  assert.equal(m.method, null);
  assert.equal(m.statusCode, 200);
  assert.equal(m.reasonPhrase, "OK");
  assert.equal(m.toTag, "bob1");
  assert.equal(m.headers.via.length, 1);
  assert.ok(m.sdp);
});

test("compact header forms", () => {
  const msg = "OPTIONS sip:x SIP/2.0\r\nv: SIP/2.0/UDP h;branch=z9hG4bKc\r\ni: c1@h\r\nf: <sip:a@h>;tag=t1\r\nt: <sip:b@h>\r\nm: <sip:a@h>\r\nl: 0\r\n\r\n";
  const p = parseSipMessage(msg);
  assert.equal(p.callId, "c1@h");
  assert.equal(p.fromTag, "t1");
  assert.equal(p.toUri, "sip:b@h");
  assert.deepEqual(p.headers.via, ["SIP/2.0/UDP h;branch=z9hG4bKc"]);
  assert.equal(p.headers.contact, "<sip:a@h>");
  assert.equal(p.headers["content-length"], "0");
});

test("compact Content-Type with an SDP body", () => {
  const p = parseSipMessage(sip(["INVITE sip:b@x SIP/2.0", "i: c@x", "CSeq: 1 INVITE", "c: application/sdp"], sdpBody));
  assert.equal(p.contentType, "application/sdp");
  assert.ok(p.sdp);
});

test("folded header lines are unfolded", () => {
  const p = parseSipMessage("OPTIONS sip:x SIP/2.0\r\nSubject: first\r\n  second\r\nCall-ID: c@x\r\n\r\n");
  assert.equal(p.headers.subject, "first second");
  assert.equal(p.callId, "c@x");
});

test("repeated headers become arrays; the first value is used for From/To/Call-ID", () => {
  const p = parseSipMessage("OPTIONS sip:x SIP/2.0\r\nRecord-Route: <sip:p1;lr>\r\nRecord-Route: <sip:p2;lr>\r\nCall-ID: a@x\r\nCall-ID: b@x\r\n\r\n");
  assert.deepEqual(p.headers["record-route"], ["<sip:p1;lr>", "<sip:p2;lr>"]);
  assert.equal(p.callId, "a@x");
});

test("LF-only line endings", () => {
  const p = parseSipMessage(invite.replace(/\r\n/g, "\n"));
  assert.equal(p.method, "INVITE");
  assert.ok(p.sdp);
});

test("multipart body: the application/sdp part is parsed", () => {
  const body = [
    "--unique-boundary-1",
    "Content-Type: application/sdp",
    "",
    sdpBody.trimEnd(),
    "--unique-boundary-1",
    "Content-Type: application/isup; version=itu-t92+",
    "Content-Disposition: signal; handling=optional",
    "",
    "\x01\x00\x49\x00",
    "--unique-boundary-1--",
    "",
  ].join("\r\n");
  const p = parseSipMessage(sip([
    "INVITE sip:b@x SIP/2.0", "Call-ID: mp@x", "CSeq: 1 INVITE",
    "Content-Type: multipart/mixed;boundary=unique-boundary-1", "MIME-Version: 1.0",
  ], body));
  assert.match(p.contentType, /^multipart\/mixed/);
  assert.ok(p.sdp, "SDP found inside multipart");
  assert.equal(p.sdp.media.length, 1);
  assert.equal(p.sdp.media[0].port, 49170);
});

test("multipart body without an SDP part", () => {
  const body = "--b\r\nContent-Type: text/plain\r\n\r\nhello\r\n--b--\r\n";
  const p = parseSipMessage(sip(["MESSAGE sip:b@x SIP/2.0", "Call-ID: m@x", "CSeq: 1 MESSAGE", "Content-Type: multipart/mixed;boundary=b"], body));
  assert.equal(p.sdp, null);
});

test("non-SDP body is kept but not parsed", () => {
  const p = parseSipMessage(sip(["MESSAGE sip:b@x SIP/2.0", "Call-ID: m@x", "CSeq: 1 MESSAGE", "Content-Type: text/plain"], "v=0 is not SDP here"));
  assert.equal(p.sdp, null);
  assert.equal(p.body, "v=0 is not SDP here");
});

test("header names from Object.prototype are ordinary headers", () => {
  const p = parseSipMessage(sip(["OPTIONS sip:b@x SIP/2.0", "Constructor: c", "__proto__: p", "toString: t", "toString: u"]));
  assert.equal(p.headers.constructor, "c");
  assert.equal(p.headers.__proto__, "p");
  assert.deepEqual(p.headers.tostring, ["t", "u"]);
  assert.equal(Object.getPrototypeOf(p.headers), null);
  assert.equal(parseSipMessage(sip(["OPTIONS sip:b@x SIP/2.0"])).headers.constructor, undefined);
});

test("no headers needed beyond the start line", () => {
  const p = parseSipMessage("BYE sip:b@x SIP/2.0\r\n\r\n");
  assert.equal(p.method, "BYE");
  assert.equal(p.callId, null);
  assert.equal(p.cseq, null);
  assert.equal(p.fromTag, null);
  assert.equal(p.contentType, "");
});

test("errors: not a string, empty, unknown method", () => {
  // @ts-expect-error not a string
  assert.throws(() => parseSipMessage(42), /expected string/);
  assert.throws(() => parseSipMessage(""), /empty start line/);
  assert.throws(() => parseSipMessage("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), /unrecognized start line/);
});

test("SDP warnings: empty for clean SDP, no SDP without a body", () => {
  assert.deepEqual(parseSipMessage(invite).sdp.warnings, []);
  assert.equal(parseSipMessage("BYE sip:b@x SIP/2.0\r\n\r\n").sdp, null);
});

test("SDP warnings: SDP that breaks RFC 8866 is parsed and its problems listed", () => {
  const broken = sdpBody.replace("t=0 0\r\n", "").replace("s=-\r\n", "s=-\r\nx=1\r\n");
  const p = parseSipMessage(sip(["INVITE sip:b@x SIP/2.0", "Call-ID: w@x", "CSeq: 1 INVITE", "Content-Type: application/sdp"], broken));
  assert.ok(p.sdp, "SDP kept");
  assert.equal(p.sdp.media[0].codecs[0].encodingName, "PCMU");
  assert.deepEqual(p.sdp.warnings.map((w) => w.code), ["unknown-line-type", "missing-mandatory-line"]);
});
