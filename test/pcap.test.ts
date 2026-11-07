// parsePcap / reassembleSip: containers, input types, packet fields, SIP detection.
// Containers, link layers, fragments and TCP reassembly through buildLadder are
// covered in ladder.test.js.
import { test } from "node:test";
import assert from "node:assert/strict";
import { parsePcap, reassembleSip } from "../src/index.js";
import { udp, tcp, classicPcap, pcapng, sip, ipv4Udp } from "../src/testing/index.js";

const hdrs = (cseq: string) => ["Via: SIP/2.0/UDP 10.0.0.1;branch=z9hG4bKp", "From: <sip:a@x>;tag=a", "To: <sip:b@x>", "Call-ID: p@x", `CSeq: ${cseq}`];
const invite = sip("INVITE sip:b@x SIP/2.0", hdrs("1 INVITE"));
const ok = sip("SIP/2.0 200 OK", hdrs("1 INVITE"));

test("classic pcap: UDP/5060 packets and SIP messages", () => {
  const buf = classicPcap([
    { ts: 1000, frame: udp({ src: "10.0.0.1", dst: "10.0.0.2", payload: invite }) },
    { ts: 1001.5, frame: udp({ src: "10.0.0.2", dst: "10.0.0.1", payload: ok }) },
  ]);
  const packets = parsePcap(buf);
  assert.equal(packets.length, 2);
  const [p] = packets;
  assert.equal(p.proto, "udp");
  assert.equal(p.src, "10.0.0.1");
  assert.equal(p.dst, "10.0.0.2");
  assert.equal(p.sport, 5060);
  assert.equal(p.dport, 5060);
  assert.equal(p.ts, 1000);
  assert.equal(new TextDecoder().decode(p.payload), invite);

  const msgs = reassembleSip(packets, { sipPort: 5060 });
  assert.deepEqual(msgs.map((m) => [m.src, m.dst, m.proto, m.ts]), [
    ["10.0.0.1:5060", "10.0.0.2:5060", "udp", 1000],
    ["10.0.0.2:5060", "10.0.0.1:5060", "udp", 1001.5],
  ]);
  assert.equal(msgs[0].raw, invite);
});

test("pcapng: UDP/5060 packets and SIP messages", () => {
  const buf = pcapng([
    { ts: 5000, frame: udp({ src: "10.0.0.1", dst: "10.0.0.2", payload: invite }) },
    { ts: 5002, frame: udp({ src: "10.0.0.2", dst: "10.0.0.1", payload: ok }) },
  ]);
  const packets = parsePcap(buf);
  assert.equal(packets.length, 2);
  assert.equal(packets[1].ts, 5002);
  assert.equal(reassembleSip(packets).length, 2);
});

test("input as ArrayBuffer, Uint8Array view and DataView", () => {
  const bytes = classicPcap([{ ts: 0, frame: udp({ src: "10.0.0.1", dst: "10.0.0.2", payload: invite }) }]);
  // a view with an offset into a larger buffer
  const big = new Uint8Array(bytes.length + 7);
  big.set(bytes, 7);
  const view = big.subarray(7);
  assert.equal(parsePcap(view).length, 1);
  assert.equal(parsePcap(bytes.slice().buffer).length, 1);
  assert.equal(parsePcap(new DataView(big.buffer, 7)).length, 1);
});

test("raw IP link type (LINKTYPE_RAW 101)", () => {
  const buf = classicPcap([{ ts: 0, frame: ipv4Udp({ src: "10.0.0.1", dst: "10.0.0.2", payload: invite }) }], { linkType: 101 });
  assert.equal(reassembleSip(parsePcap(buf)).length, 1);
});

test("unsupported link types and non-UDP/TCP packets are skipped", () => {
  const frame = udp({ src: "10.0.0.1", dst: "10.0.0.2", payload: invite });
  assert.deepEqual(parsePcap(classicPcap([{ ts: 0, frame }], { linkType: 147 })), []);
  const icmp = frame.slice();
  icmp[14 + 9] = 1; // IPv4 protocol: ICMP
  assert.deepEqual(parsePcap(classicPcap([{ ts: 0, frame: icmp }])), []);
});

test("a truncated last record is ignored", () => {
  const buf = classicPcap([
    { ts: 0, frame: udp({ src: "10.0.0.1", dst: "10.0.0.2", payload: invite }) },
    { ts: 1, frame: udp({ src: "10.0.0.2", dst: "10.0.0.1", payload: ok }) },
  ]);
  assert.equal(parsePcap(buf.subarray(0, buf.length - 10)).length, 1);
});

test("TCP packets carry seq and flags", () => {
  const buf = classicPcap([{ ts: 0, frame: tcp({ src: "10.0.0.1", dst: "10.0.0.2", sport: 40000, dport: 5060, seq: 77, payload: invite }) }]);
  const [p] = parsePcap(buf);
  assert.equal(p.proto, "tcp");
  assert.equal(p.seq, 77);
  assert.equal(p.flags, 0x18);
  const [m] = reassembleSip([p]);
  assert.equal(m.raw, invite);
  assert.equal(m.src, "10.0.0.1:40000");
});

test("sipPort: null finds SIP by content only; non-SIP on port 5060 is dropped", () => {
  const buf = classicPcap([
    { ts: 0, frame: udp({ src: "10.0.0.1", dst: "10.0.0.2", sport: 5070, dport: 5070, payload: invite }) },
    { ts: 1, frame: udp({ src: "10.0.0.1", dst: "10.0.0.2", payload: "\r\n\r\n" }) }, // keep-alive
    { ts: 2, frame: udp({ src: "10.0.0.1", dst: "10.0.0.2", payload: "HELLO" }) },
  ]);
  const packets = parsePcap(buf);
  assert.equal(reassembleSip(packets, { sipPort: null }).length, 1);
  assert.equal(reassembleSip(packets).length, 1);
});

test("TCP: several messages in one segment, CRLF keep-alives between them", () => {
  const bye = sip("BYE sip:b@x SIP/2.0", hdrs("2 BYE"));
  const buf = classicPcap([{ ts: 0, frame: tcp({ src: "10.0.0.1", dst: "10.0.0.2", sport: 40000, dport: 5060, seq: 1, payload: invite + "\r\n\r\n" + bye }) }]);
  assert.deepEqual(reassembleSip(parsePcap(buf)).map((m) => m.raw), [invite, bye]);
});

test("TCP: capture starting mid-message resyncs on the next start line", () => {
  const bye = sip("BYE sip:b@x SIP/2.0", hdrs("2 BYE"));
  const tail = invite.slice(30);
  const buf = classicPcap([{ ts: 0, frame: tcp({ src: "10.0.0.1", dst: "10.0.0.2", sport: 40000, dport: 5060, seq: 1, payload: tail + bye }) }]);
  assert.deepEqual(reassembleSip(parsePcap(buf)).map((m) => m.raw), [bye]);
});

test("TCP: Content-Length counts bytes, not characters", () => {
  const body = "v=0\r\ns=Привет\r\n";
  const msg = sip("MESSAGE sip:b@x SIP/2.0", hdrs("3 MESSAGE"), body);
  const bye = sip("BYE sip:b@x SIP/2.0", hdrs("4 BYE"));
  const buf = classicPcap([{ ts: 0, frame: tcp({ src: "10.0.0.1", dst: "10.0.0.2", sport: 40000, dport: 5060, seq: 1, payload: msg + bye }) }]);
  assert.deepEqual(reassembleSip(parsePcap(buf)).map((m) => m.raw), [msg, bye]);
});

test("errors: too small, unknown magic", () => {
  assert.throws(() => parsePcap(new Uint8Array([1, 2])), /too small/);
  assert.throws(() => parsePcap(new Uint8Array([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])), /unknown magic/);
  // @ts-expect-error not bytes
  assert.throws(() => parsePcap("pcap"), /expected Uint8Array/);
});
