// parsePcap / reassembleSip: containers, input types, packet fields, SIP detection.
// Containers, link layers, fragments and TCP reassembly through buildLadder are
// covered in ladder.test.js.
import { test } from "node:test";
import assert from "node:assert/strict";
import { parsePcap, reassembleSip } from "../src/index.js";
import { udp, tcp, classicPcap, pcapng, sip, ipv4Udp, ipv6Udp, ethernetPppoe, ipTunnel } from "../src/testing/index.js";

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

// ─── what is not SIP, found on real captures ─────────────────────────────────
for (const [name, payload] of [
  ["SSDP NOTIFY", "NOTIFY * HTTP/1.1\r\nHost: 239.255.255.250:1900\r\n\r\n"],
  ["SSDP M-SEARCH", "M-SEARCH * HTTP/1.1\r\nHost: 239.255.255.250:1900\r\n\r\n"],
  ["HTTP OPTIONS", "OPTIONS / HTTP/1.1\r\nHost: x\r\n\r\n"],
  ["HTTP with a SIP method", "MESSAGE /x HTTP/1.1\r\nHost: x\r\n\r\n"],
  ["RTSP OPTIONS", "OPTIONS rtsp://x/ RTSP/1.0\r\nCSeq: 1\r\n\r\n"],
  ["plain words", "hello world\r\n"],
  ["plain words, no line end", "hello world"],
] as const) {
  test(`not SIP: ${name}, on any port, over UDP and TCP`, () => {
    const a = { src: "10.0.0.1", dst: "10.0.0.2" };
    for (const frame of [
      udp({ ...a, sport: 1900, dport: 1900, payload }),
      udp({ ...a, payload }),
      tcp({ ...a, sport: 40000, dport: 80, seq: 1, payload }),
      tcp({ ...a, sport: 40000, dport: 5060, seq: 1, payload }),
    ]) {
      assert.deepEqual(reassembleSip(parsePcap(classicPcap([{ ts: 0, frame }]))), []);
    }
  });
}

test("a request URI longer than a short peek is still found on any port", () => {
  const long = sip(`INVITE sip:${"a".repeat(300)}@x SIP/2.0`, hdrs("1 INVITE"));
  const frame = udp({ src: "10.0.0.1", dst: "10.0.0.2", sport: 7000, dport: 7000, payload: long });
  assert.equal(reassembleSip(parsePcap(classicPcap([{ ts: 0, frame }]))).length, 1);
});

test("TCP on any port: a start line split between two segments is found", () => {
  const a = { src: "10.0.0.1", dst: "10.0.0.2", sport: 40000, dport: 7000 };
  const bytes = new TextEncoder().encode(invite);
  const buf = classicPcap([
    { ts: 0, frame: tcp({ ...a, seq: 1, payload: bytes.subarray(0, 20) }) },
    { ts: 1, frame: tcp({ ...a, seq: 21, payload: bytes.subarray(20) }) },
  ]);
  assert.deepEqual(reassembleSip(parsePcap(buf)).map((m) => m.raw), [invite]);
});

test("TCP: an HTTP request after SIP on the same stream does not resync as SIP", () => {
  const bye = sip("BYE sip:b@x SIP/2.0", hdrs("2 BYE"));
  const buf = classicPcap([{ ts: 0, frame: tcp({ src: "10.0.0.1", dst: "10.0.0.2", sport: 40000, dport: 5060, seq: 1, payload: "garbage\r\nOPTIONS / HTTP/1.1\r\nHost: x\r\n\r\n" + bye }) }]);
  assert.deepEqual(reassembleSip(parsePcap(buf)).map((m) => m.raw), [bye]);
});

// ─── encapsulation ───────────────────────────────────────────────────────────
const inner = { src: "10.0.0.1", dst: "10.0.0.2", payload: invite };
const inner6 = { src: "2001:db8::1", dst: "2001:db8::2", payload: invite };

test("PPPoE session over Ethernet, IPv4 and IPv6", () => {
  const v4 = reassembleSip(parsePcap(classicPcap([{ ts: 0, frame: ethernetPppoe(ipv4Udp(inner)) }])));
  assert.deepEqual(v4.map((m) => [m.src, m.raw]), [["10.0.0.1:5060", invite]]);
  const v6 = reassembleSip(parsePcap(classicPcap([{ ts: 0, frame: ethernetPppoe(ipv6Udp(inner6)) }])));
  assert.deepEqual(v6.map((m) => m.src), ["[2001:db8::1]:5060"]);
});

test("PPPoE frames that are not IP, or are cut short, are skipped", () => {
  const lcp = ethernetPppoe(ipv4Udp(inner));
  lcp[14 + 6] = 0xc0; lcp[14 + 7] = 0x21; // PPP LCP
  assert.deepEqual(parsePcap(classicPcap([{ ts: 0, frame: lcp }])), []);
  const cut = ethernetPppoe(ipv4Udp(inner)).subarray(0, 18);
  assert.deepEqual(parsePcap(classicPcap([{ ts: 0, frame: cut }])), []);
});

test("IP tunnels: the inner endpoints are used, for 4in4, 6in4, 4in6 and 6in6", () => {
  const out4 = { src: "192.0.2.1", dst: "192.0.2.2" };
  const out6 = { src: "2001:db8:f::1", dst: "2001:db8:f::2" };
  for (const [packet, want] of [
    [ipTunnel({ ...out4, packet: ipv4Udp(inner) }), "10.0.0.1:5060"],
    [ipTunnel({ ...out4, packet: ipv6Udp(inner6) }), "[2001:db8::1]:5060"],
    [ipTunnel({ ...out6, packet: ipv4Udp(inner) }), "10.0.0.1:5060"],
    [ipTunnel({ ...out6, packet: ipv6Udp(inner6) }), "[2001:db8::1]:5060"],
  ] as const) {
    const msgs = reassembleSip(parsePcap(classicPcap([{ ts: 0, frame: packet }], { linkType: 101 })));
    assert.deepEqual(msgs.map((m) => [m.src, m.raw]), [[want, invite]]);
  }
});

test("IP tunnels nested without end stop at a depth limit", () => {
  let packet = ipv4Udp(inner);
  for (let i = 0; i < 4; i++) packet = ipTunnel({ src: "192.0.2.1", dst: "192.0.2.2", packet });
  assert.equal(parsePcap(classicPcap([{ ts: 0, frame: packet }], { linkType: 101 })).length, 1);
  for (let i = 0; i < 1; i++) packet = ipTunnel({ src: "192.0.2.1", dst: "192.0.2.2", packet });
  assert.deepEqual(parsePcap(classicPcap([{ ts: 0, frame: packet }], { linkType: 101 })), []);
});
