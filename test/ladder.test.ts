// Tests for buildLadder / summarizeLadder and the pcap paths they depend on:
// TCP reassembly, IP fragments, non-standard ports, containers and link layers.
import { test } from "node:test";
import assert from "node:assert/strict";
import { buildLadder, summarizeLadder } from "../src/ladder.js";
import { parsePcap, reassembleSip } from "../src/pcap.js";
import {
  udp, udpFragmented, tcp, classicPcap, pcapng, sip,
  ipv6Udp, ipv6UdpFragmented, ethernetV6, linuxSll2, ipv4Udp,
} from "../src/testing/pcap-builder.js";
import { proxyCallPcap, proxyCallFlow, ALICE, PROXY, BOB } from "../src/testing/sip-scenarios.js";

const sdp = (ip: string, pts: number[]) => `v=0
o=- 1 1 IN IP4 ${ip}
s=-
c=IN IP4 ${ip}
t=0 0
m=audio 4000 RTP/AVP ${pts.join(" ")}
${pts.map((p) => `a=rtpmap:${p} ${p === 0 ? "PCMU" : p === 8 ? "PCMA" : "opus"}/${p > 95 ? "48000/2" : "8000"}`).join("\n")}
`;
const base = (cseq: string, extra: string[] = []) => [
  "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1",
  "From: <sip:a@x>;tag=aa",
  "To: <sip:b@x>",
  "Call-ID: c1@x",
  `CSeq: ${cseq}`,
  ...extra,
];

test("proxy call: one call, three endpoints in order, completed with timings", () => {
  const r = buildLadder(proxyCallPcap());
  assert.equal(r.calls.length, 1);
  const c = r.calls[0];
  assert.deepEqual(c.endpoints.map((e) => e.addr), [`${ALICE}:5060`, `${PROXY}:5060`, `${BOB}:5060`]);
  assert.equal(c.messages.length, proxyCallFlow().length);
  assert.equal(c.method, "INVITE");
  assert.equal(c.status, "completed");
  assert.equal(c.outcome, "ok");
  assert.equal(c.ringMs, 71);
  assert.equal(c.answerMs, 4210);
  assert.equal(c.talkMs, 61800 - 4210);
  assert.equal(c.messages[0].rel, 0);
  assert.equal(c.endpoints[0].agent, "Linphone/5.2");
  assert.match(c.endpoints[1].agent, /Kamailio/);
});

test("proxy call: offer/answer per hop, negotiated PCMU on both legs", () => {
  const c = buildLadder(proxyCallPcap()).calls[0];
  const roles = c.messages.filter((m) => m.sdpRole).map((m) => `${m.label}:${m.sdpRole}`);
  assert.deepEqual(roles, ["INVITE:offer", "INVITE:offer", "200 OK:answer", "200 OK:answer"]);
  const answers = c.messages.filter((m) => m.sdpRole === "answer");
  // each answer pairs with the offer on its own hop
  assert.equal(c.messages[answers[0].negotiation.offerIndex].src, `${PROXY}:5060`);
  assert.equal(c.messages[answers[1].negotiation.offerIndex].src, `${ALICE}:5060`);
  for (const a of answers) {
    assert.deepEqual(a.negotiation.media[0].agreedCodecs.map((x) => x.codec), ["PCMU", "telephone-event"]);
  }
});

test("mermaid output names participants and marks SDP", () => {
  const c = buildLadder(proxyCallPcap()).calls[0];
  assert.match(c.mermaid, /^sequenceDiagram/);
  assert.match(c.mermaid, /participant P2 as 198\.51\.100\.1:5060/);
  assert.match(c.mermaid, /P1->>P2: INVITE \(SDP offer\)/);
  assert.match(c.mermaid, /P3-->>P2: 200 OK \(SDP answer\)/);
});

test("UDP retransmission of the same message on the same hop is flagged", () => {
  const inv = sip("INVITE sip:b@x SIP/2.0", base("1 INVITE"), sdp("10.0.0.1", [0]));
  const pcap = classicPcap([
    { ts: 0, frame: udp({ src: "10.0.0.1", dst: "10.0.0.2", payload: inv }) },
    { ts: 500, frame: udp({ src: "10.0.0.1", dst: "10.0.0.2", payload: inv }) },
  ]);
  const c = buildLadder(pcap).calls[0];
  assert.equal(c.messages.length, 2);
  assert.equal(c.messages[0].retransmission, false);
  assert.equal(c.messages[1].retransmission, true);
  assert.equal(c.messages[1].sdpRole, "offer");
});

test("late offer: INVITE without SDP, offer in 200 OK, answer in ACK", () => {
  const A = "10.0.0.1", B = "10.0.0.2";
  const pcap = classicPcap([
    { ts: 0, frame: udp({ src: A, dst: B, payload: sip("INVITE sip:b@x SIP/2.0", base("1 INVITE")) }) },
    { ts: 10, frame: udp({ src: B, dst: A, payload: sip("SIP/2.0 200 OK", base("1 INVITE").map((h) => h.replace("To: <sip:b@x>", "To: <sip:b@x>;tag=bb")), sdp(B, [0, 8])) }) },
    { ts: 20, frame: udp({ src: A, dst: B, payload: sip("ACK sip:b@x SIP/2.0", base("1 ACK"), sdp(A, [8])) }) },
  ]);
  const c = buildLadder(pcap).calls[0];
  assert.deepEqual(c.messages.map((m) => m.sdpRole), [null, "offer", "answer"]);
  assert.deepEqual(c.messages[2].negotiation.media[0].agreedCodecs.map((x) => x.codec), ["PCMA"]);
});

test("rejected call reports the final status", () => {
  const A = "10.0.0.1", B = "10.0.0.2";
  const pcap = classicPcap([
    { ts: 0, frame: udp({ src: A, dst: B, payload: sip("INVITE sip:b@x SIP/2.0", base("1 INVITE")) }) },
    { ts: 30, frame: udp({ src: B, dst: A, payload: sip("SIP/2.0 486 Busy Here", base("1 INVITE")) }) },
  ]);
  const c = buildLadder(pcap).calls[0];
  assert.equal(c.status, "486 Busy Here");
  assert.equal(c.outcome, "failed");
});

test("IPv4-fragmented INVITE is reassembled", () => {
  const big = sip("INVITE sip:b@x SIP/2.0", [...base("1 INVITE"), `X-Pad: ${"p".repeat(1500)}`], sdp("10.0.0.1", [111, 0]));
  const frames = udpFragmented({ src: "10.0.0.1", dst: "10.0.0.2", payload: big, mtu: 600 });
  assert.ok(frames.length >= 3);
  const r = buildLadder(classicPcap(frames.map((frame, i) => ({ ts: i, frame }))));
  assert.equal(r.sipMessages, 1);
  assert.equal(r.calls[0].messages[0].sdpRole, "offer");
  assert.equal(r.calls[0].messages[0].sdp.media[0].codecs[0].codec, "opus");
});

test("SIP on a non-standard port is found by content", () => {
  const pcap = classicPcap([
    { ts: 0, frame: udp({ src: "10.0.0.1", dst: "10.0.0.2", sport: 5080, dport: 5080, payload: sip("OPTIONS sip:b@x SIP/2.0", base("1 OPTIONS")) }) },
    { ts: 1, frame: udp({ src: "10.0.0.9", dst: "10.0.0.2", sport: 40000, dport: 53, payload: "not sip at all" }) },
  ]);
  const r = buildLadder(pcap);
  assert.equal(r.sipMessages, 1);
  assert.equal(r.calls[0].method, "OPTIONS");
});

test("TCP: out-of-order and retransmitted segments, per-message timestamps", () => {
  const m1 = sip("INVITE sip:b@x SIP/2.0", base("1 INVITE"), sdp("10.0.0.1", [0]));
  const m2 = sip("BYE sip:b@x SIP/2.0", base("2 BYE"));
  const stream = new TextEncoder().encode(m1 + m2);
  const cut = 40;
  const s0 = 1000;
  const seg = (from: number, to: number) => stream.subarray(from, to);
  const t = (seq: number, payload: Uint8Array) => tcp({ src: "10.0.0.1", dst: "10.0.0.2", sport: 40001, dport: 5060, seq, payload });
  const l1 = new TextEncoder().encode(m1).length;
  const pcap = classicPcap([
    { ts: 0, frame: t(s0 + cut, seg(cut, l1)) }, // arrives before its predecessor
    { ts: 1, frame: t(s0, seg(0, cut)) },
    { ts: 2, frame: t(s0, seg(0, cut)) }, // retransmission
    { ts: 900, frame: t(s0 + l1, seg(l1, stream.length)) },
  ]);
  const msgs = reassembleSip(parsePcap(pcap));
  assert.deepEqual(msgs.map((m) => m.raw.split(" ")[0]), ["INVITE", "BYE"]);
  assert.equal(msgs[0].raw, m1);
  assert.equal(msgs[1].ts, 900);
  assert.equal(msgs[0].proto, "tcp");
});

// ─── containers and link layers ────────────────────────────────────────────────
const twoMessages = () => [
  sip("INVITE sip:b@x SIP/2.0", base("1 INVITE")),
  sip("SIP/2.0 180 Ringing", base("1 INVITE")),
];

test("pcapng with nanosecond if_tsresol keeps sub-millisecond timing", () => {
  const [a, b] = twoMessages();
  const t0 = Date.UTC(2026, 10, 7, 12, 0, 0);
  const pcap = pcapng([
    { ts: t0, frame: udp({ src: "10.0.0.1", dst: "10.0.0.2", payload: a }) },
    { ts: t0 + 1.25, frame: udp({ src: "10.0.0.2", dst: "10.0.0.1", payload: b }) },
  ], { tsresol: 9 });
  const c = buildLadder(pcap).calls[0];
  assert.equal(c.messages.length, 2);
  assert.ok(Math.abs(c.messages[1].rel - 1.25) < 0.001, `rel ${c.messages[1].rel}`);
  assert.ok(Math.abs(c.startTs - t0) < 0.001);
});

test("classic pcap with nanosecond magic reads timestamps", () => {
  const [a, b] = twoMessages();
  const pcap = classicPcap([
    { ts: 1000, frame: udp({ src: "10.0.0.1", dst: "10.0.0.2", payload: a }) },
    { ts: 1000.5, frame: udp({ src: "10.0.0.2", dst: "10.0.0.1", payload: b }) },
  ], { nano: true });
  const c = buildLadder(pcap).calls[0];
  assert.ok(Math.abs(c.messages[1].rel - 0.5) < 0.001);
});

test("IPv6 with an extension header; endpoints use [addr]:port", () => {
  const [a, b] = twoMessages();
  const pcap = classicPcap([
    { ts: 0, frame: ethernetV6(ipv6Udp({ src: "2001:db8::10", dst: "2001:db8::20", payload: a })) },
    { ts: 5, frame: ethernetV6(ipv6Udp({ src: "2001:db8::20", dst: "2001:db8::10", payload: b })) },
  ]);
  const c = buildLadder(pcap).calls[0];
  assert.deepEqual(c.endpoints.map((e) => e.addr), ["[2001:db8::10]:5060", "[2001:db8::20]:5060"]);
});

test("IPv6-fragmented INVITE is reassembled", () => {
  const big = sip("INVITE sip:b@x SIP/2.0", [...base("1 INVITE"), `X-Pad: ${"p".repeat(1400)}`], sdp("10.0.0.1", [0]));
  const frags = ipv6UdpFragmented({ src: "2001:db8::10", dst: "2001:db8::20", payload: big, mtu: 600 });
  assert.ok(frags.length >= 3);
  const r = buildLadder(classicPcap(frags.map((p, i) => ({ ts: i, frame: ethernetV6(p) }))));
  assert.equal(r.sipMessages, 1);
  assert.equal(r.calls[0].messages[0].sdpRole, "offer");
});

test("Linux cooked capture v2 (LINKTYPE 276)", () => {
  const [a] = twoMessages();
  const pcap = classicPcap([{ ts: 0, frame: linuxSll2(ipv4Udp({ src: "10.0.0.1", dst: "10.0.0.2", payload: a })) }], { linkType: 276 });
  const r = buildLadder(pcap);
  assert.equal(r.sipMessages, 1);
  assert.equal(r.calls[0].messages[0].src, "10.0.0.1:5060");
});

// ─── worker contract: the page gets summaries, not messages ─────────────────────
test("summarizeLadder lists calls without their messages", () => {
  const r = buildLadder(proxyCallPcap());
  const s = summarizeLadder(r);
  assert.deepEqual(
    { packets: s.packets, sipMessages: s.sipMessages, errors: s.errors },
    { packets: 13, sipMessages: 13, errors: 0 },
  );
  assert.deepEqual(s.calls[0], {
    index: 0, id: r.calls[0].id, from: "sip:alice@example.com", to: "sip:bob@example.net",
    method: "INVITE", status: "completed", outcome: "ok", durationMs: 61873, messages: 13, hosts: 3,
  });
  assert.ok(!JSON.stringify(s).includes("v=0"), "no SIP/SDP text in the summary");
});
