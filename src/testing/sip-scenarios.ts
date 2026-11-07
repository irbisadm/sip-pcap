// Realistic SIP call through a proxy: Alice -> proxy -> Bob, INVITE to BYE, with an
// SDP offer/answer on each hop. Used by tests and to generate sample captures.

import { udp, classicPcap, sip } from "./pcap-builder.js";

export const ALICE = "192.0.2.10";
export const PROXY = "198.51.100.1";
export const BOB = "203.0.113.20";

const offerSdp = `v=0
o=alice 2890844526 2890844526 IN IP4 ${ALICE}
s=-
c=IN IP4 ${ALICE}
t=0 0
m=audio 49170 RTP/AVP 111 0 8 101
a=rtpmap:111 opus/48000/2
a=fmtp:111 useinbandfec=1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=sendrecv
`;

const answerSdp = `v=0
o=bob 2808844564 2808844564 IN IP4 ${BOB}
s=-
c=IN IP4 ${BOB}
t=0 0
m=audio 30000 RTP/AVP 0 101
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=sendrecv
`;

const callId = "a84b4c76e66710@pc33.example.com";
const fromA = "From: \"Alice\" <sip:alice@example.com>;tag=1928301774";
const toB = "To: <sip:bob@example.net>";
const toBt = "To: <sip:bob@example.net>;tag=a6c85cf";

const viaA = `Via: SIP/2.0/UDP ${ALICE}:5060;branch=z9hG4bK776asdhds`;
const viaP = `Via: SIP/2.0/UDP ${PROXY}:5060;branch=z9hG4bK4b43c2ff8.1`;
const viaAr = `${viaA};received=${ALICE}`;
const viaB2 = `Via: SIP/2.0/UDP ${BOB}:5060;branch=z9hG4bKnashds10`;
const viaPb = `Via: SIP/2.0/UDP ${PROXY}:5060;branch=z9hG4bK4b43c2ff8.2`;
const rr = `Record-Route: <sip:${PROXY};lr>`;
const ua = (n: string) => `User-Agent: ${n}`;
const contactA = `Contact: <sip:alice@${ALICE}:5060>`;
const contactB = `Contact: <sip:bob@${BOB}:5060>`;

/** One message of a scenario: [ms offset, src `host:port`, dst `host:port`, SIP text]. */
export type FlowStep = [offsetMs: number, src: string, dst: string, text: string];

/** Messages of the call. */
export function proxyCallFlow(): FlowStep[] {
  const invite = (via: string[]) => sip("INVITE sip:bob@example.net SIP/2.0", [
    ...via, "Max-Forwards: 70", fromA, toB, `Call-ID: ${callId}`, "CSeq: 314159 INVITE", contactA,
    "Allow: INVITE, ACK, CANCEL, BYE, OPTIONS", ua("Linphone/5.2"),
  ], offerSdp);
  const resp = (code: string, via: string[], to: string, extra: string[] = [], body = "") => sip(`SIP/2.0 ${code}`, [
    ...via, ...extra, fromA, to, `Call-ID: ${callId}`, "CSeq: 314159 INVITE",
  ], body);
  const ack = (via: string[], ruri: string) => sip(`ACK ${ruri} SIP/2.0`, [
    ...via, "Max-Forwards: 70", fromA, toBt, `Call-ID: ${callId}`, "CSeq: 314159 ACK",
  ]);
  const byeB = (via: string[], ruri: string) => sip(`BYE ${ruri} SIP/2.0`, [
    ...via, "Max-Forwards: 70", "From: <sip:bob@example.net>;tag=a6c85cf",
    "To: \"Alice\" <sip:alice@example.com>;tag=1928301774", `Call-ID: ${callId}`, "CSeq: 231 BYE", ua("Yealink SIP-T54W 96.86.0.70"),
  ]);
  const okBye = (via: string[]) => sip("SIP/2.0 200 OK", [
    ...via, "From: <sip:bob@example.net>;tag=a6c85cf",
    "To: \"Alice\" <sip:alice@example.com>;tag=1928301774", `Call-ID: ${callId}`, "CSeq: 231 BYE",
  ]);
  const A = `${ALICE}:5060`, P = `${PROXY}:5060`, B = `${BOB}:5060`;
  return [
    [0, A, P, invite([viaA])],
    [6, P, A, resp("100 Trying", [viaAr], toB, ["Server: Kamailio (6.1.5 (x86_64/linux))"])],
    [9, P, B, invite([viaP, viaAr])],
    [71, B, P, resp("180 Ringing", [viaP, viaAr], toBt, [contactB, ua("Yealink SIP-T54W 96.86.0.70")])],
    [74, P, A, resp("180 Ringing", [viaAr], toBt, [rr, contactB])],
    [4210, B, P, resp("200 OK", [viaP, viaAr], toBt, [rr, contactB], answerSdp)],
    [4214, P, A, resp("200 OK", [viaAr], toBt, [rr, contactB], answerSdp)],
    [4290, A, P, ack([viaA.replace("776asdhds", "998sdasdh09")], `sip:bob@${BOB}:5060`)],
    [4293, P, B, ack([viaPb, viaA.replace("776asdhds", "998sdasdh09")], `sip:bob@${BOB}:5060`)],
    [61800, B, P, byeB([viaB2], `sip:alice@${ALICE}:5060`)],
    [61803, P, A, byeB([viaPb.replace(".2", ".3"), viaB2], `sip:alice@${ALICE}:5060`)],
    [61870, A, P, okBye([viaPb.replace(".2", ".3"), viaB2])],
    [61873, P, B, okBye([viaB2])],
  ];
}

/**
 * The call as a classic pcap (Ethernet/IPv4/UDP, port 5060).
 * `t0`: timestamp of the first message, ms since the Unix epoch.
 */
export function proxyCallPcap({ t0 = Date.UTC(2026, 10, 7, 12, 0, 0) }: { t0?: number } = {}): Uint8Array {
  return classicPcap(proxyCallFlow().map(([dt, src, dst, text], i) => {
    const [sip4, sport] = src.split(":");
    const [dip4, dport] = dst.split(":");
    return { ts: t0 + dt, frame: udp({ src: sip4, dst: dip4, sport: +sport, dport: +dport, payload: text, id: 100 + i }) };
  }));
}
