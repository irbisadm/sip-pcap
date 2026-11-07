// createOfferAnswerTracker on its own: roles, pairing per hop, late offers,
// PRACK, re-INVITE, retransmissions.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createOfferAnswerTracker, parseSipMessage } from "../src/index.js";
import type { ObserveResult } from "../src/offer-answer.js";
import { sip, proxyCallFlow, ALICE, PROXY, BOB } from "../src/testing/index.js";

const A = "10.0.0.1:5060", B = "10.0.0.2:5060";

const sdp = (pts: number[], dir = "sendrecv") => `v=0
o=- 1 1 IN IP4 10.0.0.1
s=-
c=IN IP4 10.0.0.1
t=0 0
m=audio 4000 RTP/AVP ${pts.join(" ")}
a=${dir}
`;
const hdrs = (cseq: string, extra: string[] = []) => [
  "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKoa",
  "From: <sip:a@x>;tag=fa",
  "To: <sip:b@x>;tag=tb",
  "Call-ID: oa@x",
  `CSeq: ${cseq}`,
  ...extra,
];

type Step = [src: string | null, dst: string | null, text: string];

/** Feed [src, dst, text] steps; returns the observe results. */
function run(steps: Step[], tracker = createOfferAnswerTracker()): ObserveResult[] {
  return steps.map(([src, dst, text], stepIndex) =>
    tracker.observe(parseSipMessage(text), { stepIndex, hop: src ? { src, dst } : null, raw: text }));
}

test("proxied call: two hops, two offer/answer pairs, each answer pairs with its own hop", () => {
  const tracker = createOfferAnswerTracker();
  const results = run(proxyCallFlow().map(([, src, dst, text]): Step => [src, dst, text]), tracker);
  const roles = results.map((r, i) => (r.role ? `${i}:${r.role}` : null)).filter(Boolean);
  assert.deepEqual(roles, ["0:offer", "2:offer", "5:answer", "6:answer"]);

  // 200 OK Bob -> proxy answers the INVITE proxy -> Bob
  assert.equal(results[5].negotiation.offerStep, 2);
  assert.equal(results[5].negotiation.answerStep, 5);
  // 200 OK proxy -> Alice answers Alice's INVITE, not the forwarded one
  assert.equal(results[6].negotiation.offerStep, 0);
  assert.equal(results[6].negotiation.answerStep, 6);
  for (const i of [5, 6]) {
    assert.deepEqual(results[i].negotiation.media[0].agreedCodecs.map((c) => c.codec), ["PCMU", "telephone-event"]);
  }
  assert.equal(tracker.state, "stable");
  assert.equal(tracker.pendingOffer, null);
  assert.equal(tracker.negotiated.offerStep, 0);
  assert.ok(results.every((r) => !r.retransmission));
  assert.deepEqual(results[2].negotiation, null);
  assert.equal(proxyCallFlow()[2][2], `${BOB}:5060`);
  assert.equal(proxyCallFlow()[2][1], `${PROXY}:5060`);
  assert.equal(proxyCallFlow()[0][1], `${ALICE}:5060`);
});

test("without hops the answer pairs with the latest offer of the same CSeq", () => {
  // the same proxied call as seen by a store that gets messages without endpoints
  const results = run(proxyCallFlow().map(([, , , text]): Step => [null, null, text]));
  assert.equal(results[5].negotiation.offerStep, 2);
  assert.equal(results[6].negotiation.offerStep, 2);
});

test("late offer: INVITE without SDP, offer in 200 OK, answer in ACK", () => {
  const tracker = createOfferAnswerTracker();
  const [inv, ok, ack] = run([
    [A, B, sip("INVITE sip:b@x SIP/2.0", hdrs("1 INVITE"))],
    [B, A, sip("SIP/2.0 200 OK", hdrs("1 INVITE"), sdp([0, 8]))],
    [A, B, sip("ACK sip:b@x SIP/2.0", hdrs("1 ACK"), sdp([8]))],
  ], tracker);
  assert.equal(inv.role, null);
  assert.equal(ok.role, "offer");
  assert.equal(ack.role, "answer");
  assert.equal(ack.negotiation.offerStep, 1);
  assert.deepEqual(ack.negotiation.media[0].agreedCodecs.map((c) => c.codec), ["PCMA"]);
  assert.equal(tracker.state, "stable");
});

test("late offer in a reliable 183 is answered by PRACK", () => {
  const [, early, prack] = run([
    [A, B, sip("INVITE sip:b@x SIP/2.0", hdrs("1 INVITE"))],
    [B, A, sip("SIP/2.0 183 Session Progress", [...hdrs("1 INVITE"), "Require: 100rel", "RSeq: 1"], sdp([0, 8]))],
    // PRACK has its own CSeq number; RAck names the INVITE (CSeq 1)
    [A, B, sip("PRACK sip:b@x SIP/2.0", [...hdrs("2 PRACK"), "RAck: 1 1 INVITE"], sdp([0]))],
  ]);
  assert.equal(early.role, "offer");
  assert.equal(prack.role, "answer");
  assert.equal(prack.negotiation.offerStep, 1);
});

test("PRACK without RAck falls back to its own CSeq number", () => {
  const [, , prack] = run([
    [A, B, sip("INVITE sip:b@x SIP/2.0", hdrs("1 INVITE"))],
    [B, A, sip("SIP/2.0 183 Session Progress", hdrs("1 INVITE"), sdp([0, 8]))],
    [A, B, sip("PRACK sip:b@x SIP/2.0", hdrs("1 PRACK"), sdp([0]))],
  ]);
  assert.equal(prack.role, "answer");
});

test("PRACK with SDP after an offering INVITE is a new offer", () => {
  const [inv, early, prack] = run([
    [A, B, sip("INVITE sip:b@x SIP/2.0", hdrs("1 INVITE"), sdp([0, 8]))],
    [B, A, sip("SIP/2.0 183 Session Progress", hdrs("1 INVITE"), sdp([0]))],
    [A, B, sip("PRACK sip:b@x SIP/2.0", hdrs("2 PRACK"), sdp([0]))],
  ]);
  assert.deepEqual([inv.role, early.role, prack.role], ["offer", "answer", "offer"]);
});

test("re-INVITE on hold: second offer/answer pair, negotiated hold", () => {
  const tracker = createOfferAnswerTracker();
  const r = run([
    [A, B, sip("INVITE sip:b@x SIP/2.0", hdrs("1 INVITE"), sdp([0]))],
    [B, A, sip("SIP/2.0 200 OK", hdrs("1 INVITE"), sdp([0]))],
    [A, B, sip("ACK sip:b@x SIP/2.0", hdrs("1 ACK"))],
    [A, B, sip("INVITE sip:b@x SIP/2.0", hdrs("2 INVITE"), sdp([0], "sendonly"))],
    [B, A, sip("SIP/2.0 200 OK", hdrs("2 INVITE"), sdp([0], "recvonly"))],
  ], tracker);
  assert.deepEqual(r.map((x) => x.role), ["offer", "answer", null, "offer", "answer"]);
  assert.equal(r[1].negotiation.hold, false);
  assert.equal(r[4].negotiation.offerStep, 3);
  assert.equal(r[4].negotiation.hold, true);
  assert.equal(tracker.negotiated.hold, true);
});

test("state follows offers and answers", () => {
  const tracker = createOfferAnswerTracker();
  assert.equal(tracker.state, "stable");
  run([[A, B, sip("INVITE sip:b@x SIP/2.0", hdrs("1 INVITE"), sdp([0]))]], tracker);
  assert.equal(tracker.state, "offer-pending");
  assert.equal(tracker.pendingOffer.stepIndex, 0);
  assert.equal(tracker.pendingOffer.sdp.media[0].codecs[0].codec, "PCMU");
  assert.equal(tracker.negotiated, null);
});

test("retransmission on the same hop: flagged, original role, no state change", () => {
  const tracker = createOfferAnswerTracker();
  const inv = sip("INVITE sip:b@x SIP/2.0", hdrs("1 INVITE"), sdp([0]));
  const ok = sip("SIP/2.0 200 OK", hdrs("1 INVITE"), sdp([0]));
  const r = run([[A, B, inv], [B, A, ok], [A, B, inv]], tracker);
  assert.deepEqual(r[2], { role: "offer", retransmission: true, negotiation: null });
  assert.equal(tracker.state, "stable", "the retransmitted offer does not reopen the exchange");
  assert.equal(tracker.negotiated.offerStep, 0);
});

test("the same text on another hop is not a retransmission", () => {
  const inv = sip("INVITE sip:b@x SIP/2.0", hdrs("1 INVITE"), sdp([0]));
  const r = run([[A, B, inv], [B, "10.0.0.3:5060", inv]]);
  assert.deepEqual(r.map((x) => [x.role, x.retransmission]), [["offer", false], ["offer", false]]);
});

test("a message without SDP is tracked for retransmissions too", () => {
  const ack = sip("ACK sip:b@x SIP/2.0", hdrs("1 ACK"));
  const r = run([[A, B, ack], [A, B, ack]]);
  assert.deepEqual(r.map((x) => [x.role, x.retransmission]), [[null, false], [null, true]]);
});

test("the caller can flag a retransmission itself", () => {
  const tracker = createOfferAnswerTracker();
  const msg = parseSipMessage(sip("INVITE sip:b@x SIP/2.0", hdrs("1 INVITE"), sdp([0])));
  const r = tracker.observe(msg, { stepIndex: 0, retransmission: true });
  assert.deepEqual(r, { role: null, retransmission: true, negotiation: null });
  assert.equal(tracker.state, "stable");
});

test("maxOffers bounds the offers kept for pairing", () => {
  const steps: Step[] = [
    [null, null, sip("INVITE sip:b@x SIP/2.0", hdrs("1 INVITE"), sdp([0]))],
    [null, null, sip("UPDATE sip:b@x SIP/2.0", hdrs("2 UPDATE"), sdp([8]))],
    [null, null, sip("SIP/2.0 200 OK", hdrs("1 INVITE"), sdp([0]))],
  ];
  // by default the answer finds the offer with its CSeq number
  assert.equal(run(steps)[2].negotiation.offerStep, 0);
  // with one offer kept, the INVITE's offer is gone and the latest offer is used
  assert.equal(run(steps, createOfferAnswerTracker({ maxOffers: 1 }))[2].negotiation.offerStep, 1);
});
