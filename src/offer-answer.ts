// SDP offer/answer bookkeeping for one SIP call or dialog: the role of every
// SDP-carrying message, the offer each answer responds to (per hop when hops are
// known), and retransmission detection. Used by the ladder and by stateful
// consumers such as the webrtc-mcp `sip_dialog` store.

import type { SdpNegotiation } from "@irbisadm/simple-sdp";
import type { RawSipMessage } from "./pcap.js";
import { negotiate, type SdpSession } from "./sdp.js";
import type { SipMessage } from "./sip.js";

/** Network hop of a message: `host:port` of sender and receiver. */
export type Hop = Pick<RawSipMessage, "src" | "dst">;

/**
 * What the tracker needs from a message. A `parseSipMessage` result fits.
 * `headers.rack` is used for PRACK (which INVITE it acknowledges). `statusCode`
 * tells a 1xx/2xx answer from SDP in an error response; without it every response
 * is treated as 1xx/2xx.
 */
export type OfferAnswerMessage = Pick<SipMessage, "kind" | "method" | "cseq" | "sdp">
  & Partial<Pick<SipMessage, "headers" | "statusCode">>;

export type SdpRole = "offer" | "answer";

export interface ObserveOptions {
  /** Caller's index of the message; echoed in results. */
  stepIndex?: number;
  /** Sender and receiver, when known (pcap). */
  hop?: Hop | null;
  /** Raw message text; with `hop`, used to spot retransmissions. */
  raw?: string;
  /** The caller already knows this is a retransmission. */
  retransmission?: boolean;
}

export type TrackedNegotiation = SdpNegotiation & { offerStep: number | null; answerStep: number | null };

export interface ObserveResult {
  /**
   * Null when the message has no SDP, or its SDP takes no part in offer/answer (an
   * error response, OPTIONS). For a retransmission, the role of the original message.
   */
  role: SdpRole | null;
  /** Same message already seen on the same hop; the state is unchanged. */
  retransmission: boolean;
  /** Set on an answer that could be paired with an offer. */
  negotiation: TrackedNegotiation | null;
  /**
   * On a 3xx-6xx response: the `stepIndex` of the offer it rejects. Null otherwise, and
   * when the offer was not observed with a `stepIndex`.
   */
  rejectedOfferStep: number | null;
}

export interface PendingOffer {
  sdp: SdpSession;
  stepIndex: number | null;
}

export interface OfferAnswerTracker {
  /** Feed the next message of the call, in order. */
  observe(msg: OfferAnswerMessage, opts?: ObserveOptions): ObserveResult;
  /** `offer-pending` while there is a `pendingOffer`, else `stable`. */
  readonly state: "stable" | "offer-pending";
  /** The latest unanswered offer. */
  readonly pendingOffer: PendingOffer | null;
  /** Result of the latest answered offer. */
  readonly negotiated: TrackedNegotiation | null;
}

export interface TrackerOptions {
  /** Offers kept for pairing; older ones are dropped. Default 50. */
  maxOffers?: number;
  /** Messages remembered for retransmission detection. Default unlimited. */
  maxFingerprints?: number;
}

/** Methods whose requests and 1xx/2xx responses take part in offer/answer. */
const OFFER_ANSWER_METHODS = new Set(["INVITE", "ACK", "PRACK", "UPDATE"]);

interface TrackedOffer extends PendingOffer {
  hop: Hop | null;
  seq: number | undefined;
  /** `requestKey` of an offer made in a request; null for a late offer in a response. */
  request: string | null;
}

/** `<CSeq number>|<CSeq method>`: the request a message belongs to. */
const requestKey = (msg: OfferAnswerMessage): string => `${msg.cseq?.seq}|${msg.cseq?.method}`;

/**
 * Create the offer/answer state of one call.
 *
 * Rules (RFC 3261 §13.2.1, RFC 3262, RFC 3311, RFC 3264, RFC 6337):
 * - only INVITE, ACK, PRACK and UPDATE and their 1xx/2xx responses carry offers
 *   and answers; SDP anywhere else (a 488 or 606 listing what the UA supports, an
 *   OPTIONS reply) has no role and leaves the state alone;
 * - a request with SDP is an offer, except ACK (it answers a late offer) and PRACK
 *   after a late offer in a reliable 1xx (the INVITE is found by the CSeq number in
 *   `RAck`, or by the PRACK's own CSeq number when `RAck` is missing);
 * - a 1xx/2xx response with SDP is an answer if its request (same CSeq number and
 *   method) offered, otherwise it is a late offer;
 * - a 3xx-6xx response to a request that offered rejects that offer: the state goes
 *   back to `stable`, the last negotiated result stays, and the offer no longer pairs
 *   with answers. Through a proxy, the rejection pairs with the offer on its own hop,
 *   like an answer;
 * - an answer pairs with the offer that crossed the same hop in the opposite
 *   direction, preferring one with the same CSeq number (`RAck` for PRACK), when hops
 *   are known; else the latest offer with the same CSeq number; else the latest offer;
 * - a retransmission (same raw text on the same hop) does not change the state.
 *
 * Roles come from the message itself rather than from what came before it, so a
 * proxied call is right: the INVITE forwarded by a proxy is a second offer on the
 * next hop, not the answer to the first one.
 */
export function createOfferAnswerTracker({ maxOffers = 50, maxFingerprints = Infinity }: TrackerOptions = {}): OfferAnswerTracker {
  /** "seq|METHOD" of requests that carried an offer */
  const offeredRequests = new Set<string>();
  /** INVITE CSeq numbers whose offer came in a response */
  const lateOffers = new Set<number | undefined>();
  const offers: TrackedOffer[] = [];
  /** hop|raw fingerprint → role of the first message with it */
  const seen = new Map<string, SdpRole | null>();

  let pendingOffer: PendingOffer | null = null;
  let negotiated: TrackedNegotiation | null = null;

  /** CSeq number of the INVITE a PRACK acknowledges (`RAck: <rseq> <cseq> <method>`). */
  function rackSeq(msg: OfferAnswerMessage): number | null {
    const v = msg.headers?.rack;
    const m = (Array.isArray(v) ? v[0] : v)?.match(/^\s*\d+\s+(\d+)\s+\w+/);
    return m ? parseInt(m[1], 10) : null;
  }

  const isRejection = (msg: OfferAnswerMessage) => msg.kind === "response" && (msg.statusCode ?? 0) >= 300;

  /**
   * The role of a message with SDP. Records what later messages depend on (requests
   * that offered, INVITEs with a late offer), so it is called once per message.
   */
  function assignRole(msg: OfferAnswerMessage): SdpRole | null {
    const seq = msg.cseq?.seq;
    if (!OFFER_ANSWER_METHODS.has((msg.kind === "request" ? msg.method : msg.cseq?.method) ?? "")) return null;
    if (isRejection(msg)) return null;
    if (msg.kind === "request") {
      if (msg.method === "ACK") return "answer";
      if (msg.method === "PRACK" && lateOffers.has(rackSeq(msg) ?? seq)) return "answer";
      offeredRequests.add(requestKey(msg));
      return "offer";
    }
    if (offeredRequests.has(requestKey(msg))) return "answer";
    if (msg.cseq?.method === "INVITE") lateOffers.add(seq);
    return "offer";
  }

  /** The latest kept offer that matches. */
  function latest(match: (o: TrackedOffer) => boolean): TrackedOffer | null {
    for (let i = offers.length - 1; i >= 0; i--) if (match(offers[i])) return offers[i];
    return null;
  }

  /** The offer crossed `hop` in the opposite direction. */
  const onHop = (o: TrackedOffer, hop: Hop | null) => !!hop && !!o.hop && o.hop.src === hop.dst && o.hop.dst === hop.src;

  function offerFor(msg: OfferAnswerMessage, hop: Hop | null): TrackedOffer | null {
    const seq = (msg.method === "PRACK" ? rackSeq(msg) : null) ?? msg.cseq?.seq;
    return latest((o) => onHop(o, hop) && o.seq === seq)
      ?? latest((o) => onHop(o, hop))
      ?? latest((o) => o.seq === seq)
      ?? offers[offers.length - 1]
      ?? null;
  }

  /** The offer a 3xx-6xx response rejects: made in its request, on its hop when known. */
  function rejectedOffer(msg: OfferAnswerMessage, hop: Hop | null): TrackedOffer | null {
    const key = requestKey(msg);
    return latest((o) => o.request === key && onHop(o, hop)) ?? latest((o) => o.request === key);
  }

  function observe(msg: OfferAnswerMessage, { stepIndex, hop = null, raw, retransmission: known = false }: ObserveOptions = {}): ObserveResult {
    const fp = raw != null ? `${hop ? `${hop.src}>${hop.dst}` : ""}|${raw}` : null;
    if (known || (fp !== null && seen.has(fp))) {
      return { role: (fp !== null ? seen.get(fp) : null) ?? null, retransmission: true, negotiation: null, rejectedOfferStep: null };
    }
    const step = stepIndex ?? null;
    let role: SdpRole | null = null;
    let negotiation: TrackedNegotiation | null = null;
    let rejectedOfferStep: number | null = null;
    if (isRejection(msg)) {
      if (offeredRequests.has(requestKey(msg))) pendingOffer = null;
      const rejected = rejectedOffer(msg, hop);
      if (rejected) {
        offers.splice(offers.indexOf(rejected), 1);
        rejectedOfferStep = rejected.stepIndex;
      }
    }
    if (msg.sdp) {
      role = assignRole(msg);
      if (role === "offer") {
        offers.push({
          sdp: msg.sdp, stepIndex: step, hop, seq: msg.cseq?.seq,
          request: msg.kind === "request" ? requestKey(msg) : null,
        });
        if (offers.length > maxOffers) offers.shift();
        pendingOffer = { sdp: msg.sdp, stepIndex: step };
      } else if (role === "answer") {
        const offer = offerFor(msg, hop);
        pendingOffer = null;
        if (offer) {
          negotiation = { ...negotiate(offer.sdp, msg.sdp), offerStep: offer.stepIndex, answerStep: step };
          negotiated = negotiation;
        }
      }
    }
    if (fp !== null && seen.size < maxFingerprints) seen.set(fp, role);
    return { role, retransmission: false, negotiation, rejectedOfferStep };
  }

  return {
    observe,
    get state() { return pendingOffer ? "offer-pending" : "stable"; },
    get pendingOffer() { return pendingOffer; },
    get negotiated() { return negotiated; },
  };
}
