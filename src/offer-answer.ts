// SDP offer/answer bookkeeping for one SIP call or dialog: the role of every
// SDP-carrying message, the offer each answer responds to (per hop when hops are
// known), and retransmission detection. Used by the ladder and by stateful
// consumers such as the webrtc-mcp `sip_dialog` store.

import { negotiate, type Negotiation, type SdpSession } from "./sdp.js";
import type { SipMessage } from "./sip.js";

/** Network hop of a message: `host:port` of sender and receiver. */
export interface Hop {
  src: string;
  dst: string;
}

/**
 * What the tracker needs from a message. A `parseSipMessage` result fits.
 * `headers.rack` is used for PRACK (which INVITE it acknowledges).
 */
export type OfferAnswerMessage = Pick<SipMessage, "kind" | "method" | "cseq" | "sdp"> & {
  headers?: SipMessage["headers"];
};

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

export type TrackedNegotiation = Negotiation & { offerStep: number | null; answerStep: number | null };

export interface ObserveResult {
  /** Null when the message has no SDP. For a retransmission, the role of the original message. */
  role: SdpRole | null;
  /** Same message already seen on the same hop; the state is unchanged. */
  retransmission: boolean;
  /** Set on an answer that could be paired with an offer. */
  negotiation: TrackedNegotiation | null;
}

export interface PendingOffer {
  sdp: SdpSession;
  stepIndex: number | null;
}

export interface OfferAnswerTracker {
  /** Feed the next message of the call, in order. */
  observe(msg: OfferAnswerMessage, opts?: ObserveOptions): ObserveResult;
  /** `offer-pending` after an offer until an answer arrives. */
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

interface TrackedOffer {
  sdp: SdpSession;
  stepIndex: number | null;
  hop: Hop | null;
  seq: number | undefined;
}

/**
 * Create the offer/answer state of one call.
 *
 * Rules (RFC 3264, RFC 6337):
 * - a request with SDP is an offer, except ACK (it answers a late offer) and PRACK
 *   after a late offer in a reliable 1xx (the INVITE is found by the CSeq number in
 *   `RAck`, or by the PRACK's own CSeq number when `RAck` is missing);
 * - a response with SDP is an answer if its request (same CSeq number and method)
 *   offered, otherwise it is a late offer;
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

  let state: OfferAnswerTracker["state"] = "stable";
  let pendingOffer: PendingOffer | null = null;
  let negotiated: TrackedNegotiation | null = null;

  /** CSeq number of the INVITE a PRACK acknowledges (`RAck: <rseq> <cseq> <method>`). */
  function rackSeq(msg: OfferAnswerMessage): number | null {
    const v = msg.headers?.rack;
    const m = (Array.isArray(v) ? v[0] : v)?.match(/^\s*\d+\s+(\d+)\s+\w+/);
    return m ? parseInt(m[1], 10) : null;
  }

  function roleOf(msg: OfferAnswerMessage): SdpRole {
    const seq = msg.cseq?.seq;
    const key = `${seq}|${msg.cseq?.method}`;
    if (msg.kind === "request") {
      if (msg.method === "ACK") return "answer";
      if (msg.method === "PRACK" && lateOffers.has(rackSeq(msg) ?? seq)) return "answer";
      offeredRequests.add(key);
      return "offer";
    }
    if (offeredRequests.has(key)) return "answer";
    if (msg.cseq?.method === "INVITE") lateOffers.add(seq);
    return "offer";
  }

  function offerFor(msg: OfferAnswerMessage, hop: Hop | null): TrackedOffer | null {
    const seq = (msg.method === "PRACK" ? rackSeq(msg) : null) ?? msg.cseq?.seq;
    const latest = (match: (o: TrackedOffer) => boolean) => {
      for (let i = offers.length - 1; i >= 0; i--) if (match(offers[i])) return offers[i];
      return null;
    };
    const onHop = (o: TrackedOffer) => !!hop && !!o.hop && o.hop.src === hop.dst && o.hop.dst === hop.src;
    return latest((o) => onHop(o) && o.seq === seq)
      ?? latest(onHop)
      ?? latest((o) => o.seq === seq)
      ?? offers[offers.length - 1]
      ?? null;
  }

  function observe(msg: OfferAnswerMessage, { stepIndex, hop = null, raw, retransmission: known = false }: ObserveOptions = {}): ObserveResult {
    const fp = raw != null ? `${hop ? `${hop.src}>${hop.dst}` : ""}|${raw}` : null;
    if (known || (fp !== null && seen.has(fp))) {
      return { role: (fp !== null ? seen.get(fp) : null) ?? null, retransmission: true, negotiation: null };
    }
    const step = stepIndex ?? null;
    let role: SdpRole | null = null;
    let negotiation: TrackedNegotiation | null = null;
    if (msg.sdp) {
      role = roleOf(msg);
      if (role === "offer") {
        offers.push({ sdp: msg.sdp, stepIndex: step, hop, seq: msg.cseq?.seq });
        if (offers.length > maxOffers) offers.shift();
        state = "offer-pending";
        pendingOffer = { sdp: msg.sdp, stepIndex: step };
      } else {
        const offer = offerFor(msg, hop);
        state = "stable";
        pendingOffer = null;
        if (offer) {
          try {
            negotiation = { ...negotiate(offer.sdp, msg.sdp), offerStep: offer.stepIndex, answerStep: step };
          } catch {
            negotiation = null;
          }
          negotiated = negotiation;
        }
      }
    }
    if (fp !== null && seen.size < maxFingerprints) seen.set(fp, role);
    return { role, retransmission: false, negotiation };
  }

  return {
    observe,
    get state() { return state; },
    get pendingOffer() { return pendingOffer; },
    get negotiated() { return negotiated; },
  };
}
