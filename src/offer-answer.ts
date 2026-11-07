// Offer/answer role of an SDP-carrying SIP message and offer↔answer pairing per hop.
// Imported from irbisadm/webrtc-mcp src/lib/sdp-sip.js.

import { negotiate, type Negotiation, type SdpSession } from "./sdp.js";
import type { SipMessage } from "./sip.js";

const MAX_OFFERS = 50;

type Hop = { src: string; dst: string };

/** The offer/answer part of the webrtc-mcp `sip_dialog` store's dialog object. */
export interface OfferAnswerDialog {
  oaState: "stable" | "offer-pending";
  pendingOffer: { sdp: SdpSession; stepIndex: number } | null;
  negotiated: (Negotiation & { offerStep: number; answerStep: number }) | null;
  /** "seq|METHOD" of requests that carried an offer */
  offeredRequests: Set<string>;
  /** INVITE CSeq numbers whose offer came in a response */
  lateOffers: Set<number | undefined>;
  offers: { sdp: SdpSession; stepIndex: number; hop: Hop | null; cseq: SipMessage["cseq"] }[];
}

// Offer/answer role of an SDP-carrying message, from the message itself rather
// than from what came before it (RFC 3264, RFC 6337): a request with SDP offers,
// except ACK (answers a late offer) and PRACK after a late offer in a reliable
// 1xx; a response answers when its request offered, otherwise it is a late offer.
// This keeps a proxied call right: the INVITE forwarded by the proxy is a second
// offer on the next hop, not the answer to the first one.
function sdpRoleOf(dialog: OfferAnswerDialog, msg: SipMessage): "offer" | "answer" {
  const cseqKey = `${msg.cseq?.seq}|${msg.cseq?.method}`;
  if (msg.kind === "request") {
    if (msg.method === "ACK") return "answer";
    if (msg.method === "PRACK" && dialog.lateOffers.has(msg.cseq?.seq)) return "answer";
    dialog.offeredRequests.add(cseqKey);
    return "offer";
  }
  if (dialog.offeredRequests.has(cseqKey)) return "answer";
  if (msg.cseq?.method === "INVITE") dialog.lateOffers.add(msg.cseq.seq);
  return "offer";
}

// The offer an answer responds to: the one that crossed the same hop the other
// way when endpoints are known (pcap), else the latest offer of the same CSeq,
// else the latest offer.
function offerFor(dialog: OfferAnswerDialog, msg: SipMessage, hop: Hop | null) {
  const offers = dialog.offers;
  for (let i = offers.length - 1; i >= 0; i--) {
    const o = offers[i];
    if (hop && o.hop && o.hop.src === hop.dst && o.hop.dst === hop.src) return o;
  }
  for (let i = offers.length - 1; i >= 0; i--) {
    if (offers[i].cseq?.seq === msg.cseq?.seq) return offers[i];
  }
  return offers[offers.length - 1] ?? null;
}

/**
 * Record the offer/answer role of a step carrying SDP. Mutates dialog.
 * @internal Still shaped for the `sip_dialog` store; not part of the public API.
 */
export function applyOfferAnswer(dialog: OfferAnswerDialog, msg: SipMessage, stepIndex: number, hop: Hop | null): "offer" | "answer" | null {
  if (!msg.sdp) return null;
  const role = sdpRoleOf(dialog, msg);
  if (role === "offer") {
    dialog.offers.push({ sdp: msg.sdp, stepIndex, hop, cseq: msg.cseq });
    if (dialog.offers.length > MAX_OFFERS) dialog.offers.shift();
    dialog.oaState = "offer-pending";
    dialog.pendingOffer = { sdp: msg.sdp, stepIndex };
    return "offer";
  }
  const offer = offerFor(dialog, msg, hop);
  dialog.oaState = "stable";
  dialog.pendingOffer = null;
  if (offer) {
    try {
      dialog.negotiated = { ...negotiate(offer.sdp, msg.sdp), offerStep: offer.stepIndex, answerStep: stepIndex };
    } catch {
      dialog.negotiated = null;
    }
  }
  return "answer";
}
