// Compiled (not run) by `npm run typecheck`: the published declarations work for a
// TypeScript consumer, through the package exports.
import {
  buildLadder, summarizeLadder, parseSdp, negotiate, parseSipMessage, parsePcap, reassembleSip,
  createOfferAnswerTracker,
  type Ladder, type LadderCall, type LadderMessage, type LadderSummary, type SdpSession,
  type SipMessage, type ObserveResult,
} from "@irbisadm/sip-pcap";
import type { SdpNegotiation, SdpResolvedCodec } from "@irbisadm/simple-sdp";
import { proxyCallPcap, classicPcap, udp, sip } from "@irbisadm/sip-pcap/testing";

const ladder: Ladder = buildLadder(proxyCallPcap(), { sipPort: null });
const summary: LadderSummary = summarizeLadder(ladder);
const call: LadderCall | undefined = ladder.calls[0];
const outcome: "ok" | "failed" | "cancelled" | "pending" | undefined = summary.calls[0]?.outcome;
const msg: LadderMessage | undefined = call?.messages[0];
const offerIndex: number | undefined = msg?.negotiation?.offerIndex;
const role: "offer" | "answer" | null | undefined = msg?.sdpRole;

const offer: SdpSession = parseSdp("v=0\r\n");
const n: SdpNegotiation = negotiate(offer, offer);
const agreed: SdpResolvedCodec | undefined = n.media[0]?.codecs[0];
const codec: string | undefined = agreed?.encodingName;
const origin: string | undefined = offer.model.origin?.sessId;

const m: SipMessage = parseSipMessage(sip("OPTIONS sip:x SIP/2.0", []));
const tracker = createOfferAnswerTracker({ maxOffers: 10 });
const r: ObserveResult = tracker.observe(m, { stepIndex: 0, hop: { src: "a:1", dst: "b:2" }, raw: "" });
const state: "stable" | "offer-pending" = tracker.state;

const raw = reassembleSip(parsePcap(classicPcap([{ ts: 0, frame: udp({ src: "10.0.0.1", dst: "10.0.0.2", payload: "x" }) }])));
const src: string | undefined = raw[0]?.src;

// @ts-expect-error sdpRole is not a free-form string
const bad: LadderMessage["sdpRole"] = "maybe";

export { outcome, offerIndex, role, codec, origin, r, state, src, bad };
