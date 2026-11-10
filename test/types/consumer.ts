// Compiled (not run) by `npm run typecheck`: the published declarations work for a
// TypeScript consumer, through the package exports.
import {
  buildLadder, summarizeLadder, parseSdp, negotiate, parseSipMessage, parsePcap, reassembleSip,
  createOfferAnswerTracker,
  type Ladder, type LadderCall, type LadderMessage, type CallList, type SdpSession,
  type SdpNegotiation, type SdpResolvedCodec, type SipMessage, type ObserveResult, type CaptureInput,
} from "@irbisadm/sip-pcap";
import { proxyCallPcap, classicPcap, udp, sip } from "@irbisadm/sip-pcap/testing";

const ladder: Ladder = buildLadder(proxyCallPcap(), { sipPort: null });
const summary: CallList = summarizeLadder(ladder);
const call: LadderCall | undefined = ladder.calls[0];
const outcome: "ok" | "failed" | "cancelled" | "pending" | undefined = summary.calls[0]?.outcome;
const msg: LadderMessage | undefined = call?.messages[0];
const offerStep: number | undefined = msg?.negotiation?.offerStep;
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

const packets = parsePcap(classicPcap([{ ts: 0, frame: udp({ src: "10.0.0.1", dst: "10.0.0.2", payload: "x" }) }]));
const raw = reassembleSip(packets);
const src: string | undefined = raw[0]?.src;
const p0 = packets[0];
const seq: number | undefined = p0?.proto === "tcp" ? p0.seq : undefined;
// @ts-expect-error seq exists on TCP packets only
const noSeq = p0?.seq;
const input: CaptureInput = new Uint8Array(0);

// @ts-expect-error sdpRole is not a free-form string
const bad: LadderMessage["sdpRole"] = "maybe";

export { seq, noSeq, input, outcome, offerStep, role, codec, origin, r, state, src, bad };
