// SIP ladder: turn a pcap/pcapng capture into calls (grouped by Call-ID), the
// network endpoints each call touched, and every SIP message between them in
// time order, with the SDP of each step and the offer/answer outcome per hop.
// Pure and runtime-neutral: runs in Node.js, browsers and Web Workers.

import { parsePcap, reassembleSip, type CaptureInput, type RawSipMessage, type ReassembleOptions } from "./pcap.js";
import { parseSipMessage, type SipMessage } from "./sip.js";
import { createOfferAnswerTracker, type OfferAnswerTracker, type SdpRole, type TrackedNegotiation } from "./offer-answer.js";

/** A network endpoint (`host:port`) the call touched. Proxies and SBCs are separate endpoints. */
export interface LadderEndpoint {
  /** `host:port`, IPv6 hosts in brackets. */
  addr: string;
  /** First User-Agent or Server header sent from this endpoint. */
  agent: string | null;
}

/**
 * One SIP message of a call: where and when it was captured (`RawSipMessage`), the
 * parsed fields the ladder needs (`SipMessage`), and its place in the call.
 * `sdp.warnings` lists where the SDP breaks RFC 8866, e.g. to show "SDP had N problems".
 */
export interface LadderMessage extends RawSipMessage,
  Pick<SipMessage, "kind" | "method" | "statusCode" | "requestUri" | "cseq" | "fromTag" | "toTag" | "sdp"> {
  /** Position in the call. */
  index: number;
  /** Ms since the first message of the call. */
  rel: number;
  /** Reason phrase ("" for requests). */
  reason: string;
  /** Method, or `<code> <reason>`. */
  label: string;
  /** Branch parameter of the top Via. */
  branch: string | null;
  /** The same message was already seen on the same hop. */
  retransmission: boolean;
  sdpRole: SdpRole | null;
  /**
   * On an answer: the offer/answer result, with the `index` of the offer it answers
   * (`offerStep`) and of this message (`answerStep`).
   */
  negotiation: (TrackedNegotiation & { offerStep: number; answerStep: number }) | null;
  /** On a 3xx-6xx response that rejects an offer: the `index` of that offer. */
  rejectedOfferStep: number | null;
}

export type CallOutcome = "ok" | "failed" | "cancelled" | "pending";

/** How a call ended: status, outcome and, for INVITE calls, timings. */
export interface CallResult {
  /** Method of the first request. */
  method: string;
  /** E.g. `completed`, `cancelled`, `486 Busy Here`. */
  status: string;
  outcome: CallOutcome;
  /** Time from the INVITE to the first 18x (INVITE calls). */
  ringMs?: number | null;
  /** Time from the INVITE to the 2xx (INVITE calls). */
  answerMs?: number | null;
  /** Time from the 2xx to the BYE (INVITE calls). */
  talkMs?: number | null;
}

/** One call: all messages with the same Call-ID. */
export interface LadderCall extends CallResult {
  /** Call-ID. */
  id: string;
  from: string | null;
  to: string | null;
  /** Timestamp of the first message, ms since the Unix epoch. */
  startTs: number;
  durationMs: number;
  endpoints: LadderEndpoint[];
  messages: LadderMessage[];
  /** Mermaid sequence diagram of the call. */
  mermaid: string;
}

/** A message that looked like SIP but did not parse. */
export interface LadderError extends Pick<RawSipMessage, "ts" | "src" | "dst"> {
  error: string;
}

export interface Ladder {
  /** UDP/TCP packets decoded from the capture. */
  packets: number;
  /** SIP messages found. */
  sipMessages: number;
  /** Ordered by start time. */
  calls: LadderCall[];
  errors: LadderError[];
}

/** A row of `CallList`: the fields of `LadderCall` a call list shows. */
export interface CallListItem
  extends Pick<LadderCall, "id" | "from" | "to" | "method" | "status" | "outcome" | "durationMs"> {
  /** Index in `ladder.calls`. */
  index: number;
  /** Number of messages. */
  messages: number;
  /** Number of endpoints. */
  hosts: number;
}

/** `summarizeLadder()`: the calls of a ladder without their messages, e.g. for a page fed by a worker. */
export interface CallList extends Pick<Ladder, "packets" | "sipMessages"> {
  /** Number of unparsable messages. */
  errors: number;
  calls: CallListItem[];
}

/** `sipPort` is passed to `reassembleSip`. */
export type LadderOptions = ReassembleOptions;

const header = (msg: SipMessage, name: string): string | null => {
  const v = msg.headers[name];
  return Array.isArray(v) ? v[0] : v ?? null;
};

function topViaBranch(msg: SipMessage): string | null {
  const via = msg.headers.via?.[0];
  const m = via && via.match(/;branch=([^;\s,]+)/i);
  return m ? m[1] : null;
}

function labelOf(msg: SipMessage): string {
  if (msg.kind === "request") return msg.method ?? "";
  return `${msg.statusCode} ${msg.reasonPhrase || ""}`.trim();
}

const code = (m: LadderMessage): number => m.statusCode ?? 0;

function callResult(call: { messages: LadderMessage[] }): CallResult {
  const msgs = call.messages;
  const first = msgs.find((m) => m.kind === "request" && !m.retransmission) ?? msgs[0];
  const method = first?.method ?? "?";
  if (method !== "INVITE") {
    const final = [...msgs].reverse().find((m) => m.kind === "response" && code(m) >= 200);
    return {
      method,
      status: final ? `${final.statusCode} ${final.reason}`.trim() : "no final response",
      outcome: !final ? "pending" : code(final) < 300 ? "ok" : "failed",
    };
  }
  // The initial INVITE and its retries: an INVITE challenged with 401/407 is sent
  // again with the next CSeq number (RFC 3261 §22.2), still without a To tag. A
  // re-INVITE inside the dialog has a To tag and does not count.
  const initialSeqs = new Set(msgs
    .filter((m) => m.kind === "request" && m.method === "INVITE" && !m.toTag)
    .map((m) => m.cseq?.seq));
  if (initialSeqs.size === 0) initialSeqs.add(first.cseq?.seq);
  const invResp = msgs.filter((m) => m.kind === "response" && m.cseq?.method === "INVITE" && initialSeqs.has(m.cseq?.seq));
  const ok = invResp.find((m) => code(m) >= 200 && code(m) < 300);
  // the last final error: a challenge followed by a retry that also fails reports the retry's code
  const fail = [...invResp].reverse().find((m) => code(m) >= 300);
  const ringing = invResp.find((m) => code(m) >= 180 && code(m) < 200);
  const bye = msgs.find((m) => m.method === "BYE");
  const cancel = msgs.find((m) => m.method === "CANCEL");
  const t0 = first.ts;
  const timing = {
    ringMs: ringing ? ringing.ts - t0 : null,
    answerMs: ok ? ok.ts - t0 : null,
    talkMs: ok && bye ? bye.ts - ok.ts : null,
  };
  if (ok && bye) return { method, status: "completed", outcome: "ok", ...timing };
  if (ok) return { method, status: "answered, no BYE in capture", outcome: "ok", ...timing };
  if (cancel) return { method, status: "cancelled", outcome: "cancelled", ...timing };
  if (fail) return { method, status: `${fail.statusCode} ${fail.reason}`.trim(), outcome: "failed", ...timing };
  return { method, status: "no final response", outcome: "pending", ...timing };
}

function mermaidOf(call: { endpoints: LadderEndpoint[]; messages: LadderMessage[] }): string {
  const alias = new Map(call.endpoints.map((e, i) => [e.addr, `P${i + 1}`]));
  const clean = (t: unknown) => String(t).replace(/[;#\n]/g, " ").trim();
  const lines = ["sequenceDiagram"];
  for (const e of call.endpoints) lines.push(`  participant ${alias.get(e.addr)} as ${clean(e.addr)}`);
  for (const m of call.messages) {
    const sdp = m.sdpRole ? ` (SDP ${m.sdpRole})` : m.rejectedOfferStep !== null ? " (SDP offer rejected)" : "";
    const arrow = m.kind === "response" ? "-->>" : "->>";
    lines.push(`  ${alias.get(m.src)}${arrow}${alias.get(m.dst)}: ${clean(m.label + sdp)}`);
  }
  return lines.join("\n");
}

interface CallState extends Pick<LadderCall, "id" | "from" | "to" | "endpoints" | "messages"> {
  endpointIdx: Map<string, number>;
  tracker: OfferAnswerTracker;
}

/** Read a pcap or pcapng capture and return its SIP calls. */
export function buildLadder(input: CaptureInput, { sipPort = 5060 }: LadderOptions = {}): Ladder {
  const packets = parsePcap(input);
  const raw = reassembleSip(packets, { sipPort });
  const calls = new Map<string, CallState>();
  const errors: LadderError[] = [];

  for (const r of raw) {
    let msg: SipMessage;
    try {
      msg = parseSipMessage(r.raw);
    } catch (e) {
      errors.push({ ts: r.ts, src: r.src, dst: r.dst, error: e instanceof Error ? e.message : String(e) });
      continue;
    }
    const id = msg.callId || "(no Call-ID)";
    let call = calls.get(id);
    if (!call) {
      call = {
        id, from: msg.fromUri, to: msg.toUri,
        endpoints: [], endpointIdx: new Map(), messages: [],
        tracker: createOfferAnswerTracker({ maxOffers: Infinity }),
      };
      calls.set(id, call);
    }
    for (const addr of [r.src, r.dst]) {
      if (!call.endpointIdx.has(addr)) {
        call.endpointIdx.set(addr, call.endpoints.length);
        call.endpoints.push({ addr, agent: null });
      }
    }
    const agent = header(msg, "user-agent") || header(msg, "server");
    if (agent) {
      const ep = call.endpoints[call.endpointIdx.get(r.src)!];
      ep.agent ||= agent;
    }

    const index = call.messages.length;
    // the same datagram again on the same hop is a retransmission (timer A/E/G)
    const oa = call.tracker.observe(msg, { stepIndex: index, hop: { src: r.src, dst: r.dst }, raw: r.raw });
    // every message is observed with its stepIndex, so both steps are set
    const negotiation = oa.negotiation as LadderMessage["negotiation"];

    call.messages.push({
      ...r,
      index,
      rel: 0,
      kind: msg.kind,
      method: msg.method,
      statusCode: msg.statusCode,
      reason: msg.reasonPhrase || "",
      label: labelOf(msg),
      requestUri: msg.requestUri,
      cseq: msg.cseq,
      branch: topViaBranch(msg),
      fromTag: msg.fromTag,
      toTag: msg.toTag,
      retransmission: oa.retransmission,
      sdp: msg.sdp,
      sdpRole: oa.role,
      negotiation,
      rejectedOfferStep: oa.rejectedOfferStep,
    });
  }

  const out = [...calls.values()].map((c): LadderCall => {
    const t0 = c.messages[0]?.ts ?? 0;
    for (const m of c.messages) m.rel = m.ts - t0;
    const base = {
      id: c.id,
      from: c.from,
      to: c.to,
      startTs: t0,
      durationMs: (c.messages[c.messages.length - 1]?.ts ?? t0) - t0,
      endpoints: c.endpoints,
      messages: c.messages,
      ...callResult(c),
    };
    return { ...base, mermaid: mermaidOf(base) };
  });
  out.sort((a, b) => a.startTs - b.startTs);

  return { packets: packets.length, sipMessages: raw.length, calls: out, errors };
}

/**
 * What a call list needs, without the messages: the browser tool's worker keeps
 * the full result and sends the page only this, then one call at a time.
 */
export function summarizeLadder(r: Ladder): CallList {
  return {
    packets: r.packets,
    sipMessages: r.sipMessages,
    errors: r.errors.length,
    calls: r.calls.map((c, index) => ({
      index, id: c.id, from: c.from, to: c.to, method: c.method, status: c.status, outcome: c.outcome,
      durationMs: c.durationMs, messages: c.messages.length, hosts: c.endpoints.length,
    })),
  };
}
