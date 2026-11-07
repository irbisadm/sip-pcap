// SIP ladder: turn a pcap/pcapng capture into calls (grouped by Call-ID), the
// network endpoints each call touched, and every SIP message between them in
// time order — with the SDP of each step and the offer/answer outcome per hop.
//
// Built on the same parsers as the MCP `sip_dialog` / `sdp_parse` tools
// (sdp-sip.js). Pure and runtime-neutral: used by the browser tool at
// webrtc.page/tools/sip-ladder and testable under node:test.

import { parsePcap, reassembleSip } from "./pcap.js";
import { parseSipMessage, type CSeq, type SipMessage } from "./sip.js";
import { negotiate, type Negotiation, type SdpSession } from "./sdp.js";

export type SdpRole = "offer" | "answer";

/** A network endpoint (`host:port`) the call touched. Proxies and SBCs are separate endpoints. */
export interface LadderEndpoint {
  /** `host:port`, IPv6 hosts in brackets. */
  addr: string;
  /** First User-Agent or Server header sent from this endpoint. */
  agent: string | null;
}

/** One SIP message of a call. */
export interface LadderMessage {
  /** Position in the call. */
  index: number;
  /** Capture timestamp, ms since the Unix epoch (fractional). */
  ts: number;
  /** Ms since the first message of the call. */
  rel: number;
  /** Sender `host:port`. */
  src: string;
  /** Receiver `host:port`. */
  dst: string;
  proto: "udp" | "tcp";
  kind: "request" | "response";
  /** Request method; null for responses. */
  method: string | null;
  /** Response code; null for requests. */
  statusCode: number | null;
  /** Reason phrase ("" for requests). */
  reason: string;
  /** Method, or `<code> <reason>`. */
  label: string;
  requestUri: string | null;
  cseq: CSeq | null;
  /** Branch parameter of the top Via. */
  branch: string | null;
  fromTag: string | null;
  toTag: string | null;
  /** The same message was already seen on the same hop. */
  retransmission: boolean;
  sdp: SdpSession | null;
  sdpRole: SdpRole | null;
  /** On an answer: the offer/answer result and the index of the offer it answers. */
  negotiation: (Negotiation & { offerIndex: number }) | null;
  /** The message as captured. */
  raw: string;
}

export type CallOutcome = "ok" | "failed" | "cancelled" | "pending";

export interface CallSummary {
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
export interface LadderCall extends CallSummary {
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
export interface LadderError {
  ts: number;
  src: string;
  dst: string;
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

export interface LadderCallSummary {
  index: number;
  id: string;
  from: string | null;
  to: string | null;
  method: string;
  status: string;
  outcome: CallOutcome;
  durationMs: number;
  messages: number;
  hosts: number;
}

export interface LadderSummary {
  packets: number;
  sipMessages: number;
  /** Number of unparsable messages. */
  errors: number;
  calls: LadderCallSummary[];
}

export interface LadderOptions {
  /** SIP port hint (default 5060); SIP on other ports is detected by content. `null` relies on content only. */
  sipPort?: number | null;
}

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

interface CallState {
  id: string;
  from: string | null;
  to: string | null;
  endpoints: LadderEndpoint[];
  endpointIdx: Map<string, number>;
  messages: LadderMessage[];
  seen: Set<string>;
  offeredRequests: Set<string>;
  lateOffer: Set<number | undefined>;
  offers: LadderMessage[];
}

// Offer/answer role of an SDP-carrying message (RFC 3264 / RFC 6337 usage):
// a request with SDP offers, unless it answers an offer sent in a response
// (ACK / PRACK after a late offer); a response answers when its request offered.
function sdpRole(msg: SipMessage, call: CallState): SdpRole | null {
  if (!msg.sdp) return null;
  const key = `${msg.cseq?.seq}|${msg.cseq?.method}`;
  if (msg.kind === "request") {
    if (msg.method === "ACK") return "answer";
    if (msg.method === "PRACK") return call.lateOffer.has(msg.cseq?.seq) ? "answer" : "offer";
    call.offeredRequests.add(key);
    return "offer";
  }
  if (call.offeredRequests.has(key)) return "answer";
  if (msg.cseq?.method === "INVITE") call.lateOffer.add(msg.cseq.seq);
  return "offer";
}

function summarize(call: { messages: LadderMessage[] }): CallSummary {
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
  const seq = first.cseq?.seq;
  const invResp = msgs.filter((m) => m.kind === "response" && m.cseq?.method === "INVITE" && m.cseq?.seq === seq);
  const ok = invResp.find((m) => code(m) >= 200 && code(m) < 300);
  const fail = invResp.find((m) => code(m) >= 300);
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
    const sdp = m.sdpRole ? ` (SDP ${m.sdpRole})` : "";
    const arrow = m.kind === "response" ? "-->>" : "->>";
    lines.push(`  ${alias.get(m.src)}${arrow}${alias.get(m.dst)}: ${clean(m.label + sdp)}`);
  }
  return lines.join("\n");
}

/** Read a pcap or pcapng capture and return its SIP calls. */
export function buildLadder(input: Uint8Array | ArrayBuffer | ArrayBufferView, { sipPort = 5060 }: LadderOptions = {}): Ladder {
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
        endpoints: [], endpointIdx: new Map(), messages: [], seen: new Set(),
        offeredRequests: new Set(), lateOffer: new Set(), offers: [],
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

    // the same datagram again on the same hop = retransmission (timer A/E/G)
    const fp = `${r.src}>${r.dst}|${r.raw}`;
    const retransmission = call.seen.has(fp);
    call.seen.add(fp);

    const m: LadderMessage = {
      index: call.messages.length,
      ts: r.ts,
      rel: 0,
      src: r.src,
      dst: r.dst,
      proto: r.proto,
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
      retransmission,
      sdp: msg.sdp,
      sdpRole: null,
      negotiation: null,
      raw: r.raw,
    };
    if (msg.sdp && !retransmission) {
      m.sdpRole = sdpRole(msg, call);
      if (m.sdpRole === "offer") {
        call.offers.push(m);
      } else {
        // pair with the offer that crossed the same hop in the other direction
        const offer = [...call.offers].reverse().find((o) => o.src === m.dst && o.dst === m.src)
          ?? call.offers[call.offers.length - 1];
        if (offer?.sdp) {
          try {
            m.negotiation = { offerIndex: offer.index, ...negotiate(offer.sdp, msg.sdp) };
          } catch {
            // leave negotiation null
          }
        }
      }
    } else if (msg.sdp) {
      m.sdpRole = call.messages.find((x) => x.raw === r.raw && x.sdpRole)?.sdpRole ?? null;
    }
    call.messages.push(m);
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
      ...summarize(c),
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
export function summarizeLadder(r: Ladder): LadderSummary {
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
