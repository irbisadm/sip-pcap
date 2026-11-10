// SIP message parser: start line, headers (compact forms, folding), tags, CSeq,
// SDP body (incl. multipart).

import { parseSdp, type SdpSession } from "./sdp.js";

export interface CSeq {
  seq: number;
  /** Upper case. */
  method: string;
}

/**
 * Header values by lower-case name. Compact forms are expanded, repeated headers
 * become arrays, and `via` is always an array. The object has no prototype, so header
 * names such as `constructor` or `__proto__` are ordinary keys.
 */
export type SipHeaders = Record<string, string | string[]> & { via?: string[] };

/** A parsed SIP message. */
export interface SipMessage {
  kind: "request" | "response";
  /** Request method, upper case; null for responses. */
  method: string | null;
  /** Null for requests. */
  statusCode: number | null;
  /** Null for requests. */
  reasonPhrase: string | null;
  /** Null for responses. */
  requestUri: string | null;
  headers: SipHeaders;
  callId: string | null;
  fromUri: string | null;
  fromTag: string | null;
  toUri: string | null;
  toTag: string | null;
  cseq: CSeq | null;
  /** Lower case, "" when absent. */
  contentType: string;
  body: string;
  /** The `application/sdp` body (also inside multipart), parsed; `sdp.warnings` lists where it breaks RFC 8866. */
  sdp: SdpSession | null;
}

// ─── SIP message parsing ────────────────────────────────────────────────────

const COMPACT_HEADERS: Record<string, string> = {
  i: "call-id",
  m: "contact",
  e: "content-encoding",
  l: "content-length",
  c: "content-type",
  f: "from",
  s: "subject",
  k: "supported",
  t: "to",
  v: "via",
  o: "event",
  r: "refer-to",
  b: "referred-by",
  x: "session-expires",
};

const SIP_METHODS = new Set([
  "INVITE", "ACK", "BYE", "CANCEL", "REGISTER", "OPTIONS", "INFO",
  "PRACK", "UPDATE", "SUBSCRIBE", "NOTIFY", "REFER", "MESSAGE", "PUBLISH",
]);

/** First value of a header that may repeat. */
const first = (v: string | string[] | undefined): string | undefined => (Array.isArray(v) ? v[0] : v);

function extractUriAndTag(value: string | undefined): { uri: string | null; tag: string | null } {
  if (!value) return { uri: null, tag: null };
  const uriMatch = value.match(/<([^>]+)>/);
  const uri = uriMatch ? uriMatch[1] : value.split(";")[0].trim();
  const tagMatch = value.match(/;tag=([^;>\s]+)/i);
  return { uri, tag: tagMatch ? tagMatch[1] : null };
}

/**
 * Parse one SIP message (CRLF or LF line endings).
 * @throws Error on an empty or unrecognized start line
 */
export function parseSipMessage(rawText: string): SipMessage {
  if (typeof rawText !== "string") throw new Error("parseSipMessage: expected string");
  const normalized = rawText.replace(/\r\n/g, "\n");
  const sep = normalized.indexOf("\n\n");
  const head = sep === -1 ? normalized : normalized.slice(0, sep);
  const body = sep === -1 ? "" : normalized.slice(sep + 2);

  const lines = head.split("\n");
  const startLine = (lines.shift() || "").trim();
  if (!startLine) throw new Error("parseSipMessage: empty start line");

  // unfold continuation lines (leading whitespace)
  const folded: string[] = [];
  for (const ln of lines) {
    if (/^\s/.test(ln) && folded.length) folded[folded.length - 1] += " " + ln.trim();
    else folded.push(ln);
  }

  // no prototype: a header named `constructor` or `__proto__` must not hit Object.prototype
  const headers: SipHeaders = Object.create(null);
  for (const ln of folded) {
    const ci = ln.indexOf(":");
    if (ci === -1) continue;
    let name = ln.slice(0, ci).trim().toLowerCase();
    const val = ln.slice(ci + 1).trim();
    if (name.length === 1 && COMPACT_HEADERS[name]) name = COMPACT_HEADERS[name];
    if (name === "via") {
      (headers.via ||= []).push(val);
    } else if (headers[name] !== undefined) {
      const prev = headers[name];
      headers[name] = Array.isArray(prev) ? [...prev, val] : [prev, val];
    } else {
      headers[name] = val;
    }
  }

  // start line
  let kind: SipMessage["kind"];
  let method: string | null = null;
  let statusCode: number | null = null;
  let reasonPhrase: string | null = null;
  let requestUri: string | null = null;
  if (/^SIP\/2\.0\s/i.test(startLine)) {
    kind = "response";
    const m = startLine.match(/^SIP\/2\.0\s+(\d{3})\s*(.*)$/i);
    statusCode = m ? parseInt(m[1], 10) : null;
    reasonPhrase = m ? m[2].trim() : null;
  } else {
    kind = "request";
    const parts = startLine.split(/\s+/);
    method = (parts[0] || "").toUpperCase();
    requestUri = parts[1] || null;
    if (!SIP_METHODS.has(method)) {
      throw new Error(`parseSipMessage: unrecognized start line: ${startLine.slice(0, 60)}`);
    }
  }

  const from = extractUriAndTag(first(headers.from));
  const to = extractUriAndTag(first(headers.to));
  let cseq: CSeq | null = null;
  const cseqHeader = first(headers.cseq);
  if (cseqHeader) {
    const cm = cseqHeader.trim().match(/^(\d+)\s+(\w+)/);
    if (cm) cseq = { seq: parseInt(cm[1], 10), method: cm[2].toUpperCase() };
  }

  const contentType = (first(headers["content-type"]) || "").toLowerCase();
  let sdp: SdpSession | null = null;
  let sdpText: string | null = null;
  if (body.trim()) {
    if (contentType.includes("application/sdp")) {
      sdpText = body;
    } else if (contentType.includes("multipart/")) {
      // pull the application/sdp part out of a multipart body
      const idx = body.indexOf("application/sdp");
      if (idx !== -1) {
        const after = body.slice(idx);
        const partStart = after.indexOf("\n\n");
        if (partStart !== -1) {
          let part = after.slice(partStart + 2);
          const bnd = part.search(/\n--/);
          if (bnd !== -1) part = part.slice(0, bnd);
          sdpText = part;
        }
      }
    }
  }
  // parseSdp throws only on empty text
  if (sdpText && sdpText.trim()) sdp = parseSdp(sdpText);

  return {
    kind,
    method,
    statusCode,
    reasonPhrase,
    requestUri,
    headers,
    callId: first(headers["call-id"]) || null,
    fromUri: from.uri,
    fromTag: from.tag,
    toUri: to.uri,
    toTag: to.tag,
    cseq,
    contentType,
    body,
    sdp,
  };
}
