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

/** Media type of a Content-Type value, lower case, without parameters. */
const mediaType = (contentType: string): string => contentType.split(";")[0].trim().toLowerCase();

/** Nested multipart bodies followed when looking for SDP. */
const MAX_MULTIPART_DEPTH = 4;

/**
 * The `application/sdp` text of a body: the body itself, or the first SDP part of a
 * multipart body (RFC 2046 §5.1), also inside nested multipart parts. The boundary
 * comes from the `boundary` parameter, else from the first `--…` line. `body` has LF
 * line endings.
 */
function sdpText(contentType: string, body: string, depth = 0): string | null {
  const type = mediaType(contentType);
  if (type === "application/sdp") return body;
  if (!type.startsWith("multipart/") || depth >= MAX_MULTIPART_DEPTH) return null;
  const param = contentType.match(/;\s*boundary\s*=\s*(?:"([^"]+)"|([^;\s]+))/i);
  const boundary = param ? param[1] ?? param[2] : body.match(/^--(\S+?)\s*$/m)?.[1];
  if (!boundary) return null;
  const delimiter = `--${boundary}`;
  let part: string[] | null = null; // lines of the current part; null before the first delimiter
  const parts: string[][] = [];
  for (const line of body.split("\n")) {
    const trimmed = line.trimEnd();
    if (trimmed === delimiter || trimmed === `${delimiter}--`) {
      if (part) parts.push(part);
      if (trimmed !== delimiter) break; // close delimiter: the epilogue follows
      part = [];
    } else if (part) {
      part.push(line);
    }
  }
  for (const lines of parts) {
    const blank = lines.indexOf("");
    const head = blank === -1 ? lines : lines.slice(0, blank);
    const partType = head.find((h) => /^content-type\s*:/i.test(h))?.replace(/^[^:]*:/, "").trim() ?? "text/plain";
    const text = sdpText(partType, blank === -1 ? "" : lines.slice(blank + 1).join("\n"), depth + 1);
    if (text !== null) return text;
  }
  return null;
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

  // the boundary is case-sensitive, so it is read from the header as written
  const contentTypeHeader = first(headers["content-type"]) || "";
  const contentType = contentTypeHeader.toLowerCase();
  const text = body.trim() ? sdpText(contentTypeHeader, body) : null;
  // parseSdp throws only on empty text
  const sdp: SdpSession | null = text?.trim() ? parseSdp(text) : null;

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
