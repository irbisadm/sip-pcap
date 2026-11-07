// parseSdp as implemented on sdp-transform before the switch to simple-sdp, kept
// unchanged as the reference for test/sdp-differential.test.ts. Not used by src/.

import sdpTransform from "sdp-transform";
import type { MediaDescription } from "sdp-transform";
import type { Codec, Extension, SdpMedia, SdpOrigin, SdpSession } from "../../src/sdp.js";

// ─── SDP parsing ──────────────────────────────────────────────────────────────

// Static RTP payload types without an explicit a=rtpmap (RFC 3551 §6).
const STATIC_PT: Record<number, { codec: string; rate: number; channels: number }> = {
  0: { codec: "PCMU", rate: 8000, channels: 1 },
  3: { codec: "GSM", rate: 8000, channels: 1 },
  4: { codec: "G723", rate: 8000, channels: 1 },
  8: { codec: "PCMA", rate: 8000, channels: 1 },
  9: { codec: "G722", rate: 8000, channels: 1 },
  13: { codec: "CN", rate: 8000, channels: 1 },
  18: { codec: "G729", rate: 8000, channels: 1 },
};

function midStr(m: MediaDescription, idx: number): string {
  return m.mid !== undefined && m.mid !== null ? String(m.mid) : `m${idx}`;
}

// Normalize an sdp-transform media entry into our codec/extension shape.
function normalizeMedia(m: MediaDescription, idx: number): SdpMedia {
  const fmtpByPt = new Map<number, string>();
  for (const f of m.fmtp || []) fmtpByPt.set(f.payload, f.config);

  const codecs: Codec[] = [];
  const seenPt = new Set<number>();
  for (const r of m.rtp || []) {
    seenPt.add(r.payload);
    codecs.push({
      pt: r.payload,
      codec: r.codec,
      rate: r.rate ?? null,
      channels: r.encoding ?? 1,
      fmtp: fmtpByPt.get(r.payload) ?? null,
    });
  }
  // static payloads listed in m= line but without rtpmap
  const ptList = String(m.payloads ?? "")
    .trim()
    .split(/\s+/)
    .filter(Boolean)
    .map(Number);
  for (const pt of ptList) {
    if (seenPt.has(pt)) continue;
    const s = STATIC_PT[pt];
    codecs.push({
      pt,
      codec: s ? s.codec : `PT${pt}`,
      rate: s ? s.rate : null,
      channels: s ? s.channels : 1,
      fmtp: fmtpByPt.get(pt) ?? null,
      static: true,
    });
  }

  const extensions: Extension[] = (m.ext || []).map((e) => ({ id: e.value, uri: e.uri }));

  return {
    mid: midStr(m, idx),
    type: m.type,
    port: m.port,
    rejected: m.port === 0,
    protocol: m.protocol,
    direction: m.direction || "sendrecv",
    codecs,
    extensions,
    ice:
      m.iceUfrag || m.icePwd
        ? { ufrag: m.iceUfrag ?? null, pwd: m.icePwd ?? null }
        : null,
    dtls: m.fingerprint
      ? {
          setup: m.setup ?? null,
          fingerprint: `${m.fingerprint.type} ${m.fingerprint.hash}`,
        }
      : m.setup
        ? { setup: m.setup, fingerprint: null }
        : null,
  } as SdpMedia;
}

/** The sdp-transform implementation of parseSdp, as it was before simple-sdp. */
export function legacyParseSdp(text: string): Omit<SdpSession, "warnings"> {
  if (typeof text !== "string" || !text.trim()) {
    throw new Error("parseSdp: empty SDP");
  }
  const raw = sdpTransform.parse(text);
  const media = (raw.media || []).map((m, i) => normalizeMedia(m, i));
  let bundle: string[] = [];
  for (const g of raw.groups || []) {
    if (g.type === "BUNDLE") bundle = String(g.mids).trim().split(/\s+/).filter(Boolean);
  }
  const hold = media.some((m) => m.direction === "inactive" || m.direction === "sendonly" || m.direction === "recvonly");
  // sdp-transform turns values that look like integers into numbers (sessionId, ipVer)
  const origin = (raw.origin as unknown as SdpOrigin | undefined) || null;
  return {
    origin,
    bundle,
    hold,
    media,
  };
}

