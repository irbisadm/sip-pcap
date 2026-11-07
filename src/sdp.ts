// SDP parsing (normalized media model) and RFC 3264 offer/answer negotiation.
// The output shapes are a public contract: add fields, never rename or remove them.

// sdp-transform is replaced by @irbisadm/simple-sdp.
import sdpTransform from "sdp-transform";
import type { MediaDescription } from "sdp-transform";

export type Direction = "sendrecv" | "sendonly" | "recvonly" | "inactive";

/** One RTP payload type of a media section. */
export interface Codec {
  /** Payload type. */
  pt: number;
  /** Encoding name, e.g. `opus`, `PCMU`; `PT<n>` for an unknown static type. */
  codec: string;
  /** Clock rate. */
  rate: number | null;
  channels: number;
  /** The `a=fmtp` parameter string, as written. */
  fmtp: string | null;
  /** Listed in `m=` without `a=rtpmap`; name and rate come from RFC 3551. */
  static?: true;
}

/** `a=extmap` */
export interface Extension {
  id: number;
  uri: string;
}

export interface SdpMedia {
  /** `a=mid`, or `m<index>` when absent. */
  mid: string;
  /** `audio`, `video`, `application`, … */
  type: string;
  port: number;
  /** Port 0. */
  rejected: boolean;
  /** E.g. `RTP/AVP`, `UDP/TLS/RTP/SAVPF`. */
  protocol: string;
  direction: Direction;
  /** Codecs with `a=rtpmap` in their order, then static types without it. */
  codecs: Codec[];
  extensions: Extension[];
  ice: { ufrag: string | null; pwd: string | null } | null;
  dtls: { setup: string | null; fingerprint: string | null } | null;
}

/** `o=` line. */
export interface SdpOrigin {
  username: string;
  /** A number when it fits exactly, else the original string. */
  sessionId: number | string;
  /** See `sessionId`. */
  sessionVersion: number | string;
  netType: string;
  /** 4 or 6. */
  ipVer: number;
  address: string;
}

/** Normalized session description. */
export interface SdpSession {
  origin: SdpOrigin | null;
  /** Mids of the `a=group:BUNDLE` line. */
  bundle: string[];
  /** Some media section is not sendrecv. */
  hold: boolean;
  media: SdpMedia[];
}

/** Offer/answer result for one media section. */
export interface NegotiatedMedia {
  mid: string;
  type: string;
  rejected: boolean;
  /** Answer codecs also present in the offer (by name, rate and channels). */
  agreedCodecs: Codec[];
  /** Answer extensions also present in the offer (by URI). */
  agreedExtensions: Extension[];
  directionOffer: Direction;
  directionAnswer: Direction;
  hold: boolean;
  /** `a=setup` of the offer. */
  dtlsOffer: string | null;
  /** `a=setup` of the answer. */
  dtlsAnswer: string | null;
  /** ICE ufrag of the offer. */
  iceOffer: string | null;
  /** ICE ufrag of the answer. */
  iceAnswer: string | null;
}

export interface Negotiation {
  bundle: string[];
  hold: boolean;
  /** One entry per answer media section. */
  media: NegotiatedMedia[];
}

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

/**
 * Parse an SDP into the normalized session model.
 * @throws Error on empty input
 */
export function parseSdp(text: string): SdpSession {
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

// ─── RFC 3264 offer/answer negotiation ──────────────────────────────────────

function codecKey(c: Codec): string {
  return `${(c.codec || "").toLowerCase()}/${c.rate ?? ""}/${c.channels ?? 1}`;
}

function reconcileDirection(
  offerDir: Direction | undefined,
  answerDir: Direction | undefined,
): { directionOffer: Direction; directionAnswer: Direction; hold: boolean } {
  // hold if either side stops one direction
  const d = answerDir || "sendrecv";
  const hold = d === "inactive" || d === "sendonly" || d === "recvonly" ||
    (offerDir && (offerDir === "inactive" || offerDir === "sendonly" || offerDir === "recvonly"));
  return { directionOffer: offerDir || "sendrecv", directionAnswer: d, hold: !!hold };
}

/** RFC 3264 offer/answer: what the two sides agreed on, per answer media section. */
export function negotiate(offer: SdpSession, answer: SdpSession): Negotiation {
  if (!offer || !answer) throw new Error("negotiate: need both offer and answer");
  const offerByMid = new Map(offer.media.map((m) => [m.mid, m]));
  const media = answer.media.map((am, idx): NegotiatedMedia => {
    const om: Pick<SdpMedia, "codecs" | "extensions" | "direction"> & Partial<SdpMedia> =
      offerByMid.get(am.mid) || offer.media[idx] || { codecs: [], extensions: [], direction: "sendrecv" };
    const rejected = am.rejected || am.port === 0;
    const offerKeys = new Set(om.codecs.map(codecKey));
    const agreedCodecs = rejected ? [] : am.codecs.filter((c) => offerKeys.has(codecKey(c)));
    const offerUris = new Set(om.extensions.map((e) => e.uri));
    const agreedExtensions = rejected ? [] : am.extensions.filter((e) => offerUris.has(e.uri));
    const dir = reconcileDirection(om.direction, am.direction);
    return {
      mid: am.mid,
      type: am.type,
      rejected,
      agreedCodecs,
      agreedExtensions,
      ...dir,
      dtlsOffer: om.dtls?.setup ?? null,
      dtlsAnswer: am.dtls?.setup ?? null,
      iceOffer: om.ice?.ufrag ?? null,
      iceAnswer: am.ice?.ufrag ?? null,
    };
  });
  return {
    bundle: answer.bundle.length ? answer.bundle : offer.bundle,
    hold: media.some((m) => m.hold),
    media,
  };
}
