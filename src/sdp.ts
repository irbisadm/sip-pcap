// SDP parsing (normalized media model) and RFC 3264 offer/answer negotiation.
// The output shapes are a public contract: add fields, never rename or remove them.

import { sdpReader } from "@irbisadm/simple-sdp";
import type { SdpCommonAttributes, SdpLenient, SdpLenientMediaSection, SdpParseWarning } from "@irbisadm/simple-sdp";

export type { SdpParseWarning, SdpParseWarningCode, SdpParseWarningAction } from "@irbisadm/simple-sdp";

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
  /** Null when the `m=` line has no readable port (never 0 then: 0 means rejected). */
  port: number | null;
  /** Port 0. */
  rejected: boolean;
  /** E.g. `RTP/AVP`, `UDP/TLS/RTP/SAVPF`. */
  protocol: string;
  direction: Direction;
  /** Codecs with `a=rtpmap` in `m=` order, then static types without it. */
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
  /**
   * Where the SDP breaks RFC 8866 and what the parser did about it; empty for a
   * clean SDP. From `@irbisadm/simple-sdp` lenient parsing.
   */
  warnings: SdpParseWarning[];
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

const ENCRYPT_URI = "urn:ietf:params:rtp-hdrext:encrypt";

// A numeric string becomes a number when the round trip is exact, as the
// sdp-transform based parser did for o= (64-bit ids stay strings).
const intIfExact = (v: string): number | string => (String(Number(v)) === v ? Number(v) : v);

// The `a=fmtp` parameter strings of each media section, as written. The model keeps
// parameters as a map; the normalized `fmtp` field is the original text.
function rawFmtp(text: string): Map<number, string>[] {
  const out: Map<number, string>[] = [];
  for (const line of text.split(/\r\n|\r|\n/)) {
    if (line.startsWith("m=")) out.push(new Map());
    const m = out.length ? /^a=fmtp:(\d+) (.*)$/.exec(line) : null;
    if (m) out[out.length - 1].set(Number(m[1]), m[2]);
  }
  return out;
}

const genericAttr = (m: SdpCommonAttributes, name: string): string | undefined =>
  m.attributes?.find((a) => a.name === name)?.value;

// Typed `a=setup`, or one that lenient parsing kept as a generic attribute because
// its value is not one of the RFC 4145 values.
const setupOf = (m: SdpCommonAttributes): string | undefined => m.setup ?? genericAttr(m, "setup");

function lastFingerprint(m: SdpCommonAttributes): string | undefined {
  const f = m.fingerprints?.[m.fingerprints.length - 1];
  return f ? `${f.hashFunction} ${f.fingerprint}` : undefined;
}

// `a=rtpmap` lines that lenient parsing kept as generic attributes because they do
// not follow RFC 8866, e.g. `a=rtpmap:96 telephone-event` without a clock rate.
function looseRtpmaps(m: SdpLenientMediaSection): Map<number, { codec: string; rate: number | null; channels: number }> {
  const out = new Map<number, { codec: string; rate: number | null; channels: number }>();
  for (const a of m.attributes ?? []) {
    const r = a.name === "rtpmap" && a.value ? /^(\d+)\s+([^/\s]+)(?:\/(\d+)(?:\/(\d+))?)?/.exec(a.value) : null;
    if (r && !out.has(Number(r[1]))) {
      out.set(Number(r[1]), { codec: r[2], rate: r[3] ? Number(r[3]) : null, channels: r[4] ? Number(r[4]) : 1 });
    }
  }
  return out;
}

function normalizeMedia(m: SdpLenientMediaSection, idx: number, session: SdpLenient, fmtp: Map<number, string> | undefined): SdpMedia {
  const codecs: Codec[] = [];
  const statics: Codec[] = [];
  const loose = looseRtpmaps(m);
  for (const c of m.codecs ?? []) {
    const pt = c.payloadType;
    const l = loose.get(pt);
    if (c.encodingName !== undefined) {
      codecs.push({
        pt,
        codec: c.encodingName,
        rate: c.clockRate ?? null,
        channels: c.encodingParameters ?? 1,
        fmtp: fmtp?.get(pt) ?? null,
      });
    } else if (l) {
      codecs.push({ pt, ...l, fmtp: fmtp?.get(pt) ?? null });
    } else {
      const s = STATIC_PT[pt];
      statics.push({
        pt,
        codec: s ? s.codec : `PT${pt}`,
        rate: s ? s.rate : null,
        channels: s ? s.channels : 1,
        fmtp: fmtp?.get(pt) ?? null,
        static: true,
      });
    }
  }

  const extensions: Extension[] = (m.extmap ?? []).map((e) => {
    // RFC 6904: `a=extmap:<id> urn:ietf:params:rtp-hdrext:encrypt <uri>`
    const uri = e.uri === ENCRYPT_URI && e.attributes ? e.attributes.split(" ")[0] : e.uri;
    return { id: e.id, uri };
  });

  // session-level values apply to every media section that does not set its own
  const ufrag = m.iceUfrag ?? session.iceUfrag;
  const pwd = m.icePwd ?? session.icePwd;
  const fingerprint = lastFingerprint(m) ?? lastFingerprint(session);
  const setup = setupOf(m) ?? setupOf(session);
  const port = m.port ?? null;

  return {
    mid: m.mid ?? `m${idx}`,
    type: m.type,
    port,
    rejected: port === 0,
    protocol: m.proto ?? "",
    direction: m.direction ?? session.direction ?? "sendrecv",
    // with a=rtpmap first, then static types without it, as before
    codecs: [...codecs, ...statics],
    extensions,
    ice: ufrag !== undefined || pwd !== undefined ? { ufrag: ufrag ?? null, pwd: pwd ?? null } : null,
    dtls: fingerprint !== undefined || setup !== undefined
      ? { setup: setup ?? null, fingerprint: fingerprint ?? null }
      : null,
  };
}

function normalizeOrigin(o: SdpLenient["origin"]): SdpOrigin | null {
  const ipVer = o && /^IP(\d)$/.exec(o.addrType);
  if (!o || !ipVer) return null;
  return {
    username: o.username,
    sessionId: intIfExact(o.sessId),
    sessionVersion: intIfExact(o.sessVersion),
    netType: o.netType,
    ipVer: Number(ipVer[1]),
    address: o.unicastAddress,
  };
}

/**
 * Parse an SDP into the normalized session model.
 *
 * Parsing is lenient: SDP from real devices that breaks RFC 8866 (lines out of
 * order, unknown or malformed lines, a missing `s=`, …) still gives the best model
 * the text allows, and every deviation is listed in `warnings`.
 * @throws Error on empty input
 */
export function parseSdp(text: string): SdpSession {
  if (typeof text !== "string" || !text.trim()) {
    throw new Error("parseSdp: empty SDP");
  }
  // strict parsing would be sdpReader.parse(text), which throws SdpParseError
  const { sdp: raw, warnings } = sdpReader.parseLenient(text);
  const fmtp = rawFmtp(text);
  const media = raw.media.map((m, i) => normalizeMedia(m, i, raw, fmtp[i]));
  const bundleGroup = raw.group?.filter((g) => g.semantics === "BUNDLE").pop();
  const hold = media.some((m) => m.direction === "inactive" || m.direction === "sendonly" || m.direction === "recvonly");
  return {
    origin: normalizeOrigin(raw.origin),
    bundle: bundleGroup ? [...bundleGroup.mids] : [],
    hold,
    media,
    warnings,
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
