// SDP bodies of SIP messages. Parsing, the effective per-media view and RFC 3264
// offer/answer come from @irbisadm/simple-sdp; this module only ties them together.

import { sdpNegotiator, sdpReader, sdpResolver } from "@irbisadm/simple-sdp";
import type { SdpLenient, SdpNegotiation, SdpParseWarning, SdpResolved } from "@irbisadm/simple-sdp";

/**
 * A parsed SDP body: what applies to each media section (`bundle`, `hold`, `media` of
 * `SdpResolved`), the lenient model with every line as written, and where the text
 * breaks RFC 8866.
 */
export interface SdpSession extends SdpResolved {
  /** The lenient model of `@irbisadm/simple-sdp`: origin, connection, candidates, … */
  model: SdpLenient;
  /** Deviations from RFC 8866 and what the parser did about them; empty for a clean SDP. */
  warnings: SdpParseWarning[];
}

/**
 * Parse an SDP body. Parsing is lenient: SDP from real devices that breaks RFC 8866
 * (lines out of order, unknown or malformed lines, a missing `s=`, …) still gives the
 * best model the text allows, and every deviation is listed in `warnings`.
 * @throws Error on empty input
 */
export function parseSdp(text: string): SdpSession {
  if (typeof text !== "string" || !text.trim()) {
    throw new Error("parseSdp: empty SDP");
  }
  const { sdp: model, warnings } = sdpReader.parseLenient(text);
  return { ...sdpResolver.resolve(model), model, warnings };
}

/** RFC 3264 offer/answer: what the two sides agreed on, per media section of the answer. */
export function negotiate(offer: SdpSession, answer: SdpSession): SdpNegotiation {
  if (!offer || !answer) throw new Error("negotiate: need both offer and answer");
  return sdpNegotiator.negotiate(offer.model, answer.model);
}
