// The summary the webrtc.page worker sends: summarizeLadder() plus the first parse errors.
import { summarizeLadder as summarizeCalls } from "../../dist/index.js";

const MAX_PROBLEMS = 50;

export function summarizeLadder(r) {
  return {
    ...summarizeCalls(r),
    problems: r.errors.slice(0, MAX_PROBLEMS).map(({ src, dst, error }) => ({
      src,
      dst,
      error: error.replace(/^parseSipMessage: /, ""),
    })),
  };
}
