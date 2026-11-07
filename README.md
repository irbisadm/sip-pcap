# @irbisadm/sip-pcap

Read pcap and pcapng captures and get SIP calls back: the network endpoints each
call touched, every SIP message in time order, retransmissions, the SDP of each
step and the result of the SDP offer/answer exchange on each hop.

- One endpoint per `host:port`, so proxies and SBCs show up as separate hops.
- Offer/answer per hop: through a proxy, the INVITE the proxy forwards is a second
  offer, and each 200 OK answers the offer on its own hop.
- Runs in Node.js (≥ 20), browsers and Web Workers. No Node APIs: it works on
  `Uint8Array`, `DataView` and `TextDecoder`.
- ESM, typed (`.d.ts` included).

```sh
npm install @irbisadm/sip-pcap
```

## Quick start

```js
import { readFile } from "node:fs/promises";
import { buildLadder } from "@irbisadm/sip-pcap";

const ladder = buildLadder(await readFile("call.pcapng"));
for (const call of ladder.calls) {
  console.log(call.id, call.status, call.endpoints.map((e) => e.addr).join(" -> "));
  for (const m of call.messages) {
    console.log(`  +${m.rel.toFixed(0)}ms ${m.src} -> ${m.dst} ${m.label}${m.sdpRole ? ` (SDP ${m.sdpRole})` : ""}`);
  }
}
```

In a browser, pass the bytes of a `File`:

```js
const ladder = buildLadder(await file.arrayBuffer());
```

## API

### `buildLadder(input, { sipPort = 5060 } = {})`

`input` is a pcap or pcapng capture as `Uint8Array`, `ArrayBuffer` or any
`ArrayBufferView` (a Node.js `Buffer` works). SIP is found on `sipPort` and, on any
other port, by content; `sipPort: null` uses content detection only.

Returns:

```js
{
  packets: 13,          // UDP/TCP packets decoded
  sipMessages: 13,      // SIP messages found
  errors: [],           // [{ ts, src, dst, error }] messages that looked like SIP but did not parse
  calls: [{
    id: "a84b4c76e66710@pc33.example.com",   // Call-ID
    from: "sip:alice@example.com",
    to: "sip:bob@example.net",
    startTs: 1794052800000,                  // ms since the Unix epoch
    durationMs: 61873,
    method: "INVITE",
    status: "completed",                     // or "cancelled", "486 Busy Here", "answered, no BYE in capture", …
    outcome: "ok",                           // "ok" | "failed" | "cancelled" | "pending"
    ringMs: 71, answerMs: 4210, talkMs: 57590, // INVITE calls only
    endpoints: [{ addr: "192.0.2.10:5060", agent: "Linphone/5.2" }, …],
    messages: [{
      index: 0, ts, rel: 0,                  // rel: ms since the first message of the call
      src: "192.0.2.10:5060", dst: "198.51.100.1:5060", proto: "udp",
      kind: "request", method: "INVITE", statusCode: null, reason: "", label: "INVITE",
      requestUri, cseq: { seq: 314159, method: "INVITE" }, branch, fromTag, toTag,
      retransmission: false,                 // same message already seen on the same hop
      sdp: { … },                            // parseSdp() model, or null
      sdpRole: "offer",                      // "offer" | "answer" | null
      negotiation: null,                     // on answers: { offerIndex, ...negotiate() }
      raw: "INVITE sip:bob@example.net SIP/2.0\r\n…",
    }, …],
    mermaid: "sequenceDiagram\n  participant P1 as 192.0.2.10:5060\n…",
  }],
}
```

IPv6 endpoints are written `[2001:db8::10]:5060`.

### `summarizeLadder(ladder)`

The call list without messages, for a UI that keeps the full ladder in a Web Worker
and sends the page only what it shows:

```js
const worker = new Worker(new URL("./ladder.worker.js", import.meta.url), { type: "module" });

// ladder.worker.js
import { buildLadder, summarizeLadder } from "@irbisadm/sip-pcap";
let ladder;
onmessage = ({ data }) => {
  if (data.type === "load") {
    ladder = buildLadder(data.bytes);
    postMessage({ type: "summary", summary: summarizeLadder(ladder) });
  } else if (data.type === "call") {
    postMessage({ type: "call", call: ladder.calls[data.index] });
  }
};
```

```js
summarizeLadder(ladder);
// { packets, sipMessages, errors: 0,
//   calls: [{ index, id, from, to, method, status, outcome, durationMs, messages, hosts }] }
```

### `parseSdp(text)`

Parse an SDP into a normalized model:

```js
import { parseSdp } from "@irbisadm/sip-pcap";

parseSdp(sdpText);
// {
//   origin: { username, sessionId, sessionVersion, netType, ipVer, address },
//   bundle: ["0", "1"],          // a=group:BUNDLE
//   hold: false,                 // some media section is not sendrecv
//   media: [{
//     mid: "0",                  // a=mid, or "m<index>" when absent
//     type: "audio", port: 49170, rejected: false, protocol: "UDP/TLS/RTP/SAVPF",
//     direction: "sendrecv",
//     codecs: [{ pt: 111, codec: "opus", rate: 48000, channels: 2, fmtp: "minptime=10;useinbandfec=1" },
//              { pt: 0, codec: "PCMU", rate: 8000, channels: 1, fmtp: null, static: true }],
//     extensions: [{ id: 1, uri: "urn:ietf:params:rtp-hdrext:ssrc-audio-level" }],
//     ice: { ufrag, pwd } | null,
//     dtls: { setup, fingerprint: "sha-256 AA:BB:…" } | null,
//   }],
// }
```

Static payload types listed in `m=` without `a=rtpmap` get their name and rate from
the RFC 3551 table and `static: true`. Throws on empty input.

### `negotiate(offer, answer)`

RFC 3264 outcome of two `parseSdp` results, one entry per answer media section:

```js
import { parseSdp, negotiate } from "@irbisadm/sip-pcap";

negotiate(parseSdp(offerText), parseSdp(answerText));
// {
//   bundle: ["0", "1"],
//   hold: false,
//   media: [{
//     mid: "0", type: "audio", rejected: false,
//     agreedCodecs: [ …answer codecs also in the offer (by name, rate, channels)… ],
//     agreedExtensions: [ …answer extensions also in the offer (by URI)… ],
//     directionOffer: "sendrecv", directionAnswer: "sendrecv", hold: false,
//     dtlsOffer: "actpass", dtlsAnswer: "active",
//     iceOffer: "ufragA", iceAnswer: "ufragB",
//   }],
// }
```

Media sections are matched by `mid`, else by position.

### `parseSipMessage(text)`

```js
import { parseSipMessage } from "@irbisadm/sip-pcap";

const msg = parseSipMessage(rawText);
// { kind: "request" | "response", method, statusCode, reasonPhrase, requestUri,
//   headers,            // lower-case names; compact forms expanded; repeats as arrays; via always an array
//   callId, fromUri, fromTag, toUri, toTag, cseq: { seq, method },
//   contentType, body,
//   sdp }               // parseSdp() of an application/sdp body, also inside multipart; else null
```

Handles CRLF and LF line endings, folded headers and compact header forms (`i`, `f`,
`t`, `v`, `m`, `l`, `c`, …). Throws on an empty or unrecognized start line.

### `parsePcap(input)` and `reassembleSip(packets, { sipPort = 5060 } = {})`

The two steps under `buildLadder`, for callers that want their own grouping:

```js
import { parsePcap, reassembleSip, parseSipMessage } from "@irbisadm/sip-pcap";

const packets = parsePcap(bytes);
// [{ ts, src, dst, sport, dport, proto: "udp" | "tcp", payload: Uint8Array, seq?, flags? }]
const messages = reassembleSip(packets);
// [{ raw, ts, src: "host:port", dst: "host:port", proto }] in time order
const parsed = messages.map((m) => parseSipMessage(m.raw));
```

### `createOfferAnswerTracker({ maxOffers = 50, maxFingerprints = Infinity } = {})`

The offer/answer state of one call. `buildLadder` uses it per Call-ID; a stateful
dialog store can use it the same way. Feed messages in order:

```js
import { createOfferAnswerTracker, parseSipMessage } from "@irbisadm/sip-pcap";

const tracker = createOfferAnswerTracker();
messages.forEach((m, stepIndex) => {
  const r = tracker.observe(parseSipMessage(m.raw), { stepIndex, hop: { src: m.src, dst: m.dst }, raw: m.raw });
  // r.role:           "offer" | "answer" | null
  // r.retransmission: true when the same raw text was already seen on the same hop
  // r.negotiation:    on an answer: { ...negotiate(offer, answer), offerStep, answerStep }
});
tracker.state;        // "stable" | "offer-pending"
tracker.pendingOffer; // { sdp, stepIndex } | null
tracker.negotiated;   // the latest answered offer's negotiation | null
```

Rules (RFC 3264, RFC 6337):

- a request with SDP is an offer, except ACK (it answers a late offer) and PRACK that
  answers a late offer made in a reliable 1xx (found by the CSeq number in `RAck`);
- a response with SDP is an answer if its request (same CSeq number and method)
  offered, otherwise it is a late offer;
- an answer pairs with the offer that crossed the same hop in the opposite direction
  when hops are known, else with the latest offer with the same CSeq number, else with
  the latest offer;
- a retransmission does not change the state; it reports the role of the original.

`hop` and `raw` are optional: without `hop`, pairing falls back to CSeq; without
`raw`, retransmissions are not detected unless you pass `retransmission: true`.

## Testing helpers: `@irbisadm/sip-pcap/testing`

Build captures in memory, for tests and sample files. Not part of the main entry.

```js
import { classicPcap, pcapng, udp, tcp, sip, proxyCallPcap } from "@irbisadm/sip-pcap/testing";

const invite = sip("INVITE sip:bob@example.net SIP/2.0", [
  "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK1",
  "From: <sip:alice@example.com>;tag=1", "To: <sip:bob@example.net>",
  "Call-ID: c1@example.com", "CSeq: 1 INVITE",
], sdpText);                    // CRLF line endings, Content-Type and Content-Length set
const bytes = classicPcap([{ ts: Date.now(), frame: udp({ src: "192.0.2.10", dst: "192.0.2.20", payload: invite }) }]);

proxyCallPcap();                // a full call Alice -> proxy -> Bob, INVITE to BYE
```

Also: `udpFragmented`, `ipv4Udp`, `ipv6Udp`, `ipv6UdpFragmented`, `ethernetV6`,
`linuxSll2`, `proxyCallFlow` (the same call as `[ms, src, dst, text]` rows) and the
scenario addresses `ALICE`, `PROXY`, `BOB`.

## Supported captures

- Containers: classic pcap (microsecond and nanosecond, either byte order); pcapng
  (several sections and interfaces, `if_tsresol`, Enhanced and Simple Packet Blocks).
- Link layers: Ethernet (with 802.1Q / QinQ tags), raw IP (LINKTYPE 101, 12, 14,
  228, 229), BSD loopback (0, 108), Linux cooked capture v1 (113) and v2 (276).
- Network: IPv4 and IPv6, IPv6 extension headers, IP fragment reassembly (both).
- Transport: UDP; TCP ordered by sequence number with retransmitted bytes dropped,
  split into messages by `Content-Length` (in bytes), resyncing when the capture
  starts mid-message.

## Limits

- SIP over TLS and secure WebSocket (WSS) is encrypted in captures and cannot be read.
- SIP over plain WebSocket is not decoded yet.
- RTP is not analysed; only the SDP that describes it.
- SCTP is not supported.

## Types

Written in TypeScript (strict). The package ships ES modules compiled to ES2022
with their declarations; no runtime helpers, no bundling. The library is compiled
without Node.js types, so it cannot use Node APIs by accident. All public types are
exported from the package root, e.g.:

```ts
import type { Ladder, LadderCall, LadderSummary, SdpSession, Negotiation } from "@irbisadm/sip-pcap";
```

## Development

```sh
npm run build       # src/ -> dist/
npm test            # node:test via tsx (builds first)
npm run typecheck   # library, tests and a consumer of the built declarations
npm run check:pack  # check what npm would publish
```

## License

MIT
