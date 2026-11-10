# @irbisadm/sip-pcap

Read pcap and pcapng captures and get SIP calls back: the network endpoints each
call touched, every SIP message in time order, retransmissions, the SDP of each
step and the result of the SDP offer/answer exchange on each hop.

- One endpoint per `host:port`, so proxies and SBCs show up as separate hops.
- Offer/answer per hop: through a proxy, the INVITE the proxy forwards is a second
  offer, and each 200 OK answers the offer on its own hop.
- Runs in Node.js (≥ 20), browsers and Web Workers. No Node APIs: it works on
  `Uint8Array`, `DataView` and `TextDecoder`.
- ESM, typed (`.d.ts` included). One runtime dependency:
  [`@irbisadm/simple-sdp`](https://www.npmjs.com/package/@irbisadm/simple-sdp).
- Tolerant of real-world SDP: old phones and gateways that break RFC 8866 still get
  their SDP parsed, with a list of what was wrong.

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
other port, by content; `sipPort: null` uses content detection only. Either way the
first line has to be a SIP start line (`<method> <uri> SIP/2.0` or `SIP/2.0 <code>`), so
HTTP, RTSP and SSDP are not taken for SIP.

Returns:

```js
{
  packets: 13,          // UDP/TCP packets decoded
  sipMessages: 13,      // SIP messages found
  errors: [],           // [{ ts, src, dst, error }] SIP that did not parse, e.g. an unknown method
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
      sdpWarnings: [],                       // where the SDP breaks RFC 8866 (see parseSdp)
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

Parse an SDP body. Parsing, the per-media view and offer/answer come from
[`@irbisadm/simple-sdp`](https://www.npmjs.com/package/@irbisadm/simple-sdp); the types
that appear in this API (`SdpResolved`, `SdpNegotiation`, `SdpParseWarning`, …) are
re-exported from this package.

```js
import { parseSdp } from "@irbisadm/sip-pcap";

parseSdp(sdpText);
// {
//   bundle: ["0", "1"],          // mids of the first a=group:BUNDLE
//   hold: false,                 // a media section that is not rejected is not sendrecv
//   media: [{                    // simple-sdp sdpResolver.resolve(): what applies to each m= line
//     index: 0, mid: "0",        // mid is absent without a=mid
//     type: "audio", port: 49170, rejected: false, proto: "UDP/TLS/RTP/SAVPF",
//     direction: "sendrecv",
//     codecs: [{ payloadType: 111, encodingName: "opus", clockRate: 48000, encodingParameters: 2,
//                parameters: { minptime: "10", useinbandfec: "1" } },
//              { payloadType: 0, encodingName: "PCMU", clockRate: 8000, static: true }],
//     extmap: [{ id: 1, uri: "urn:ietf:params:rtp-hdrext:ssrc-audio-level" }],
//     iceUfrag: "…", icePwd: "…", setup: "actpass",
//     fingerprints: [{ hashFunction: "sha-256", fingerprint: "AA:BB:…" }],
//   }],
//   model: { origin, connectionInformation, media: [ … ], … }, // simple-sdp lenient model, every line
//   warnings: [],                // empty for a clean SDP, see below
// }
```

`media` is the effective view: session-level direction, ICE, DTLS and `a=extmap` apply
to every media section that does not set its own, static payload types listed in `m=`
without `a=rtpmap` get their RFC 3551 name, rate and `static: true`, and `a=rtcp-fb:*`
is added to every codec. The full rules are in the simple-sdp README ("Resolve and
negotiate"). `model` keeps everything as written: origin, connection, candidates, SSRCs,
generic attributes. Absent values are left out rather than `null`. Throws on empty input
only.

Parsing is lenient (simple-sdp `parseLenient`): an SDP that breaks RFC 8866 (lines
out of order, unknown or malformed lines, a missing `s=`, trailing spaces, CR-only
line endings, …) still gives the best model the text allows, and each problem is
reported in `warnings`:

```js
parseSdp("v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\nm=audio 4000 RTP/AVP 0\r\n").warnings;
// [{ code: "missing-mandatory-line", reason: 'missing mandatory "s=" line',
//    lineNumber: 0, line: "", action: "skipped" }]
```

`code` is one of simple-sdp's stable `SdpParseWarningCode` values; `action` says
what the parser did with the line (`kept`, `skipped`, `generic-attribute`,
`first-kept`, `repaired`). Values that are not RFC-conformant but still readable are
used: `a=setup:client` gives `setup: "client"`, `a=rtpmap:96 telephone-event` (no clock
rate) gives the codec without `clockRate`.

### `negotiate(offer, answer)`

RFC 3264 outcome of two `parseSdp` results (simple-sdp `sdpNegotiator.negotiate`), one
entry per answer media section:

```js
import { parseSdp, negotiate } from "@irbisadm/sip-pcap";

negotiate(parseSdp(offerText), parseSdp(answerText));
// {
//   bundle: ["0", "1"],          // the answer's group; [] when the answer declines BUNDLE
//   hold: false,
//   media: [{
//     index: 0, offerIndex: 0, mid: "0", type: "audio", rejected: false,
//     codecs: [ …answer codecs also in the offer (by name, clock rate, channels)… ],
//     extmap: [ …answer extensions also in the offer (by URI)… ],
//     offerDirection: "sendrecv", answerDirection: "sendrecv", hold: false,
//   }],
// }
```

Media sections are matched by `mid`, else by position; `offerIndex` is the matched
section of the offer. ICE and DTLS values of each side are in `offer.media[offerIndex]`
and `answer.media[index]`.

### `parseSipMessage(text)`

```js
import { parseSipMessage } from "@irbisadm/sip-pcap";

const msg = parseSipMessage(rawText);
// { kind: "request" | "response", method, statusCode, reasonPhrase, requestUri,
//   headers,            // lower-case names; compact forms expanded; repeats as arrays; via always an array
//   callId, fromUri, fromTag, toUri, toTag, cseq: { seq, method },
//   contentType, body,
//   sdp,                // parseSdp() of an application/sdp body, also inside multipart; else null
//   sdpWarnings }       // sdp.warnings, or [] without SDP
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

Rules (RFC 3261 §13.2.1, RFC 3262, RFC 3311, RFC 3264, RFC 6337):

- only INVITE, ACK, PRACK and UPDATE and their 1xx/2xx responses carry offers and
  answers; SDP elsewhere (a `488` or `606` listing what the UA supports, a reply to
  `OPTIONS`) gets role `null` and leaves the state alone. Pass `statusCode` (a
  `parseSipMessage` result has it) so that error responses are recognised;
- a request with SDP is an offer, except ACK (it answers a late offer) and PRACK that
  answers a late offer made in a reliable 1xx (found by the CSeq number in `RAck`);
- a 1xx/2xx response with SDP is an answer if its request (same CSeq number and
  method) offered, otherwise it is a late offer;
- a 3xx–6xx response to a request that offered rejects the offer: the state returns
  to `stable` and `negotiated` keeps the previous result;
- an answer pairs with the offer that crossed the same hop in the opposite direction,
  preferring one with the same CSeq number (`RAck` for PRACK), when hops are known;
  else with the latest offer with the same CSeq number; else with the latest offer;
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
`ethernetPppoe`, `ipTunnel`, `linuxSll2`, `proxyCallFlow` (the same call as `[ms, src, dst, text]` rows) and the
scenario addresses `ALICE`, `PROXY`, `BOB`.

## Supported captures

- Containers: classic pcap (microsecond and nanosecond, either byte order); pcapng
  (several sections and interfaces, `if_tsresol`, Enhanced and Simple Packet Blocks).
- Link layers: Ethernet (with 802.1Q / QinQ tags and PPPoE sessions), raw IP (LINKTYPE
  101, 12, 14, 228, 229), BSD loopback (0, 108), Linux cooked capture v1 (113) and v2
  (276).
- Network: IPv4 and IPv6, IPv6 extension headers, IP fragment reassembly (both), IP
  tunnels (IP-in-IP, 6in4, 4in6, 6in6; endpoints are those of the inner packet).
- Transport: UDP; TCP ordered by sequence number with retransmitted bytes dropped,
  split into messages by `Content-Length` (in bytes), resyncing when the capture
  starts mid-message.

## Limits

- SIP over TLS and secure WebSocket (WSS) is encrypted in captures and cannot be read.
- SIP over plain WebSocket is not decoded yet.
- RTP is not analysed; only the SDP that describes it.
- SCTP is not supported.
- The SIP copy inside an ICMP error is not treated as a message.
- Calls are grouped by Call-ID. A B2BUA or an SBC that sets a new Call-ID on its
  outbound leg (most do) shows up as two calls; the legs are not correlated
  (`X-CID`, `Session-ID` of RFC 7989).
- An endpoint is a `host:port` as seen in the packet. SIP over TCP from ephemeral ports,
  or a host behind NAT, can give one host several endpoints.
- A retransmission is the same message text again on the same hop within a call. A
  packet captured twice (on `-i any`, a VLAN sub-interface and its parent, or a SPAN
  port) is therefore flagged as a retransmission too.
- CSeq numbers are matched without the direction: each side keeps its own counter, so
  a request from the callee with the same number as one from the caller can be
  paired wrongly. Rare in practice.
- TCP streams are keyed by address and port only: no SYN/FIN tracking, no 32-bit
  sequence wraparound, and gaps from packets lost by the capture are not reported.
- `tcpdump port 5060` keeps only the first fragment of a fragmented datagram (the
  others have no UDP header); such datagrams cannot be reassembled and are dropped.
  Capture with `udp` or by host instead.

## Checked against real captures

The automated tests build their captures in memory. As a one-off check on 2026-11-08,
the library was also run over 61 public capture files, with `tshark` as an independent
reference. This is **not** part of `npm test`, CI or the release process, the captures
are not in this repository (most have no clear license), and the result describes that
run, not every later version.

Sources: [Wireshark SampleCaptures](https://wiki.wireshark.org/SampleCaptures),
[goffinet/sip_captures](https://github.com/goffinet/sip_captures),
[sngrep `tests/`](https://github.com/irontec/sngrep/tree/master/tests),
[Wireshark `test/captures`](https://github.com/wireshark/wireshark/tree/master/test/captures)
and `SIP.pcap` from
[Malcolm-Test-Artifacts](https://github.com/idaholab/Malcolm-Test-Artifacts).

Version 0.1.0 did not crash on any file and agreed with `tshark` on the number of SIP
messages in 56 of them. The run found these problems, fixed in 0.1.1:

| Problem in 0.1.0 | Effect on the run |
|---|---|
| SSDP `NOTIFY * HTTP/1.1` taken for SIP; HTTP and RTSP `OPTIONS` affected in the same way | 656 false messages in one `(no Call-ID)` call |
| SIP inside PPPoE not found | 64 messages lost |
| SIP inside IP-in-IP not found | 2 messages lost |
| Requests with an unknown method dropped silently (they now appear in `errors`) | 11 messages unreported |
| A late `183` for the INVITE, after an `UPDATE` exchange, paired with the `UPDATE` offer | 2 wrong pairs |

With the fixes, 59 of the 61 files agree with `tshark`. In the other two, `tshark`
also counts the SIP copies inside ICMP errors (3 messages in each), which this library
leaves out on purpose. In one of them the 11 unknown-method requests are reported in
`errors` rather than as calls.

What the run does not show: only the number of SIP messages, Call-IDs and SDP bodies was
compared with `tshark`, not the content of parsed fields. Retransmission counts were not
validated: they differ from `tshark` (550 here, 423 there) because the definitions
differ, and the difference was not analysed further.

## Types

Written in TypeScript (strict). The package ships ES modules compiled to ES2022
with their declarations; no runtime helpers, no bundling. The library is compiled
without Node.js types, so it cannot use Node APIs by accident. All public types are
exported from the package root, including the `@irbisadm/simple-sdp` types used in the
API, so a project under pnpm does not need simple-sdp as its own dependency:

```ts
import type { Ladder, LadderCall, LadderSummary, SdpSession, SdpNegotiation } from "@irbisadm/sip-pcap";
```

## Development

```sh
nvm use             # Node 24 (.nvmrc); the library itself supports Node >= 20
npm ci
npm run build       # src/ -> dist/
npm test            # node:test via tsx (builds first)
npm run typecheck   # library, tests and a consumer of the built declarations
npm run check:pack  # check what npm would publish
```

## License

MIT
