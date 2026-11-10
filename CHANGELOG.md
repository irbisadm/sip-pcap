# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed — breaking

SDP interpretation moved to `@irbisadm/simple-sdp` 1.5.0 (`sdpResolver.resolve`,
`sdpNegotiator.negotiate`), and so do the SDP types: import them from `@irbisadm/simple-sdp`.
This package exports only `SdpSession`.

- `parseSdp()` returns `SdpSession` = simple-sdp `SdpResolved` (`bundle`, `hold`, `media`)
  plus `model` (the lenient model, every line as written) and `warnings`. Media sections
  use simple-sdp names: `proto` (was `protocol`), `extmap` (was `extensions`), `iceUfrag`,
  `icePwd`, `setup`, `fingerprints` (were `ice: {ufrag, pwd}` and `dtls: {setup, fingerprint}`),
  and `index`. `mid` is absent without `a=mid` (was `"m<index>"`).
- Codecs are simple-sdp codecs: `payloadType`, `encodingName`, `clockRate`,
  `encodingParameters`, `parameters` (an object), `rtcpFeedback` (were `pt`, `codec`, `rate`,
  `channels`, `fmtp` as text). They are in `m=` order; static payload types are no longer
  moved to the end. An unassigned payload type without `a=rtpmap` has no `encodingName` (was
  `"PT<n>"`).
- `origin` moved to `model.origin` with simple-sdp fields (`sessId`, `sessVersion` as strings,
  `addrType`, `unicastAddress`).
- Absent values are left out instead of `null`.
- `negotiate()` returns `SdpNegotiation`: per media section `codecs`, `extmap` (were
  `agreedCodecs`, `agreedExtensions`), `offerDirection`, `answerDirection` (were
  `directionOffer`, `directionAnswer`), `index` and `offerIndex`. `dtlsOffer`, `dtlsAnswer`,
  `iceOffer` and `iceAnswer` are gone: read them from the resolved media sections.
- `negotiate()` takes `bundle` from the answer only; an answer without BUNDLE gives `[]`
  (RFC 9143), where the offer's group was used before.
- A rejected media section (port 0) no longer counts as hold.
- Types `Direction`, `Codec`, `Extension`, `SdpMedia`, `SdpOrigin`, `NegotiatedMedia`,
  `Negotiation`, `SdpParseWarning`, `SdpParseWarningCode` and `SdpParseWarningAction` are no
  longer exported. Their counterparts in `@irbisadm/simple-sdp` are `SdpDirection`,
  `SdpResolvedCodec`, `SdpResolvedExtmap`, `SdpResolvedMediaSection`, `SdpOrigin`,
  `SdpNegotiatedMediaSection`, `SdpNegotiation` and the same three warning types.

### Added (via simple-sdp)

- Session-level `a=extmap` applies to media sections; `a=rtcp-fb:*` is added to every codec.

### Fixed

- A call whose INVITE was challenged with `401`/`407` and sent again with the next
  CSeq number is reported by the outcome of the retry: `completed` with its timings,
  not `407 Proxy Authentication Required`. Timings still count from the first INVITE.
- SDP in a `3xx`–`6xx` response (a `488` or `606` listing what the UA supports) is no
  longer taken as an answer: it has role `null` and no longer replaces the result of
  an earlier `183`. Such a response returns the offer/answer state to `stable`.
- SDP in a reply to `OPTIONS`, or in any method other than INVITE, ACK, PRACK and
  UPDATE, is no longer taken as a late offer.

### Added

- `OfferAnswerMessage` accepts `statusCode`; a `parseSipMessage` result already has it.

### Documentation

- Limits: B2BUA/SBC legs with a new Call-ID, endpoints per `host:port`, what counts as
  a retransmission, CSeq without direction, TCP stream keys, and fragments lost to
  `tcpdump port 5060`.

## [0.1.2] — 2026-11-08

### Fixed

- Doubled spaces in an `m=` line no longer shift its fields or lose its codecs:
  `m=audio  9 RTP/AVP 0` had no port and `9` as the protocol. `m=audio 9  RTP/AVP 0` had
  an empty protocol and no warning; it now gets a `malformed-media` warning. Comes from
  `@irbisadm/simple-sdp` 1.4.0, the new minimum version.

## [0.1.1] — 2026-11-08

Fixes from running the library over public capture files; see "Checked against real
captures" in the README.

### Added

- PPPoE sessions over Ethernet and IP tunnels (IP-in-IP, 6in4, 4in6, 6in6) are decoded.
- `ethernetPppoe` and `ipTunnel` in `@irbisadm/sip-pcap/testing`.

### Changed

- A request with a method that is not known but a valid SIP start line now counts as a
  SIP message and is reported in `errors` by `buildLadder`; it used to be dropped silently.

### Fixed

- Other protocols are no longer taken for SIP: SSDP `NOTIFY * HTTP/1.1`, HTTP and RTSP
  requests with a SIP method name made a false `(no Call-ID)` call. The first line now has
  to be a whole SIP start line, on any port. The check also reads far enough for a long
  request URI on a non-standard port.
- An answer now pairs with the offer of its own CSeq number on its hop. A late `183` for
  the INVITE, sent after an `UPDATE` exchange, was paired with the `UPDATE` offer.

## [0.1.0] — 2026-11-07

First release. The code comes from the SIP ladder and `sip_dialog` tools of
webrtc.page, made into a standalone package.

### Added

- `buildLadder` and `summarizeLadder`: SIP calls from a pcap/pcapng capture, with
  endpoints per `host:port`, messages in time order, retransmissions, SDP per step,
  offer/answer per hop, call status and timings, and a Mermaid sequence diagram.
- `parsePcap` and `reassembleSip`: classic pcap (µs and ns) and pcapng; Ethernet
  (802.1Q/QinQ), raw IP, BSD loopback, Linux cooked v1/v2; IPv4/IPv6 with extension
  headers and fragment reassembly; UDP and TCP (ordered by sequence number,
  retransmissions dropped, split by Content-Length); SIP found by port or content.
- `parseSipMessage`: compact headers, folding, repeated headers, SDP in plain and
  multipart bodies.
- `parseSdp` and `negotiate` (RFC 3264). SDP is parsed leniently with
  `@irbisadm/simple-sdp`: SDP that breaks RFC 8866 is still parsed, and its problems
  are reported as `warnings` (`parseSdp`), `sdpWarnings` (`parseSipMessage`, ladder
  messages). Differences from the earlier sdp-transform based parser are listed in
  the README.
- `createOfferAnswerTracker`: offer/answer roles, pairing per hop, late offers,
  retransmissions; one implementation for the ladder and stateful dialog stores.
- `@irbisadm/sip-pcap/testing`: in-memory pcap/pcapng writer and a proxied call scenario.
- Written in TypeScript; ships ES2022 modules with declarations.

### Fixed

- PRACK answering a late offer in a reliable 1xx is recognised by the INVITE CSeq
  number in `RAck`; before, it was compared with the PRACK's own CSeq number, which
  differs in real traffic.
