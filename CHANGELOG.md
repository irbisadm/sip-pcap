# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

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
