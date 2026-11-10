// SDP samples shared by the unit tests.

export const sdpOffer = [
  "v=0", "o=- 1 2 IN IP4 127.0.0.1", "s=-", "t=0 0", "a=group:BUNDLE 0 1",
  "m=audio 49170 UDP/TLS/RTP/SAVPF 111 0", "c=IN IP4 0.0.0.0", "a=mid:0", "a=sendrecv",
  "a=ice-ufrag:aaaa", "a=ice-pwd:bbbbbbbbbbbbbbbbbbbbbb",
  "a=fingerprint:sha-256 AA:BB", "a=setup:actpass",
  "a=rtpmap:111 opus/48000/2", "a=fmtp:111 minptime=10;useinbandfec=1",
  "a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level",
  "m=video 49172 UDP/TLS/RTP/SAVPF 96", "a=mid:1", "a=sendrecv", "a=rtpmap:96 VP8/90000",
].join("\r\n") + "\r\n";

export const sdpAnswer = [
  "v=0", "o=- 9 2 IN IP4 127.0.0.1", "s=-", "t=0 0", "a=group:BUNDLE 0 1",
  "m=audio 49180 UDP/TLS/RTP/SAVPF 111", "c=IN IP4 0.0.0.0", "a=mid:0", "a=sendrecv",
  "a=setup:active", "a=rtpmap:111 opus/48000/2",
  "a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level",
  "m=video 0 UDP/TLS/RTP/SAVPF 96", "a=mid:1", "a=rtpmap:96 VP8/90000",
].join("\r\n") + "\r\n";

export const sipSdp = `v=0
o=alice 2890844526 2890844526 IN IP4 192.0.2.10
s=-
c=IN IP4 192.0.2.10
t=0 0
m=audio 49170 RTP/AVP 0 8 18 101
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=fmtp:18 annexb=no
`;
