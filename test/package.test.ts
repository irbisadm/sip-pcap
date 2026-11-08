// The package entry points, as consumers import them (package self-reference to
// the built dist/; `npm test` builds first).
import { test } from "node:test";
import assert from "node:assert/strict";

test("@irbisadm/sip-pcap exports the public API", async () => {
  const api = await import("@irbisadm/sip-pcap");
  assert.deepEqual(Object.keys(api).sort(), [
    "buildLadder", "createOfferAnswerTracker", "negotiate", "parsePcap", "parseSdp",
    "parseSipMessage", "reassembleSip", "summarizeLadder",
  ]);
});

test("@irbisadm/sip-pcap/testing exports the capture builders and the proxy scenario", async () => {
  const testing = await import("@irbisadm/sip-pcap/testing");
  assert.deepEqual(Object.keys(testing).sort(), [
    "ALICE", "BOB", "PROXY", "classicPcap", "ethernetPppoe", "ethernetV6", "ipTunnel", "ipv4Udp", "ipv6Udp", "ipv6UdpFragmented",
    "linuxSll2", "pcapng", "proxyCallFlow", "proxyCallPcap", "sip", "tcp", "udp", "udpFragmented",
  ]);
  const { buildLadder } = await import("@irbisadm/sip-pcap");
  assert.equal(buildLadder(testing.proxyCallPcap()).calls[0].messages.length, 13);
});

test("internal modules are not importable", async () => {
  const internal: string = "@irbisadm/sip-pcap/dist/pcap.js";
  await assert.rejects(import(internal), { code: "ERR_PACKAGE_PATH_NOT_EXPORTED" });
});
