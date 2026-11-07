// Minimal pcap writer for tests and the SIP ladder sample capture: Ethernet +
// IPv4 + UDP/TCP frames, IPv4 fragmentation, classic pcap container.
// Plain Uint8Array, no Node APIs.

/** One captured frame: timestamp in ms since the Unix epoch (fractional) and frame bytes. */
export interface CaptureRecord {
  ts: number;
  frame: Uint8Array;
}

export type Payload = string | Uint8Array;

export interface UdpOptions {
  src: string;
  dst: string;
  sport?: number;
  dport?: number;
  payload: Payload;
  /** IP identification. */
  id?: number;
}

export interface FragmentOptions extends UdpOptions {
  /** Maximum IP payload bytes per fragment. */
  mtu?: number;
}

export interface TcpOptions {
  src: string;
  dst: string;
  sport: number;
  dport: number;
  seq: number;
  payload: Payload;
}

const enc = new TextEncoder();
const bytes = (x: Payload): Uint8Array => (typeof x === "string" ? enc.encode(x) : x);

function concat(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

const ip4 = (s: string) => s.split(".").map(Number);

function ethernet(etherType = 0x0800): Uint8Array {
  const e = new Uint8Array(14);
  e.set([0x02, 0, 0, 0, 0, 2, 0x02, 0, 0, 0, 0, 1]);
  new DataView(e.buffer).setUint16(12, etherType);
  return e;
}

function ipv4Header({ src, dst, proto, payloadLen, id = 0, moreFragments = false, fragOffset = 0 }: {
  src: string; dst: string; proto: number; payloadLen: number; id?: number; moreFragments?: boolean; fragOffset?: number;
}): Uint8Array {
  const h = new Uint8Array(20);
  const dv = new DataView(h.buffer);
  h[0] = 0x45;
  dv.setUint16(2, 20 + payloadLen);
  dv.setUint16(4, id);
  dv.setUint16(6, (moreFragments ? 0x2000 : 0) | (fragOffset / 8));
  h[8] = 64;
  h[9] = proto;
  h.set(ip4(src), 12);
  h.set(ip4(dst), 16);
  return h;
}

function udpSegment({ sport, dport, payload }: { sport: number; dport: number; payload: Payload }): Uint8Array {
  const data = bytes(payload);
  const u = new Uint8Array(8);
  const dv = new DataView(u.buffer);
  dv.setUint16(0, sport);
  dv.setUint16(2, dport);
  dv.setUint16(4, 8 + data.length);
  return concat([u, data]);
}

/** One Ethernet/IPv4/UDP frame. */
export function udp({ src, dst, sport = 5060, dport = 5060, payload, id = 0 }: UdpOptions): Uint8Array {
  const l4 = udpSegment({ sport, dport, payload });
  return concat([ethernet(), ipv4Header({ src, dst, proto: 17, payloadLen: l4.length, id }), l4]);
}

/** A UDP datagram split into IPv4 fragments of at most `mtu` bytes of IP payload (Ethernet frames). */
export function udpFragmented({ src, dst, sport = 5060, dport = 5060, payload, id = 1, mtu = 512 }: FragmentOptions): Uint8Array[] {
  const l4 = udpSegment({ sport, dport, payload });
  const size = Math.floor(mtu / 8) * 8;
  const frames: Uint8Array[] = [];
  for (let off = 0; off < l4.length; off += size) {
    const part = l4.subarray(off, off + size);
    const more = off + size < l4.length;
    frames.push(concat([ethernet(), ipv4Header({ src, dst, proto: 17, payloadLen: part.length, id, moreFragments: more, fragOffset: off }), part]));
  }
  return frames;
}

/** One Ethernet/IPv4/TCP frame (PSH+ACK) carrying `payload` at sequence number `seq`. */
export function tcp({ src, dst, sport, dport, seq, payload }: TcpOptions): Uint8Array {
  const data = bytes(payload);
  const t = new Uint8Array(20);
  const dv = new DataView(t.buffer);
  dv.setUint16(0, sport);
  dv.setUint16(2, dport);
  dv.setUint32(4, seq >>> 0);
  t[12] = 5 << 4;
  t[13] = 0x18; // PSH+ACK
  const l4 = concat([t, data]);
  return concat([ethernet(), ipv4Header({ src, dst, proto: 6, payloadLen: l4.length }), l4]);
}

/**
 * Classic little-endian pcap.
 * `nano` → nanosecond-resolution magic (0xa1b23c4d); `linkType` default 1 (EN10MB).
 */
export function classicPcap(records: CaptureRecord[], { nano = false, linkType = 1 }: { nano?: boolean; linkType?: number } = {}): Uint8Array {
  const gh = new Uint8Array(24);
  const g = new DataView(gh.buffer);
  g.setUint32(0, nano ? 0xa1b23c4d : 0xa1b2c3d4, true);
  g.setUint16(4, 2, true);
  g.setUint16(6, 4, true);
  g.setUint32(16, 65535, true);
  g.setUint32(20, linkType, true);
  const unit = nano ? 1e9 : 1e6;
  const recs = records.map(({ ts, frame }) => {
    const rh = new Uint8Array(16);
    const r = new DataView(rh.buffer);
    const ticks = Math.round(ts * (unit / 1000));
    r.setUint32(0, Math.floor(ticks / unit), true);
    r.setUint32(4, ticks % unit, true);
    r.setUint32(8, frame.length, true);
    r.setUint32(12, frame.length, true);
    return concat([rh, frame]);
  });
  return concat([gh, ...recs]);
}

const pad4 = (n: number) => (4 - (n % 4)) % 4;

/**
 * pcapng with one SHB and one IDB.
 * `tsresol` → if_tsresol option value (default 6 = µs; 9 = ns); `linkType` default 1.
 */
export function pcapng(records: CaptureRecord[], { tsresol = 6, linkType = 1 }: { tsresol?: number; linkType?: number } = {}): Uint8Array {
  const shb = new Uint8Array(28);
  const s = new DataView(shb.buffer);
  s.setUint32(0, 0x0a0d0d0a, true);
  s.setUint32(4, 28, true);
  s.setUint32(8, 0x1a2b3c4d, true);
  s.setUint16(12, 1, true);
  s.setInt32(16, -1, true);
  s.setInt32(20, -1, true);
  s.setUint32(24, 28, true);
  // IDB with an if_tsresol option (code 9, 1 byte) and opt_endofopt
  const idb = new Uint8Array(32);
  const d = new DataView(idb.buffer);
  d.setUint32(0, 1, true);
  d.setUint32(4, 32, true);
  d.setUint16(8, linkType, true);
  d.setUint32(12, 65535, true);
  d.setUint16(16, 9, true);
  d.setUint16(18, 1, true);
  idb[20] = tsresol;
  d.setUint16(24, 0, true);
  d.setUint16(26, 0, true);
  d.setUint32(28, 32, true);
  const perSec = 10 ** tsresol;
  const epbs = records.map(({ ts, frame }) => {
    const total = 28 + frame.length + pad4(frame.length) + 4;
    const b = new Uint8Array(total);
    const v = new DataView(b.buffer);
    const ticks = BigInt(Math.round(ts * (perSec / 1000)));
    v.setUint32(0, 6, true);
    v.setUint32(4, total, true);
    v.setUint32(8, 0, true);
    v.setUint32(12, Number(ticks >> 32n), true);
    v.setUint32(16, Number(ticks & 0xffffffffn), true);
    v.setUint32(20, frame.length, true);
    v.setUint32(24, frame.length, true);
    b.set(frame, 28);
    v.setUint32(total - 4, total, true);
    return b;
  });
  return concat([shb, idb, ...epbs]);
}

function ipv6Addr(str: string): Uint8Array {
  const [head, tail = ""] = str.split("::");
  const h = head ? head.split(":") : [];
  const t = tail ? tail.split(":") : [];
  const groups = [...h, ...Array<string>(8 - h.length - t.length).fill("0"), ...t];
  const out = new Uint8Array(16);
  groups.forEach((g, i) => { out[i * 2] = parseInt(g, 16) >> 8; out[i * 2 + 1] = parseInt(g, 16) & 0xff; });
  return out;
}

function ipv6Packet({ src, dst, next, body }: { src: string; dst: string; next: number; body: Uint8Array }): Uint8Array {
  const h = new Uint8Array(40);
  const dv = new DataView(h.buffer);
  dv.setUint32(0, 0x60000000);
  dv.setUint16(4, body.length);
  h[6] = next;
  h[7] = 64;
  h.set(ipv6Addr(src), 8);
  h.set(ipv6Addr(dst), 24);
  return concat([h, body]);
}

/**
 * IPv6/UDP packet (no link layer), with a hop-by-hop options header in front of
 * UDP so the extension-header walk is exercised.
 */
export function ipv6Udp({ src, dst, sport = 5060, dport = 5060, payload }: Omit<UdpOptions, "id">): Uint8Array {
  const hbh = new Uint8Array(8);
  hbh[0] = 17; // next: UDP
  hbh[1] = 0; // (0 + 1) * 8 bytes
  hbh[2] = 1; hbh[3] = 4; // PadN option filling the rest
  return ipv6Packet({ src, dst, next: 0, body: concat([hbh, udpSegment({ sport, dport, payload })]) });
}

/** An IPv6/UDP datagram split with IPv6 Fragment headers (IPv6 packets, no link layer). */
export function ipv6UdpFragmented({ src, dst, sport = 5060, dport = 5060, payload, id = 7, mtu = 512 }: FragmentOptions): Uint8Array[] {
  const l4 = udpSegment({ sport, dport, payload });
  const size = Math.floor(mtu / 8) * 8;
  const out: Uint8Array[] = [];
  for (let off = 0; off < l4.length; off += size) {
    const part = l4.subarray(off, off + size);
    const fh = new Uint8Array(8);
    const dv = new DataView(fh.buffer);
    fh[0] = 17;
    dv.setUint16(2, off | (off + size < l4.length ? 1 : 0));
    dv.setUint32(4, id);
    out.push(ipv6Packet({ src, dst, next: 44, body: concat([fh, part]) }));
  }
  return out;
}

/** Ethernet frame around an IPv6 packet. */
export function ethernetV6(ipPacket: Uint8Array): Uint8Array {
  return concat([ethernet(0x86dd), ipPacket]);
}

/** Linux cooked capture v2 (LINKTYPE 276) header around an IP packet. */
export function linuxSll2(ipPacket: Uint8Array, etherType = 0x0800): Uint8Array {
  const h = new Uint8Array(20);
  const dv = new DataView(h.buffer);
  dv.setUint16(0, etherType);
  dv.setUint32(4, 2); // interface index
  dv.setUint16(8, 1); // ARPHRD_ETHER
  h[10] = 0; // PACKET_HOST
  h[11] = 6; // address length
  return concat([h, ipPacket]);
}

/** IPv4/UDP packet without a link layer (for raw-IP and cooked captures). */
export function ipv4Udp({ src, dst, sport = 5060, dport = 5060, payload, id = 0 }: UdpOptions): Uint8Array {
  const l4 = udpSegment({ sport, dport, payload });
  return concat([ipv4Header({ src, dst, proto: 17, payloadLen: l4.length, id }), l4]);
}

/**
 * Build a SIP message text with CRLF line endings and a correct Content-Length.
 * A non-empty body gets `Content-Type: application/sdp`.
 */
export function sip(startLine: string, headers: string[], body = ""): string {
  const b = body.replace(/\r?\n/g, "\r\n");
  const lines = [startLine, ...headers];
  if (b) lines.push("Content-Type: application/sdp");
  lines.push(`Content-Length: ${enc.encode(b).length}`);
  return lines.join("\r\n") + "\r\n\r\n" + b;
}
