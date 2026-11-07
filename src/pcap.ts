// pcap/pcapng reader and SIP reassembly.
// Runtime-neutral: Uint8Array / DataView / TextDecoder only, so the same code runs
// in Node.js, browsers and Web Workers. Node's Buffer works as input (it is a Uint8Array).

/** A decoded UDP or TCP packet. */
export interface Packet {
  /** Capture timestamp, ms since the Unix epoch (fractional). */
  ts: number;
  /** Source IP (IPv6 in RFC 5952 form). */
  src: string;
  /** Destination IP. */
  dst: string;
  sport: number;
  dport: number;
  proto: "udp" | "tcp";
  /** Transport payload (a view into the input). */
  payload: Uint8Array;
  /** TCP sequence number. */
  seq?: number;
  /** TCP flags byte. */
  flags?: number;
}

/** A SIP message found in a capture, not parsed yet. */
export interface RawSipMessage {
  /** Message text. */
  raw: string;
  /** Timestamp of the packet its first byte arrived in. */
  ts: number;
  /** Sender `host:port`, IPv6 hosts in brackets. */
  src: string;
  /** Receiver `host:port`. */
  dst: string;
  proto: "udp" | "tcp";
}

export interface ReassembleOptions {
  /** SIP port hint (default 5060); `null` relies on content detection only. */
  sipPort?: number | null;
}

type FragmentTable = Map<string, { parts: { offset: number; data: Uint8Array }[]; total: number | null }>;
type TcpSegment = { seq: number; ts: number; payload: Uint8Array };

const utf8 = new TextDecoder("utf-8");

function toBytes(input: Uint8Array | ArrayBuffer | ArrayBufferView): Uint8Array {
  if (input instanceof Uint8Array) return input;
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  if (ArrayBuffer.isView(input)) return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  throw new Error("parsePcap: expected Uint8Array or ArrayBuffer");
}
const dataView = (b: Uint8Array) => new DataView(b.buffer, b.byteOffset, b.byteLength);

// ─── pcap parsing (classic + pcapng) ────────────────────────────────────────

/**
 * Decode a classic pcap (µs or ns) or pcapng capture into UDP and TCP packets.
 * Other protocols and link layers are skipped. IP fragments are reassembled.
 * @throws Error when the input is not pcap or pcapng
 */
export function parsePcap(input: Uint8Array | ArrayBuffer | ArrayBufferView): Packet[] {
  const buf = toBytes(input);
  if (buf.length < 4) throw new Error("parsePcap: buffer too small");
  const dv = dataView(buf);
  const m32be = dv.getUint32(0, false);
  if (m32be === 0x0a0d0d0a) return parsePcapng(buf, dv);
  if (
    m32be === 0xa1b2c3d4 || m32be === 0xd4c3b2a1 ||
    m32be === 0xa1b23c4d || m32be === 0x4d3cb2a1
  ) {
    return parseClassicPcap(buf, dv);
  }
  throw new Error(
    `parsePcap: unknown magic 0x${m32be.toString(16)} (not classic pcap or pcapng)`
  );
}

function parseClassicPcap(buf: Uint8Array, dv: DataView): Packet[] {
  const magic = dv.getUint32(0, false);
  // little-endian if byte-swapped magic
  const le = magic === 0xd4c3b2a1 || magic === 0x4d3cb2a1;
  const nano = magic === 0xa1b23c4d || magic === 0x4d3cb2a1;
  const linkType = dv.getUint32(20, le);
  const frags: FragmentTable = new Map();
  const packets: Packet[] = [];
  let off = 24;
  while (off + 16 <= buf.length) {
    const tsSec = dv.getUint32(off, le);
    const tsFrac = dv.getUint32(off + 4, le);
    const inclLen = dv.getUint32(off + 8, le);
    off += 16;
    if (off + inclLen > buf.length) break;
    const frame = buf.subarray(off, off + inclLen);
    off += inclLen;
    const ts = tsSec * 1000 + (nano ? tsFrac / 1e6 : tsFrac / 1e3);
    const pkt = decodeFrame(frame, linkType, ts, frags);
    if (pkt) packets.push(pkt);
  }
  return packets;
}

// if_tsresol option value → timestamp units per second.
function tsUnitsPerSec(v: number): number {
  return v & 0x80 ? 2 ** (v & 0x7f) : 10 ** (v & 0x7f);
}

function parsePcapng(buf: Uint8Array, dv: DataView): Packet[] {
  let le = true;
  let ifaces: { linkType: number; unitsPerSec: number }[] = []; // per section
  const frags: FragmentTable = new Map();
  const packets: Packet[] = [];
  let off = 0;
  while (off + 12 <= buf.length) {
    // the byte order is fixed per section, announced by each SHB
    if (dv.getUint32(off, false) === 0x0a0d0d0a) {
      le = dv.getUint32(off + 8, true) === 0x1a2b3c4d;
      ifaces = [];
    }
    const blockType = dv.getUint32(off, le);
    const totalLen = dv.getUint32(off + 4, le);
    if (totalLen < 12 || off + totalLen > buf.length) break;
    if (blockType === 0x00000001) {
      // Interface Description Block: linktype(2), reserved(2), snaplen(4), options
      const iface = { linkType: dv.getUint16(off + 8, le), unitsPerSec: 1e6 };
      let o = off + 16;
      const end = off + totalLen - 4;
      while (o + 4 <= end) {
        const code = dv.getUint16(o, le);
        const len = dv.getUint16(o + 2, le);
        if (code === 0) break;
        if (code === 9 && len >= 1) iface.unitsPerSec = tsUnitsPerSec(buf[o + 4]);
        o += 4 + len + ((4 - (len % 4)) % 4);
      }
      ifaces.push(iface);
    } else if (blockType === 0x00000006) {
      // Enhanced Packet Block: iface_id(4), ts_hi(4), ts_lo(4), cap_len(4), orig_len(4)
      const iface = ifaces[dv.getUint32(off + 8, le)] ?? { linkType: 1, unitsPerSec: 1e6 };
      const ticks = dv.getUint32(off + 12, le) * 4294967296 + dv.getUint32(off + 16, le);
      const capLen = dv.getUint32(off + 20, le);
      const dataStart = off + 28;
      const frame = buf.subarray(dataStart, Math.min(dataStart + capLen, off + totalLen));
      const ts = (ticks * 1000) / iface.unitsPerSec;
      const pkt = decodeFrame(frame, iface.linkType, ts, frags);
      if (pkt) packets.push(pkt);
    } else if (blockType === 0x00000003) {
      // Simple Packet Block: orig_len(4), packet data (no timestamp)
      const frame = buf.subarray(off + 12, off + totalLen - 4);
      const pkt = decodeFrame(frame, ifaces[0]?.linkType ?? 1, 0, frags);
      if (pkt) packets.push(pkt);
    }
    off += totalLen + ((4 - (totalLen % 4)) % 4);
  }
  return packets;
}

// IP fragment reassembly. Keyed by src|dst|id|proto; returns the full payload once
// the last fragment and every byte before it have arrived, else null.
function addFragment(frags: FragmentTable, key: string, offset: number, more: boolean, data: Uint8Array): Uint8Array | null {
  let f = frags.get(key);
  if (!f) {
    f = { parts: [], total: null };
    frags.set(key, f);
  }
  f.parts.push({ offset, data });
  if (!more) f.total = offset + data.length;
  if (f.total === null) return null;
  f.parts.sort((a, b) => a.offset - b.offset);
  let covered = 0;
  for (const p of f.parts) {
    if (p.offset > covered) return null;
    covered = Math.max(covered, p.offset + p.data.length);
  }
  if (covered < f.total) return null;
  const out = new Uint8Array(f.total);
  for (const p of f.parts) out.set(p.data.subarray(0, Math.max(0, Math.min(p.data.length, f.total - p.offset))), p.offset);
  frags.delete(key);
  return out;
}

// Strip link/IP/transport layers, return a UDP/TCP payload with endpoints.
function decodeFrame(frame: Uint8Array, linkType: number, ts: number, frags: FragmentTable): Packet | null {
  const dv = dataView(frame);
  let off = 0;
  let etherType: number;
  if (linkType === 1) {
    // EN10MB Ethernet (+ 802.1Q / QinQ tags)
    if (frame.length < 14) return null;
    etherType = dv.getUint16(12);
    off = 14;
    while (etherType === 0x8100 || etherType === 0x88a8) {
      if (off + 4 > frame.length) return null;
      etherType = dv.getUint16(off + 2);
      off += 4;
    }
  } else if (linkType === 101 || linkType === 12 || linkType === 14 || linkType === 228 || linkType === 229) {
    // raw IP
    etherType = (frame[0] >> 4) === 6 ? 0x86dd : 0x0800;
  } else if (linkType === 0 || linkType === 108) {
    // BSD loopback / OpenBSD loop: 4-byte family header
    off = 4;
    etherType = (frame[off] >> 4) === 6 ? 0x86dd : 0x0800;
  } else if (linkType === 113) {
    // Linux cooked capture v1
    if (frame.length < 16) return null;
    etherType = dv.getUint16(14);
    off = 16;
  } else if (linkType === 276) {
    // Linux cooked capture v2 (protocol type first)
    if (frame.length < 20) return null;
    etherType = dv.getUint16(0);
    off = 20;
  } else {
    return null;
  }

  let proto: number;
  let srcIp: string;
  let dstIp: string;
  let l4: Uint8Array | null;
  if (etherType === 0x0800) {
    if (off + 20 > frame.length) return null;
    const ihl = (frame[off] & 0x0f) * 4;
    const totalLen = dv.getUint16(off + 2);
    const id = dv.getUint16(off + 4);
    const flagsFrag = dv.getUint16(off + 6);
    proto = frame[off + 9];
    srcIp = `${frame[off + 12]}.${frame[off + 13]}.${frame[off + 14]}.${frame[off + 15]}`;
    dstIp = `${frame[off + 16]}.${frame[off + 17]}.${frame[off + 18]}.${frame[off + 19]}`;
    // totalLen bounds the datagram: Ethernet pads short frames with zeros
    const end = totalLen ? Math.min(frame.length, off + totalLen) : frame.length;
    l4 = frame.subarray(off + ihl, end);
    const more = (flagsFrag & 0x2000) !== 0;
    const fragOff = (flagsFrag & 0x1fff) * 8;
    if (more || fragOff) {
      l4 = addFragment(frags, `${srcIp}|${dstIp}|${id}|${proto}`, fragOff, more, l4);
      if (!l4) return null;
    }
  } else if (etherType === 0x86dd) {
    if (off + 40 > frame.length) return null;
    const payloadLen = dv.getUint16(off + 4);
    let next = frame[off + 6];
    srcIp = ipv6Str(dv, off + 8);
    dstIp = ipv6Str(dv, off + 24);
    const end = payloadLen ? Math.min(frame.length, off + 40 + payloadLen) : frame.length;
    let p = off + 40;
    let frag: { offset: number; more: boolean; id: number } | null = null;
    // walk extension headers: hop-by-hop, routing, destination options, fragment
    while (next === 0 || next === 43 || next === 60 || next === 44) {
      if (p + 8 > end) return null;
      if (next === 44) {
        const fo = dv.getUint16(p + 2);
        frag = { offset: fo & 0xfff8, more: (fo & 1) === 1, id: dv.getUint32(p + 4) };
        next = frame[p];
        p += 8;
      } else {
        const hdrLen = (frame[p + 1] + 1) * 8;
        next = frame[p];
        p += hdrLen;
      }
    }
    proto = next;
    l4 = frame.subarray(p, end);
    if (frag && (frag.more || frag.offset)) {
      l4 = addFragment(frags, `${srcIp}|${dstIp}|${frag.id}|${proto}`, frag.offset, frag.more, l4);
      if (!l4) return null;
    }
  } else {
    return null;
  }

  const lv = dataView(l4);
  if (proto === 17) {
    if (l4.length < 8) return null;
    const udpLen = lv.getUint16(4);
    const end = udpLen >= 8 ? Math.min(l4.length, udpLen) : l4.length;
    return {
      ts, src: srcIp, dst: dstIp, sport: lv.getUint16(0), dport: lv.getUint16(2),
      proto: "udp", payload: l4.subarray(8, end),
    };
  }
  if (proto === 6) {
    if (l4.length < 20) return null;
    const dataOff = ((l4[12] >> 4) & 0x0f) * 4;
    return {
      ts, src: srcIp, dst: dstIp, sport: lv.getUint16(0), dport: lv.getUint16(2),
      proto: "tcp", seq: lv.getUint32(4), flags: l4[13], payload: l4.subarray(dataOff),
    };
  }
  return null;
}

function ipv6Str(dv: DataView, off: number): string {
  const parts: string[] = [];
  for (let i = 0; i < 16; i += 2) parts.push(dv.getUint16(off + i).toString(16));
  // RFC 5952 style: compress the longest run of zero groups
  let best = -1, bestLen = 0;
  for (let i = 0; i < 8; ) {
    if (parts[i] !== "0") { i++; continue; }
    let j = i;
    while (j < 8 && parts[j] === "0") j++;
    if (j - i > bestLen && j - i > 1) { best = i; bestLen = j - i; }
    i = j;
  }
  if (best === -1) return parts.join(":");
  return `${parts.slice(0, best).join(":")}::${parts.slice(best + bestLen).join(":")}`;
}

// ─── SIP reassembly ─────────────────────────────────────────────────────────

const SIP_START_RE = /^(INVITE|ACK|BYE|CANCEL|REGISTER|OPTIONS|INFO|PRACK|UPDATE|SUBSCRIBE|NOTIFY|REFER|MESSAGE|PUBLISH)\s|^SIP\/2\.0\s/;
const SIP_LINE_RE = /(^|\r?\n)((INVITE|ACK|BYE|CANCEL|REGISTER|OPTIONS|INFO|PRACK|UPDATE|SUBSCRIBE|NOTIFY|REFER|MESSAGE|PUBLISH) \S+ SIP\/2\.0|SIP\/2\.0 \d{3} )/;

function looksLikeSip(text: string): boolean {
  return SIP_START_RE.test(text.trimStart());
}

// Peek at the first bytes only: cheap check before decoding a whole payload.
function bytesLookLikeSip(bytes: Uint8Array): boolean {
  return looksLikeSip(utf8.decode(bytes.subarray(0, 64)));
}

function indexOfCrlfCrlf(b: Uint8Array, from: number): number {
  for (let i = from; i + 3 < b.length; i++) {
    if (b[i] === 13 && b[i + 1] === 10 && b[i + 2] === 13 && b[i + 3] === 10) return i;
  }
  return -1;
}

// Split a TCP byte stream into SIP messages by Content-Length (which counts bytes,
// so the split happens on bytes, not on decoded characters). Each message gets the
// timestamp of the segment its first byte arrived in.
function splitSipBytes(bytes: Uint8Array, tsAt: (offset: number) => number): { raw: string; ts: number }[] {
  const out: { raw: string; ts: number }[] = [];
  let pos = 0;
  while (pos < bytes.length) {
    // skip CRLF keep-alives between messages
    while (pos < bytes.length && (bytes[pos] === 13 || bytes[pos] === 10)) pos++;
    if (pos >= bytes.length) break;
    if (!bytesLookLikeSip(bytes.subarray(pos))) {
      // capture started mid-message: resync on the next start line
      const rest = utf8.decode(bytes.subarray(pos));
      const m = SIP_LINE_RE.exec(rest);
      if (!m) break;
      const skipChars = m.index + m[1].length;
      pos += new TextEncoder().encode(rest.slice(0, skipChars)).length;
      continue;
    }
    const hdrEnd = indexOfCrlfCrlf(bytes, pos);
    if (hdrEnd === -1) {
      out.push({ raw: utf8.decode(bytes.subarray(pos)), ts: tsAt(pos) });
      break;
    }
    const head = utf8.decode(bytes.subarray(pos, hdrEnd));
    const clMatch = head.match(/(?:^|\n)(?:content-length|l)[ \t]*:[ \t]*(\d+)/i);
    const end = Math.min(bytes.length, hdrEnd + 4 + (clMatch ? parseInt(clMatch[1], 10) : 0));
    out.push({ raw: utf8.decode(bytes.subarray(pos, end)), ts: tsAt(pos) });
    pos = end;
  }
  return out;
}

// Order one direction of a TCP connection by sequence number and drop
// retransmitted / overlapping bytes.
function assembleTcp(segs: TcpSegment[]): { bytes: Uint8Array; tsAt: (offset: number) => number } {
  segs.sort((a, b) => a.seq - b.seq || a.ts - b.ts);
  const chunks: Uint8Array[] = [];
  const marks: [offset: number, ts: number][] = [];
  let next: number | null = null;
  let length = 0;
  for (const s of segs) {
    let data = s.payload;
    if (next !== null) {
      const delta = s.seq - next;
      if (delta < 0) {
        if (-delta >= data.length) continue; // pure retransmission
        data = data.subarray(-delta);
      }
    }
    if (!data.length) continue;
    marks.push([length, s.ts]);
    chunks.push(data);
    length += data.length;
    next = (next === null ? s.seq : Math.max(next, s.seq)) + s.payload.length;
  }
  const bytes = new Uint8Array(length);
  let o = 0;
  for (const c of chunks) { bytes.set(c, o); o += c.length; }
  const tsAt = (offset: number): number => {
    let ts = marks[0]?.[1] ?? 0;
    for (const [mo, mts] of marks) { if (mo > offset) break; ts = mts; }
    return ts;
  };
  return { bytes, tsAt };
}

// host:port, with IPv6 hosts in brackets (RFC 3986) so the port is unambiguous
const endpoint = (ip: string, port: number) => (ip.includes(":") ? `[${ip}]:${port}` : `${ip}:${port}`);

/**
 * Turn packets into time-ordered SIP messages with endpoint info.
 * A packet counts when either port equals `sipPort` or its payload starts like a
 * SIP message, so SIP on non-standard ports is found too. TCP streams are ordered
 * by sequence number, retransmitted bytes dropped, and split by Content-Length.
 */
export function reassembleSip(packets: Packet[], { sipPort = 5060 }: ReassembleOptions = {}): RawSipMessage[] {
  const out: RawSipMessage[] = [];
  const tcpStreams = new Map<string, { segs: TcpSegment[]; sip: boolean; src: string; dst: string }>();
  for (const p of packets) {
    const onPort = sipPort != null && (p.sport === sipPort || p.dport === sipPort);
    if (p.proto === "udp") {
      if (!p.payload.length) continue;
      if (!onPort && !bytesLookLikeSip(p.payload)) continue;
      const text = utf8.decode(p.payload);
      if (looksLikeSip(text)) {
        out.push({ raw: text, ts: p.ts, src: endpoint(p.src, p.sport), dst: endpoint(p.dst, p.dport), proto: "udp" });
      }
    } else {
      const key = `${p.src}:${p.sport}>${p.dst}:${p.dport}`;
      let s = tcpStreams.get(key);
      if (!s) {
        s = { segs: [], sip: onPort, src: endpoint(p.src, p.sport), dst: endpoint(p.dst, p.dport) };
        tcpStreams.set(key, s);
      }
      if (!p.payload.length) continue;
      if (!s.sip && bytesLookLikeSip(p.payload)) s.sip = true;
      s.segs.push({ seq: p.seq ?? 0, ts: p.ts, payload: p.payload });
    }
  }
  for (const s of tcpStreams.values()) {
    if (!s.sip || !s.segs.length) continue;
    const { bytes, tsAt } = assembleTcp(s.segs);
    for (const m of splitSipBytes(bytes, tsAt)) {
      out.push({ raw: m.raw, ts: m.ts, src: s.src, dst: s.dst, proto: "tcp" });
    }
  }
  out.sort((a, b) => a.ts - b.ts);
  return out;
}
