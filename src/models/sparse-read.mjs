import fs from 'node:fs';

const MB = 1024 * 1024;
const SIG_LOCAL = 0x04034b50;
const SIG_CENTRAL = 0x02014b50;
const SIG_EOCD = 0x06054b50;
const SIG_EOCD64 = 0x06064b50;
const SIG_LOCATOR64 = 0x07064b50;
const MAX32 = 0xffffffff;

export function readAt(fd, pos, len) {
  const buf = Buffer.alloc(Math.max(0, len));
  const n = len > 0 ? fs.readSync(fd, buf, 0, len, pos) : 0;
  return buf.subarray(0, n);
}

const u64 = (buf, o) => Number(buf.readBigUInt64LE(o));

function zipDirectory(fd, size) {
  const tailLen = Math.min(size, 22 + 0xffff + 20);
  const tail = readAt(fd, size - tailLen, tailLen);
  for (let i = tail.length - 22; i >= 0; i--) {
    if (tail.readUInt32LE(i) !== SIG_EOCD) continue;
    let count = tail.readUInt16LE(i + 10);
    let cdSize = tail.readUInt32LE(i + 12);
    let cdOffset = tail.readUInt32LE(i + 16);
    if (count === 0xffff || cdSize === MAX32 || cdOffset === MAX32) {
      if (i < 20 || tail.readUInt32LE(i - 20) !== SIG_LOCATOR64) continue;
      const rec = readAt(fd, u64(tail, i - 12), 56);
      if (rec.length < 56 || rec.readUInt32LE(0) !== SIG_EOCD64) continue;
      count = u64(rec, 32);
      cdSize = u64(rec, 40);
      cdOffset = u64(rec, 48);
    }
    if (cdOffset + cdSize <= size) return { count, cdSize, cdOffset };
  }
  return null;
}

function* centralRecords(cd, max) {
  let p = 0;
  for (let n = 0; n < max && p + 46 <= cd.length; n++) {
    if (cd.readUInt32LE(p) !== SIG_CENTRAL) return;
    const method = cd.readUInt16LE(p + 10);
    let compSize = cd.readUInt32LE(p + 20);
    let size = cd.readUInt32LE(p + 24);
    const nameLen = cd.readUInt16LE(p + 28);
    const extraLen = cd.readUInt16LE(p + 30);
    const commentLen = cd.readUInt16LE(p + 32);
    let localOffset = cd.readUInt32LE(p + 42);
    const name = cd.toString('utf8', p + 46, p + 46 + nameLen);
    const extra = cd.subarray(p + 46 + nameLen, p + 46 + nameLen + extraLen);
    if (size === MAX32 || compSize === MAX32 || localOffset === MAX32) {
      for (let e = 0; e + 4 <= extra.length; ) {
        const id = extra.readUInt16LE(e);
        const len = extra.readUInt16LE(e + 2);
        if (id === 0x0001) {
          let q = e + 4;
          const end = Math.min(extra.length, q + len);
          if (size === MAX32 && q + 8 <= end) { size = u64(extra, q); q += 8; }
          if (compSize === MAX32 && q + 8 <= end) { compSize = u64(extra, q); q += 8; }
          if (localOffset === MAX32 && q + 8 <= end) localOffset = u64(extra, q);
          break;
        }
        e += 4 + len;
      }
    }
    yield { name, method, compSize, size, localOffset };
    p += 46 + nameLen + extraLen + commentLen;
  }
}

export function zipSubset(fd, size, match, { maxEntry = 64 * MB, maxTotal = 128 * MB, maxEntries = 8192, maxDirectory = 64 * MB } = {}) {
  const dir = zipDirectory(fd, size);
  if (!dir || dir.cdSize > maxDirectory) return null;
  const cd = readAt(fd, dir.cdOffset, dir.cdSize);
  if (cd.length < dir.cdSize) return null;
  const locals = [];
  const centrals = [];
  let offset = 0;
  let total = 0;
  let taken = 0;
  let skipped = 0;
  for (const r of centralRecords(cd, maxEntries)) {
    if (!match.test(r.name)) continue;
    if ((r.method !== 0 && r.method !== 8) || r.compSize > maxEntry || total + r.compSize > maxTotal || taken >= 0xffff) {
      skipped++;
      continue;
    }
    const head = readAt(fd, r.localOffset, 30);
    if (head.length < 30 || head.readUInt32LE(0) !== SIG_LOCAL) {
      skipped++;
      continue;
    }
    const data = readAt(fd, r.localOffset + 30 + head.readUInt16LE(26) + head.readUInt16LE(28), r.compSize);
    if (data.length < r.compSize) {
      skipped++;
      continue;
    }
    const name = Buffer.from(r.name, 'utf8');
    const inflated = Math.min(r.size, MAX32 - 1);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(SIG_LOCAL, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(r.method, 8);
    local.writeUInt32LE(r.compSize, 18);
    local.writeUInt32LE(inflated, 22);
    local.writeUInt16LE(name.length, 26);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(SIG_CENTRAL, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(r.method, 10);
    central.writeUInt32LE(r.compSize, 20);
    central.writeUInt32LE(inflated, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt32LE(offset, 42);
    locals.push(local, name, data);
    centrals.push(central, name);
    offset += 30 + name.length + data.length;
    total += data.length;
    taken++;
  }
  const directory = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(SIG_EOCD, 0);
  eocd.writeUInt16LE(taken, 8);
  eocd.writeUInt16LE(taken, 10);
  eocd.writeUInt32LE(directory.length, 12);
  eocd.writeUInt32LE(offset, 16);
  return { buf: Buffer.concat([...locals, directory, eocd]), read: taken, skipped };
}

function byteReader(fd, size, window = 4096) {
  let base = 0;
  let buf = Buffer.alloc(0);
  return (pos) => {
    if (pos < base || pos >= base + buf.length) {
      buf = readAt(fd, pos, Math.min(window, size - pos));
      base = pos;
      if (!buf.length) throw new Error('read past the end');
    }
    return buf[pos - base];
  };
}

function varint(byte, pos, end) {
  let value = 0;
  let mul = 1;
  for (let i = 0; i < 10; i++) {
    if (pos >= end) throw new Error('truncated varint');
    const b = byte(pos++);
    value += (b & 0x7f) * mul;
    if (b < 0x80) return [value, pos];
    mul *= 128;
  }
  throw new Error('varint too long');
}

function* pbFields(byte, start, end, budget) {
  let p = start;
  while (p < end) {
    if (++budget.steps > budget.maxSteps) throw new Error('too many fields');
    const keyAt = p;
    const [key, q] = varint(byte, p, end);
    const field = Math.floor(key / 8);
    const wire = key % 8;
    if (!field) throw new Error('field 0');
    let dataAt = q;
    let next;
    if (wire === 0) next = varint(byte, q, end)[1];
    else if (wire === 1) next = q + 8;
    else if (wire === 5) next = q + 4;
    else if (wire === 2) {
      const [len, r] = varint(byte, q, end);
      dataAt = r;
      next = r + len;
    } else throw new Error(`wire type ${wire}`);
    if (next > end) throw new Error('field overruns its message');
    yield { field, wire, keyAt, dataAt, next };
    p = next;
  }
}

function encodeVarint(n) {
  const out = [];
  let v = n;
  while (v > 127) {
    out.push((v % 128) | 128);
    v = Math.floor(v / 128);
  }
  out.push(v);
  return Buffer.from(out);
}

const lengthField = (field, body) => Buffer.concat([encodeVarint(field * 8 + 2), encodeVarint(body.length), body]);

const ONNX_GRAPH = 7;
const GRAPH_INITIALIZER = 5;
const GRAPH_SPARSE_INITIALIZER = 15;
const TENSOR_PAYLOAD = new Set([4, 5, 6, 7, 9, 10, 11]);

export function onnxSkeleton(fd, size, { maxField = 16 * MB, maxTotal = 64 * MB, maxSteps = 2_000_000 } = {}) {
  const byte = byteReader(fd, size);
  const budget = { steps: 0, maxSteps };
  let total = 0;
  let skipped = 0;
  const copy = (f) => {
    const len = f.next - f.keyAt;
    if (len > maxField || total + len > maxTotal) {
      skipped++;
      return null;
    }
    total += len;
    return readAt(fd, f.keyAt, len);
  };
  const tensor = (f) => {
    const parts = [];
    for (const t of pbFields(byte, f.dataAt, f.next, budget)) {
      if (TENSOR_PAYLOAD.has(t.field)) continue;
      const kept = copy(t);
      if (kept) parts.push(kept);
    }
    return lengthField(f.field, Buffer.concat(parts));
  };
  const graph = (f) => {
    const parts = [];
    for (const g of pbFields(byte, f.dataAt, f.next, budget)) {
      if (g.wire === 2 && g.field === GRAPH_INITIALIZER) parts.push(tensor(g));
      else if (g.wire === 2 && g.field === GRAPH_SPARSE_INITIALIZER) continue;
      else {
        const kept = copy(g);
        if (kept) parts.push(kept);
      }
    }
    return lengthField(f.field, Buffer.concat(parts));
  };
  const parts = [];
  for (const f of pbFields(byte, 0, size, budget)) {
    if (f.wire === 2 && f.field === ONNX_GRAPH) parts.push(graph(f));
    else {
      const kept = copy(f);
      if (kept) parts.push(kept);
    }
  }
  return { buf: Buffer.concat(parts), skipped };
}
