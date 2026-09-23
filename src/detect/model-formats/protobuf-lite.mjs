// GENERATED MIRROR of Dragox.Backend model-formats/readers/protobuf-lite.ts (types stripped, imports swapped).
// Do not hand-edit - change the backend file and run scripts/mirror-model-config.mjs,
// so `shomra model-scan <path>` and the platform read a weight file identically.
                          
                

               

                

                 
 

const MAX_FIELDS = 20_000;
const MAX_DEPTH = 8;

function readVarint(buf        , pos        )                                         {
  let result = 0;
  let shift = 0;
  let i = pos;
  while (i < buf.length) {
    const b = buf[i++];

    if (shift > 45) return null;
    result += (b & 0x7f) * Math.pow(2, shift);
    if ((b & 0x80) === 0) return { value: result, next: i };
    shift += 7;
  }
  return null;
}

                         
                    

                 

                     
 

export function pbWalk(buf        )         {
  const fields            = [];
  let i = 0;
  let clean = true;
  let truncated = false;

  while (i < buf.length && fields.length < MAX_FIELDS) {
    const tag = readVarint(buf, i);
    if (!tag) {
      clean = false;
      break;
    }
    const field = Math.floor(tag.value / 8);
    const wire = tag.value & 7;
    if (field === 0) {
      clean = false;
      break;
    }
    i = tag.next;

    if (wire === 0) {
      const v = readVarint(buf, i);
      if (!v) { clean = false; break; }
      fields.push({ field, wire, bytes: Buffer.alloc(0), varint: v.value });
      i = v.next;
    } else if (wire === 1 || wire === 5) {
      const width = wire === 1 ? 8 : 4;
      if (i + width > buf.length) { clean = false; truncated = true; break; }
      fields.push({ field, wire, bytes: buf.subarray(i, i + width), varint: 0 });
      i += width;
    } else if (wire === 2) {
      const len = readVarint(buf, i);
      if (!len) { clean = false; break; }
      const start = len.next;
      const end = start + len.value;
      if (end > buf.length) {
        fields.push({ field, wire, bytes: buf.subarray(start), varint: 0 });
        truncated = true;
        clean = false;
        break;
      }
      fields.push({ field, wire, bytes: buf.subarray(start, end), varint: 0 });
      i = end;
    } else {
      clean = false;
      break;
    }
  }

  return { fields, clean, truncated };
}

export function looksLikeProtobuf(buf        , minFields = 2)          {
  if (buf.length < 4) return false;
  const w = pbWalk(buf);
  if (w.fields.length < minFields) return false;
  return w.clean || w.truncated;
}

export function pbGet(walk        , field        )           {
  return walk.fields.filter((f) => f.field === field && f.wire === 2).map((f) => f.bytes);
}

export function pbString(walk        , field        )                {
  const b = pbGet(walk, field)[0];
  return b ? b.toString('utf8') : null;
}

export function pbCollectStrings(
  buf        ,
  opts                                                                                             ,
)                                    {
  const out                                    = [];
  const max = opts.max ?? 500;
  const depth = opts.depth ?? 0;
  if (depth > MAX_DEPTH) return out;

  const walk = pbWalk(buf);
  for (const f of walk.fields) {
    if (out.length >= max) break;
    if (f.wire !== 2) continue;
    const path = opts.path ? `${opts.path}.${f.field}` : `${f.field}`;
    if (opts.collect.has(f.field)) {
      const text = f.bytes.toString('utf8');
      if (text && !/[\x00-\x08\x0b\x0c\x0e-\x1f]/.test(text)) out.push({ path, value: text });
    }
    if (opts.descend.has(f.field)) {
      out.push(
        ...pbCollectStrings(f.bytes, {
          descend: opts.descend,
          collect: opts.collect,
          max: max - out.length,
          depth: depth + 1,
          path,
        }),
      );
    }
  }
  return out;
}
