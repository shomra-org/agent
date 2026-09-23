// GENERATED MIRROR of Dragox.Backend model-formats/readers/zip-walk.ts (types stripped, imports swapped).
// Do not hand-edit - change the backend file and run scripts/mirror-model-config.mjs,
// so `shomra model-scan <path>` and the platform read a weight file identically.
import { inflateRawSync } from 'node:zlib';

const SIG_LOCAL = 0x04034b50;
const SIG_CENTRAL = 0x02014b50;
const SIG_EOCD = 0x06054b50;

const ZIP64_SENTINEL = 0xffffffff;

                                 
                 

                      

                         

                       

                    
 

                           
               
                
                    
                      
 

const DEFAULTS = {
  maxEntries: 8192,
  maxCompressed: 32 * 1024 * 1024,
  maxInflated: 64 * 1024 * 1024,
  maxTotal: 192 * 1024 * 1024,
};

const MAX_ENTRY_NAME = 4096;
const EMPTY = Buffer.alloc(0);

export function isZip(buf        )          {
  return buf.length >= 4 && buf.readUInt32LE(0) === SIG_LOCAL;
}

                  
               
                  
                     
                        
                      
                   
 

function makeBudget(opts                )         {
  return {
    seen: 0,
    decoded: 0,
    maxEntries: opts.maxEntries ?? DEFAULTS.maxEntries,
    maxCompressed: opts.maxCompressed ?? DEFAULTS.maxCompressed,
    maxInflated: opts.maxInflated ?? DEFAULTS.maxInflated,
    maxTotal: opts.maxTotal ?? DEFAULTS.maxTotal,
  };
}

function materialize(
  name        ,
  raw        ,
  method        ,
  opts                ,
  b        ,
)                  {
  if (name.length > MAX_ENTRY_NAME) return null;
  if (opts.match && !opts.match.test(name)) return null;
  if (raw.length > b.maxCompressed) return null;
  if (method === 0) {
    b.decoded += raw.length;
    return { name, bytes: raw, inflated: false, unreadable: false };
  }
  if (method === 8) {
    try {
      const out = inflateRawSync(raw, { maxOutputLength: b.maxInflated });
      b.decoded += out.length;
      return { name, bytes: out, inflated: true, unreadable: false };
    } catch {
      return { name, bytes: EMPTY, inflated: false, unreadable: true };
    }
  }
  return null;
}

                         
               
                 
                   
                      
 

function findEocdOffset(buf        )                                                             {
  if (buf.length < 22) return null;
  const start = Math.max(0, buf.length - (22 + 0xffff));
  for (let i = buf.length - 22; i >= start; i--) {
    if (buf.readUInt32LE(i) !== SIG_EOCD) continue;
    const count = buf.readUInt16LE(i + 10);
    const cdSize = buf.readUInt32LE(i + 12);
    const cdOffset = buf.readUInt32LE(i + 16);
    if (cdOffset === ZIP64_SENTINEL || cdSize === ZIP64_SENTINEL) return null;
    if (cdOffset + cdSize <= buf.length) return { cdOffset, cdSize, count };
  }
  return null;
}

function* centralRecords(buf        , cd                                      , max        )                           {
  const end = Math.min(buf.length, cd.cdOffset + cd.cdSize);
  let p = cd.cdOffset;
  let n = 0;
  while (p + 46 <= end && n < max) {
    if (buf.readUInt32LE(p) !== SIG_CENTRAL) break;
    const method = buf.readUInt16LE(p + 10);
    const compSize = buf.readUInt32LE(p + 20);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const localOffset = buf.readUInt32LE(p + 42);
    const name = buf.toString('utf8', p + 46, p + 46 + nameLen);
    yield { name, method, compSize, localOffset };
    p += 46 + nameLen + extraLen + commentLen;
    n++;
  }
}

function readAtLocalOffset(buf        , rec               , opts                , b        )                  {
  const o = rec.localOffset;
  if (o < 0 || o + 30 > buf.length) return null;
  if (buf.readUInt32LE(o) !== SIG_LOCAL) return null;

  const localNameLen = buf.readUInt16LE(o + 26);
  const localExtraLen = buf.readUInt16LE(o + 28);
  const dataStart = o + 30 + localNameLen + localExtraLen;

  if (rec.compSize === ZIP64_SENTINEL) return null;
  const dataEnd = dataStart + rec.compSize;
  if (dataEnd > buf.length || dataEnd < dataStart) return null;

  return materialize(rec.name, buf.subarray(dataStart, dataEnd), rec.method, opts, b);
}

/**
 * ⚠ THE CENTRAL DIRECTORY IS WHAT THE LOADER READS, so it is what this reads.
 * torch.load / numpy / keras all open the zip through Python's `zipfile`, which
 * indexes the archive from the END-OF-CENTRAL-DIRECTORY record and trusts the
 * SIZES IN THE CENTRAL DIRECTORY - never the ones in the local file header. A
 * reader that walks local headers sequentially and trusts THEIR sizes can be
 * shown a different archive than the loader sees: set the data-descriptor flag
 * (bit 3), zero the local-header sizes, and the sequential reader reads zero
 * bytes (stored) or halts entirely (deflate) while the loader reads the real
 * payload straight out of the central directory. That is the picklescan
 * CVE-2025-1945 family, and the whole class is "the scanner's zip reader is
 * stricter than the loader's".
 *
 * So the primary pass is the central directory, and the sequential local-header
 * walk is kept as a SUPPLEMENT, deduped by offset: an entry present in one and
 * not the other is scanned rather than dropped, because a discrepancy between
 * the two readers is exactly the evasion. Scanning the union can only
 * over-report on a malformed archive, which is the safe direction for a
 * detector; letting a discrepancy hide an entry is the unsafe one.
 *
 * ⚠ A bad CRC or a name mismatch between the two headers is NOT handled here and
 * does not need to be: Python REFUSES a name-mismatched entry (`BadZipFile`), so
 * it is not a loadable-but-hidden payload, and this reader never checks CRC in
 * the first place, so a corrupt-CRC entry is read, not skipped.
 *
 * ⚠ ZIP64 is a stated bound: an entry whose size or the directory offset is the
 * 0xFFFFFFFF sentinel is left to the sequential fallback rather than parsed from
 * the zip64 extra field. Real multi-gigabyte models use it; the per-entry byte
 * caps upstream already treat those as partial reads.
 */
export function* walkZipEntries(buf        , opts                 = {})                      {
  const b = makeBudget(opts);
  const seenOffsets = new Set        ();

  const eocd = findEocdOffset(buf);
  if (eocd) {
    for (const rec of centralRecords(buf, eocd, b.maxEntries)) {
      if (b.seen >= b.maxEntries || b.decoded >= b.maxTotal) break;
      b.seen++;
      seenOffsets.add(rec.localOffset);
      const entry = readAtLocalOffset(buf, rec, opts, b);
      if (entry) yield entry;
    }
  }

  yield* sequentialWalk(buf, opts, b, seenOffsets);
}

function* sequentialWalk(buf        , opts                , b        , seenOffsets             )                      {
  let i = 0;

  while (i + 30 <= buf.length && b.seen < b.maxEntries && b.decoded < b.maxTotal) {
    if (buf.readUInt32LE(i) !== SIG_LOCAL) break;
    const offset = i;
    const method = buf.readUInt16LE(i + 8);
    const compSize = buf.readUInt32LE(i + 18);
    const nameLen = buf.readUInt16LE(i + 26);
    const extraLen = buf.readUInt16LE(i + 28);
    const nameStart = i + 30;
    const dataStart = nameStart + nameLen + extraLen;
    if (dataStart > buf.length) break;
    const name = buf.toString('utf8', nameStart, nameStart + nameLen);

    if (compSize === 0 && method !== 0) break;

    const dataEnd = dataStart + compSize;
    if (dataEnd > buf.length) break;

    if (!seenOffsets.has(offset)) {
      b.seen++;
      const entry = materialize(name, buf.subarray(dataStart, dataEnd), method, opts, b);
      if (entry) yield entry;
    }

    i = dataEnd;
  }
}

export function readZipEntries(buf        , opts                                      = {})             {
  const out             = [];
  const limit = opts.limit ?? 64;
  for (const e of walkZipEntries(buf, opts)) {
    out.push(e);
    if (out.length >= limit) break;
  }
  return out;
}
