// GENERATED MIRROR of Dragox.Backend model-formats/scanners/numpy-scan.ts (types stripped, imports swapped).
// Do not hand-edit - change the backend file and run scripts/mirror-model-config.mjs,
// so `shomra model-scan <path>` and the platform read a weight file identically.
import { walkZipEntries, isZip } from './zip-walk.mjs';
import { scanPickleStream,                       } from './pickle-scan.mjs';
                                                        

const NPY_MAGIC = Buffer.from([0x93, 0x4e, 0x55, 0x4d, 0x50, 0x59]);

function startsWith(buf        , magic        )          {
  return buf.length >= magic.length && buf.subarray(0, magic.length).equals(magic);
}

                            
                
                    
                       
 

export function parseNpyHeader(buf        )                   {
  if (!startsWith(buf, NPY_MAGIC) || buf.length < 10) return null;
  const major = buf[6];
  let headerLen        ;
  let headerStart        ;
  if (major <= 1) {
    headerLen = buf.readUInt16LE(8);
    headerStart = 10;
  } else {
    if (buf.length < 12) return null;
    headerLen = buf.readUInt32LE(8);
    headerStart = 12;
  }
  const dataStart = headerStart + headerLen;
  if (dataStart > buf.length) return null;
  const header = buf.toString('latin1', headerStart, dataStart);

  const raw = descrExpression(header);
  const plain = /^['"]([^'"]*)['"]$/.exec(raw);
  return { descr: plain ? plain[1] : raw, dataStart, objectDtype: descrHasObjectField(raw) };
}

function descrExpression(header        )         {
  const structured = header.match(/['"]descr['"]\s*:\s*([\s\S]*?),\s*['"]fortran_order['"]/);
  if (structured) return structured[1].trim();
  const simple = header.match(/['"]descr['"]\s*:\s*(['"][^'"]*['"])/);
  return simple ? simple[1] : '';
}

export function isObjectDtype(descr        )          {
  return /(^|[|<>=])O\d*$/.test(descr) || descr === 'O' || descr === '|O';
}

export function descrHasObjectField(raw        )          {
  if (!raw) return false;
  const quoted = raw.match(/['"][^'"]*['"]/g);
  if (!quoted) return false;
  const values = quoted.map((t) => t.slice(1, -1));
  return /^['"][^'"]*['"]$/.test(raw) ? isObjectDtype(values[0]) : values.some(isObjectDtype);
}

function toNumpyFinding(h             , file        , member         )              {
  const where = member ? `${file} (member ${member})` : file;
  return {
    ...h,
    ruleId: h.ruleId.replace(/^pickle\./, 'numpy.'),
    source: 'numpy object array',
    file,
    message:
      `This is a NumPy object-dtype array whose data section is a pickle; ` +
      `\`numpy.load(allow_pickle=True)\` (the default in older NumPy) deserializes and executes it. ` +
      h.message.replace('torch.load / pickle.load / joblib.load', 'numpy.load(allow_pickle=True)') +
      ` Found in ${where}.`,
  };
}

function* npzMembers(buf        )                                                                  {
  yield* walkZipEntries(buf, {
    match: /\.npy$/i,
    maxCompressed: 64 * 1024 * 1024,
    maxInflated: 64 * 1024 * 1024,
    maxTotal: 64 * 1024 * 1024,
  });
}

export function scanNumpyModel(buf        , file        )                   {
  const findings                = [];
  const globals = new Set        ();

  const scanOne = (bytes        , member         ) => {
    const hdr = parseNpyHeader(bytes);
    if (!hdr || !hdr.objectDtype) return;

    const res = scanPickleStream(bytes.subarray(hdr.dataStart), file);
    for (const h of res.findings) findings.push(toNumpyFinding(h, file, member));
    res.globals.forEach((g) => globals.add(g));
  };

  let unreadableMembers = 0;
  if (isZip(buf)) {
    for (const { name, bytes, unreadable } of npzMembers(buf)) {
      if (unreadable) unreadableMembers++;
      else scanOne(bytes, name);
    }
  } else {
    scanOne(buf);
  }

  return { findings, containerBlindSpot: unreadableMembers > 0, containerFormat: null, globals: [...globals] };
}

export const NUMPY_SCAN_EXTS = ['.npy', '.npz'];

export function isNumpyScannable(path        )          {
  const i = path.lastIndexOf('.');
  return i !== -1 && NUMPY_SCAN_EXTS.includes(path.slice(i).toLowerCase());
}
