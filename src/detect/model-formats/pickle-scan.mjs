// GENERATED MIRROR of Dragox.Backend model-formats/scanners/pickle-scan.ts (types stripped, imports swapped).
// Do not hand-edit - change the backend file and run scripts/mirror-model-config.mjs,
// so `shomra model-scan <path>` and the platform read a weight file identically.
import { walkZipEntries } from './zip-walk.mjs';
                                                                            
                                                                      

const UNSAFE_MODULE_WILDCARD = new Set([
  'os', 'nt', 'posix', 'subprocess', 'sys', 'socket', 'ssl', 'shutil', 'runpy',
  'pty', 'commands', 'pickle', '_pickle', 'bdb', 'pdb', 'asyncio', 'ctypes',
  '_ctypes', 'aiohttp', 'httplib', 'requests', 'urllib', 'urllib2', 'webbrowser',
  'pip', 'venv', 'ensurepip', 'timeit', 'cProfile', 'profile', 'pydoc',
  'multiprocessing', 'code', 'codeop', 'dill', 'cloudpickle', 'marshal',
  'smtplib', 'ftplib', 'imaplib', 'pexpect', 'torch.hub', 'numpy.f2py',
  'distutils',
  'imp', 'zipimport', 'py_compile', 'compileall', 'pkg_resources',
  'telnetlib', 'poplib', 'nntplib', 'xmlrpc', 'http.client', 'urllib3',
  'torch.multiprocessing', 'torch.utils.cpp_extension', 'torch.distributed.run',
  'paddle.jit', 'paddle.static',
]);

const UNSAFE_QUALIFIED = new Map                     ([
  ['builtins', new Set(['eval', 'exec', 'compile', 'getattr', 'setattr', 'apply', 'open', 'breakpoint', '__import__'])],
  ['__builtin__', new Set(['eval', 'exec', 'compile', 'getattr', 'setattr', 'apply', 'open', 'breakpoint', '__import__'])],
  ['operator', new Set(['attrgetter', 'itemgetter', 'methodcaller'])],
  ['_operator', new Set(['attrgetter', 'itemgetter', 'methodcaller'])],
  ['types', new Set(['CodeType', 'FunctionType'])],
  ['importlib', new Set(['import_module', '__import__'])],
  ['pkgutil', new Set(['resolve_name'])],
  ['pandas', new Set(['read_pickle', 'eval'])],
  ['joblib', new Set(['load'])],
  ['torch.serialization', new Set(['load'])],
  ['torch._inductor.codecache', new Set(['compile_file'])],
  ['torch.jit.unsupported_tensor_ops', new Set(['execWrapper'])],
  ['torch', new Set(['load', 'compile'])],
  ['numpy.testing._private.utils', new Set(['runstring'])],
  ['numpy.lib.npyio', new Set(['load'])],
]);

const EXEC_NAME_RE = /^(system|popen|spawn\w*|exec\w*|run|call|Popen|check_output|check_call|getoutput|getstatusoutput|eval|compile|load|import_module|__import__)$/;

function classifyGlobal(mod        , name        )                                         {
  const qualified = UNSAFE_QUALIFIED.get(mod);
  if (qualified?.has(name)) return { unsafe: true, callable: true };
  for (const w of UNSAFE_MODULE_WILDCARD) {
    if (mod === w || mod.startsWith(w + '.')) {
      return { unsafe: true, callable: EXEC_NAME_RE.test(name) };
    }
  }
  return { unsafe: false, callable: false };
}

const PROTO = 0x80, FRAME = 0x95, STOP = 0x2e;
const GLOBAL = 0x63, INST = 0x69, STACK_GLOBAL = 0x93;
const REDUCE = 0x52, BUILD = 0x62, OBJ = 0x6f;
const NEWOBJ = 0x81, NEWOBJ_EX = 0x92;

const SHORT_BINUNICODE = 0x8c, BINUNICODE = 0x58, BINUNICODE8 = 0x8d;
const SHORT_BINSTRING = 0x55, BINSTRING = 0x54, STRING = 0x53, UNICODE = 0x56;

const PUT = 0x70, BINPUT = 0x71, LONG_BINPUT = 0x72, MEMOIZE = 0x94;
const GET = 0x67, BINGET = 0x68, LONG_BINGET = 0x6a;

const MAX_DECODE = 1024;

const MAX_OPS = 2_000_000;

const MAX_STREAMS = 64;

const MAX_TOTAL_OPS = 6_000_000;

const MAX_ZIP_ENTRIES = 4096;
const MAX_INFLATE_BYTES = 32 * 1024 * 1024;

const OTHER = Symbol('other');
                                  

                  
                                                                      

                     
                    

                                         

                     

                     
 

function readLenPrefixed(buf        , pos        , lenBytes        , encoding                )                                       {
  let len        ;
  if (lenBytes === 1) {
    if (pos >= buf.length) return null;
    len = buf[pos];
  } else if (lenBytes === 4) {
    if (pos + 4 > buf.length) return null;
    len = buf.readUInt32LE(pos);
  } else {
    if (pos + 8 > buf.length) return null;
    const big = buf.readBigUInt64LE(pos);
    if (big > BigInt(buf.length)) return null;
    len = Number(big);
  }
  const dataStart = pos + lenBytes;
  const dataEnd = dataStart + len;
  if (dataEnd > buf.length) return null;
  const value       = len <= MAX_DECODE ? buf.toString(encoding, dataStart, dataEnd) : OTHER;
  return { value, next: dataEnd };
}

function readLine(buf        , pos        , max = 1024)                                        {
  const end = Math.min(buf.length, pos + max);
  let j = pos;
  while (j < end && buf[j] !== 0x0a) j++;
  if (j >= end || buf[j] !== 0x0a) return null;
  return { text: buf.toString('latin1', pos, j), next: j + 1 };
}

function disassemble(buf        , start        , budget                   )         {
  const globals = new Map                                                       ();
  const trace                                  = [];
  const stack         = [];
  const memo = new Map              ();
  let sawReduce = false, sawBuild = false, truncated = false, parsedAny = false;

  const push = (v      ) => { if (stack.length < 1_000_000) stack.push(v); };
  const note = (off        , text        ) => { if (trace.length < 20_000) trace.push({ off, text }); };
  const recordGlobal = (modRaw      , nameRaw      , off        ) => {
    if (typeof modRaw !== 'string' || typeof nameRaw !== 'string') return;
    const mod = modRaw.replace(/\n/g, ''), name = nameRaw.replace(/\n/g, '');
    const dotted = `${mod}.${name}`;
    if (!globals.has(dotted)) globals.set(dotted, { mod, name, offset: off });
    note(off, `GLOBAL     '${mod}' '${name}'`);
  };

  let i = start, ops = 0;
  while (i < buf.length && ops < MAX_OPS && (!budget || budget.left > 0)) {
    const op = buf[i];
    const opOff = i;
    i++;
    ops++;
    if (budget) budget.left--;
    parsedAny = true;

    switch (op) {
      case STOP:
        return { globals, sawReduce, sawBuild, trace, parsedAny, truncated };

      case GLOBAL:
      case INST: {
        const mod = readLine(buf, i);
        if (!mod) { truncated = true; return finish(); }
        const name = readLine(buf, mod.next);
        if (!name) { truncated = true; return finish(); }
        recordGlobal(mod.text, name.text, opOff);
        push(OTHER);
        i = name.next;
        break;
      }
      case STACK_GLOBAL: {
        const name = stack.pop();
        const mod = stack.pop();
        recordGlobal(mod ?? OTHER, name ?? OTHER, opOff);
        push(OTHER);
        break;
      }

      case REDUCE: sawReduce = true; note(opOff, 'REDUCE'); break;
      case BUILD: sawBuild = true; note(opOff, 'BUILD'); break;
      case OBJ:
      case NEWOBJ:
      case NEWOBJ_EX: sawBuild = true; note(opOff, 'NEWOBJ'); break;

      case SHORT_BINUNICODE: { const r = readLenPrefixed(buf, i, 1, 'utf8'); if (!r) { truncated = true; return finish(); } push(r.value); i = r.next; break; }
      case SHORT_BINSTRING: { const r = readLenPrefixed(buf, i, 1, 'latin1'); if (!r) { truncated = true; return finish(); } push(r.value); i = r.next; break; }
      case BINUNICODE: { const r = readLenPrefixed(buf, i, 4, 'utf8'); if (!r) { truncated = true; return finish(); } push(r.value); i = r.next; break; }
      case BINSTRING: { const r = readLenPrefixed(buf, i, 4, 'latin1'); if (!r) { truncated = true; return finish(); } push(r.value); i = r.next; break; }
      case BINUNICODE8: { const r = readLenPrefixed(buf, i, 8, 'utf8'); if (!r) { truncated = true; return finish(); } push(r.value); i = r.next; break; }
      case STRING: case UNICODE: { const r = readLine(buf, i); if (!r) { truncated = true; return finish(); } push(unquote(r.text)); i = r.next; break; }

      case MEMOIZE: memo.set(memo.size, stack[stack.length - 1] ?? OTHER); break;
      case PUT: { const r = readLine(buf, i); if (!r) { truncated = true; return finish(); } memo.set(parseInt(r.text, 10) || 0, stack[stack.length - 1] ?? OTHER); i = r.next; break; }
      case BINPUT: { if (i >= buf.length) { truncated = true; return finish(); } memo.set(buf[i], stack[stack.length - 1] ?? OTHER); i += 1; break; }
      case LONG_BINPUT: { if (i + 4 > buf.length) { truncated = true; return finish(); } memo.set(buf.readUInt32LE(i), stack[stack.length - 1] ?? OTHER); i += 4; break; }
      case GET: { const r = readLine(buf, i); if (!r) { truncated = true; return finish(); } push(memo.get(parseInt(r.text, 10) || 0) ?? OTHER); i = r.next; break; }
      case BINGET: { if (i >= buf.length) { truncated = true; return finish(); } push(memo.get(buf[i]) ?? OTHER); i += 1; break; }
      case LONG_BINGET: { if (i + 4 > buf.length) { truncated = true; return finish(); } push(memo.get(buf.readUInt32LE(i)) ?? OTHER); i += 4; break; }

      default: {
        const adv = operandSize(op, buf, i);
        if (adv === null) { truncated = true; return finish(); }
        if (adv.pushes) push(OTHER);
        i += adv.size;
      }
    }
  }
  truncated = true;
  return finish();

  function finish()         {
    return { globals, sawReduce, sawBuild, trace, parsedAny, truncated };
  }
}

function unquote(s        )         {
  const t = s.trim();
  if (t.length >= 2 && (t[0] === "'" || t[0] === '"') && t[t.length - 1] === t[0]) return t.slice(1, -1);
  return t;
}

function operandSize(op        , buf        , pos        )                                           {
  switch (op) {
    case 0x28: case 0x30: case 0x31: case 0x32:
    case 0x61: case 0x65: case 0x73: case 0x75:
    case 0x51: case 0x97: case 0x98:
      return { size: 0, pushes: false };

    case 0x4e:
    case 0x88: case 0x89:
    case 0x29: case 0x5d: case 0x7d: case 0x8f:
    case 0x6c: case 0x74: case 0x64: case 0x90:
    case 0x85: case 0x86: case 0x87:
      return { size: 0, pushes: true };

    case 0x4b: case 0x82: return { size: 1, pushes: true };

    case 0x4d: case 0x83: return { size: 2, pushes: true };

    case 0x4a: case 0x84: return { size: 4, pushes: true };

    case 0x47: return { size: 8, pushes: true };

    case PROTO: return { size: 1, pushes: false };

    case FRAME: return { size: 8, pushes: false };

    case 0x49: case 0x4c: case 0x46: case 0x50: {
      const r = readLine(buf, pos); return r ? { size: r.next - pos, pushes: true } : null;
    }

    case 0x8a: { if (pos >= buf.length) return null; return { size: 1 + buf[pos], pushes: true }; }
    case 0x8b: { if (pos + 4 > buf.length) return null; return { size: 4 + buf.readUInt32LE(pos), pushes: true }; }

    case 0x43: { if (pos >= buf.length) return null; return { size: 1 + buf[pos], pushes: true }; }
    case 0x42: { if (pos + 4 > buf.length) return null; return { size: 4 + buf.readUInt32LE(pos), pushes: true }; }
    case 0x8e: case 0x96: {
      if (pos + 8 > buf.length) return null;
      const n = buf.readBigUInt64LE(pos);
      if (n > BigInt(buf.length)) return null;
      return { size: 8 + Number(n), pushes: true };
    }
    default:
      return null;
  }
}

                                   
                          

                              

                                 

                    
 

const CONTAINER_MAGICS                                      = [
  { format: 'zip', magic: Buffer.from([0x50, 0x4b, 0x03, 0x04]) },
  { format: '7z', magic: Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]) },
  { format: 'rar', magic: Buffer.from([0x52, 0x61, 0x72, 0x21, 0x1a, 0x07]) },
  { format: 'gzip', magic: Buffer.from([0x1f, 0x8b]) },
  { format: 'bzip2', magic: Buffer.from([0x42, 0x5a, 0x68]) },
  { format: 'xz', magic: Buffer.from([0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]) },
];

function detectContainer(buf        )                {
  for (const { format, magic } of CONTAINER_MAGICS) {
    if (buf.length >= magic.length && buf.subarray(0, magic.length).equals(magic)) return format;
  }
  return null;
}

function findStreamStarts(buf        , hasContainer         )           {
  const starts           = [];
  for (let i = 0; i + 1 < buf.length && starts.length < MAX_STREAMS; i++) {
    if (buf[i] === PROTO && buf[i + 1] >= 2 && buf[i + 1] <= 5) starts.push(i);
  }

  if (starts.length === 0 && !hasContainer) starts.push(0);
  return starts;
}

const ZIP_PICKLE_NAME = /(^|\/)(data|constants|version|attributes)\.pkl$|\.pkl$|\.pickle$/i;

function* zipPickleEntries(buf        )                                                                  {
  yield* walkZipEntries(buf, {
    match: ZIP_PICKLE_NAME,
    maxEntries: MAX_ZIP_ENTRIES,
    maxCompressed: MAX_INFLATE_BYTES,
    maxInflated: MAX_INFLATE_BYTES,
    maxTotal: 64 * 1024 * 1024,
  });
}

export function scanPickleStream(buf        , file        )                   {
  const findings                = [];
  const containerFormat = detectContainer(buf);

  const globalsSeen = new Map                                                       ();
  const trace                                  = [];
  const budget = { left: MAX_TOTAL_OPS };
  let sawReduce = false, sawBuild = false, parsedAny = false;

  const absorb = (d        , offsetBase = 0) => {
    parsedAny = parsedAny || d.parsedAny;
    sawReduce = sawReduce || d.sawReduce;
    sawBuild = sawBuild || d.sawBuild;
    for (const [k, v] of d.globals) {
      if (!globalsSeen.has(k)) globalsSeen.set(k, { ...v, offset: v.offset + offsetBase });
    }
    for (const t of d.trace) if (trace.length < 20_000) trace.push({ off: t.off + offsetBase, text: t.text });
  };

  let unreadableMembers = 0;
  if (containerFormat === 'zip') {
    for (const { bytes, unreadable } of zipPickleEntries(buf)) {
      if (unreadable) {
        unreadableMembers++;
        continue;
      }
      for (const start of findStreamStarts(bytes, false)) {
        absorb(disassemble(bytes, start, budget));
        if (budget.left <= 0) break;
      }
      if (budget.left <= 0) break;
    }
  }

  for (const start of findStreamStarts(buf, !!containerFormat)) {
    if (budget.left <= 0) break;
    absorb(disassemble(buf, start, budget));
  }
  trace.sort((a, b) => a.off - b.off);

  const unsafeGlobals = [...globalsSeen]
    .filter(([, g]) => classifyGlobal(g.mod, g.name).unsafe)
    .map(([dotted]) => dotted)
    .sort();

  for (const [dotted, { mod, name, offset }] of globalsSeen) {
    const { unsafe, callable } = classifyGlobal(mod, name);
    if (!unsafe) continue;

    const severity           = callable || sawReduce || sawBuild ? 'CRITICAL' : 'HIGH';
    findings.push({
      ruleId: 'pickle.dangerous_global',
      title: callable ? 'Pickle imports an OS/exec gadget' : 'Pickle imports a dangerous module',
      severity,
      file,
      line: 1,
      sink: dotted,
      source: 'weight deserialization',
      snippet: buildOpcodeSnippet(dotted, offset, trace, { reduce: sawReduce, build: sawBuild }),
      snippetStartLine: 1,
      disasm: buildDisasm(offset, trace, { reduce: sawReduce, build: sawBuild }, containerFormat, unsafeGlobals),
      message:
        `The pickle stream references \`${dotted}\`` +
        (sawReduce
          ? ' and reaches a REDUCE opcode that invokes a callable on load'
          : sawBuild
            ? ' and reaches a BUILD/NEWOBJ opcode that runs __setstate__ on load'
            : '') +
        '. Deserializing this file (torch.load / pickle.load / joblib.load) executes that code in the host process - the canonical model-hub RCE.',
      remediation:
        'Do not load this file. Obtain a safetensors release of the weights, or convert in a disposable sandbox after confirming with picklescan/fickling. Never torch.load an untrusted checkpoint.',
      cwe: 'CWE-502',
    });
  }

  const containerBlindSpot = (!!containerFormat && !parsedAny) || unreadableMembers > 0;
  return { findings, containerBlindSpot, containerFormat, globals: [...globalsSeen.keys()] };
}

function opcodeWindow(offset        , trace                                 )                                  {
  const from = trace.findIndex((t) => t.off >= offset);
  return (from === -1 ? trace : trace.slice(from)).slice(0, 8);
}

function opcodeNote(text        )                     {
  if (text.startsWith('GLOBAL')) return 'push callable';
  if (text === 'REDUCE') return 'calls it on load - RCE';
  if (text === 'BUILD') return 'runs __setstate__ on load';
  if (text === 'NEWOBJ') return 'constructs instance on load';
  return undefined;
}

function buildOpcodeSnippet(dotted        , offset        , trace                                 , saw                                     )         {
  const { reduce, build } = saw;
  const lines = [`# pickle opcode disassembly (dangerous global at offset ~${offset})`];
  const window = opcodeWindow(offset, trace);
  for (const t of window) {
    let annot = '';
    if (t.text.startsWith('GLOBAL')) annot = `   # push callable`;
    else if (t.text === 'REDUCE') annot = `   # calls it on load  <-- RCE`;
    else if (t.text === 'BUILD') annot = `   # runs __setstate__ on load`;
    else if (t.text === 'NEWOBJ') annot = `   # constructs instance on load`;
    lines.push(`${String(t.off).padStart(8)}  ${t.text}${annot}`);
  }
  if (window.length === 0) {
    lines.push(`GLOBAL     '${dotted.replace('.', "' '")}'`);
    if (build) lines.push('BUILD');
    if (reduce) lines.push('REDUCE                     # <-- RCE');
  }
  return lines.join('\n');
}

function buildDisasm(
  offset        ,
  trace                                 ,
  saw                                     ,
  container               ,
  globals          ,
)               {
  const { reduce, build } = saw;
  return {
    kind: 'pickle',
    globals,
    reduce,
    build,
    container,
    offset,
    ops: opcodeWindow(offset, trace).map((t) => ({ off: t.off, text: t.text, note: opcodeNote(t.text) })),
  };
}

export const PICKLE_SCAN_EXTS = [
  '.bin', '.pt', '.pth', '.pkl', '.pickle', '.ckpt', '.joblib', '.dill',
  '.pdparams', '.pdopt', '.pt2', '.sav', '.model', '.pklz', '.mar', '.nemo',
];

export function isPickleScannable(path        )          {
  const i = path.lastIndexOf('.');
  return i !== -1 && PICKLE_SCAN_EXTS.includes(path.slice(i).toLowerCase());
}
