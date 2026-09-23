import fs from 'node:fs';
import path from 'node:path';
import { SKIP_DIRS } from '../artifacts/matchers.mjs';
import { scanGgufModel } from '../detect/model-formats/gguf-scan.mjs';
import { isKerasScannable, isSavedModelScannable, scanKerasModel, scanSavedModel } from '../detect/model-formats/keras-scan.mjs';
import { CODE_BEARING_FORMATS, FORMAT_LABEL, detectFormatMismatch, detectWeightFormat, extOf } from '../detect/model-formats/model-format.mjs';
import { isNumpyScannable, scanNumpyModel } from '../detect/model-formats/numpy-scan.mjs';
import { isOnnxScannable, scanOnnxModel } from '../detect/model-formats/onnx-scan.mjs';
import { isPickleScannable, scanPickleStream } from '../detect/model-formats/pickle-scan.mjs';
import { scanSafetensors } from '../detect/model-formats/safetensors-scan.mjs';
import { isModelConfigPath, localModelConfig } from '../detect/signals/model-config.mjs';
import { onnxSkeleton, zipSubset } from './sparse-read.mjs';

export const WHOLE_FILE_MAX = 128 * 1024 * 1024;
const HEAD_BYTES = 16 * 1024 * 1024;
const TAIL_BYTES = 1024 * 1024;
const GGUF_HEAD_BYTES = 64 * 1024 * 1024;
const KERAS_HEAD_BYTES = 4 * 1024 * 1024;
const MB = 1024 * 1024;
const SAFETENSORS_HEADER_MAX = 100 * 1024 * 1024;
const CONFIG_MAX = 2 * 1024 * 1024;
const MAX_FILES = 400;

const NOT_READ_HERE = new Map([['.tflite', 'tflite'], ['.mlmodel', 'coreml'], ['.pte', 'executorch']]);
const PICKLE_ENTRY = /\.(?:pkl|pickle)$/i;
const NPY_ENTRY = /\.npy$/i;
const KERAS_ENTRY = /(^|\/)(config|metadata)\.json$/i;
const CONFIG_EXT_RE = /\.(?:json|jsonc|ya?ml|jinja2?|txt|toml|properties|pbtxt|cfg)$|(?:^|\/)(?:modelfile|mlmodel)$/i;
const RANK = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

function walk(root, limit = MAX_FILES) {
  const out = [];
  let truncated = false;
  const stack = [root];
  const seen = new Set();
  while (stack.length) {
    const dir = stack.pop();
    let real;
    try {
      real = fs.realpathSync(dir);
    } catch {
      continue;
    }
    if (seen.has(real)) continue;
    seen.add(real);
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const ent of entries) {
      const full = path.join(dir, ent.name);
      let isDir = ent.isDirectory();
      let isFile = ent.isFile();
      if (ent.isSymbolicLink()) {
        try {
          const st = fs.statSync(full);
          isDir = st.isDirectory();
          isFile = st.isFile();
        } catch {
          continue;
        }
      }
      if (isDir) {
        if (!SKIP_DIRS.has(ent.name)) stack.push(full);
      } else if (isFile) {
        if (out.length >= limit) {
          truncated = true;
          return { files: out, truncated };
        }
        out.push(full);
      }
    }
  }
  return { files: out, truncated };
}

function readWindow(fd, pos, len) {
  const buf = Buffer.alloc(len);
  const n = fs.readSync(fd, buf, 0, len, pos);
  return buf.subarray(0, n);
}

function readBytes(full, size, { head = HEAD_BYTES, tail = TAIL_BYTES, whole = WHOLE_FILE_MAX } = {}) {
  const fd = fs.openSync(full, 'r');
  try {
    if (size <= whole) return { buf: readWindow(fd, 0, size), partial: false };
    const headBuf = readWindow(fd, 0, head);
    if (!tail) return { buf: headBuf, partial: true };
    return { buf: Buffer.concat([headBuf, readWindow(fd, Math.max(head, size - tail), tail)]), partial: true };
  } finally {
    fs.closeSync(fd);
  }
}

function readSafetensorsHeader(full, size) {
  const fd = fs.openSync(full, 'r');
  try {
    const prefix = readWindow(fd, 0, 8);
    if (prefix.length < 8) return prefix;
    const len = Number(prefix.readBigUInt64LE(0));
    const want = Math.min(size, 8 + Math.min(Math.max(len, 0), SAFETENSORS_HEADER_MAX));
    return readWindow(fd, 0, want);
  } finally {
    fs.closeSync(fd);
  }
}

function fromSast(h) {
  return {
    severity: h.severity,
    title: h.title,
    file: h.file,
    detail: h.message,
    remediation: h.remediation,
    ...(h.sink ? { sink: h.sink } : {}),
    ...(h.snippet ? { snippet: h.snippet } : {}),
  };
}

function partlyRead(rel, detail, remediation) {
  return { severity: 'LOW', title: `Partly read: ${rel}`, file: rel, detail, remediation };
}

function readHead(full, size, bytes) {
  const fd = fs.openSync(full, 'r');
  try {
    return readWindow(fd, 0, Math.min(size, bytes));
  } finally {
    fs.closeSync(fd);
  }
}

function sparseZip(full, size, match) {
  const fd = fs.openSync(full, 'r');
  try {
    const sub = zipSubset(fd, size, match);
    return sub ? { buf: sub.buf, partial: sub.skipped > 0, sparse: true } : null;
  } catch {
    return null;
  } finally {
    fs.closeSync(fd);
  }
}

function readZipped(full, size, match, wholeMax, scan, blind) {
  const read = (size > wholeMax && sparseZip(full, size, match)) || readBytes(full, size, { whole: wholeMax });
  const res = scan(read.buf);
  if (read.sparse || !blind(res)) return { read, res };
  const sub = sparseZip(full, size, match);
  if (!sub) return { read, res };
  const again = scan(sub.buf);
  return blind(again) ? { read, res } : { read: sub, res: again };
}

function readOnnx(full, size, wholeMax) {
  if (size <= wholeMax) return { buf: readBytes(full, size, { whole: wholeMax }).buf, note: null };
  const fd = fs.openSync(full, 'r');
  try {
    const sk = onnxSkeleton(fd, size);
    return { buf: sk.buf, note: sk.skipped ? `${sk.skipped} part(s) of its graph were too large to read, so what they hold was not checked.` : null };
  } catch {
    return { buf: readWindow(fd, 0, HEAD_BYTES), note: `It is not a graph this scan could walk, so only its first ${HEAD_BYTES / MB} MB were read.` };
  } finally {
    fs.closeSync(fd);
  }
}

function partialRow(rel, size) {
  return {
    severity: 'LOW',
    title: `Partly read: ${rel}`,
    file: rel,
    detail: `${rel} is ${Math.round(size / (1024 * 1024))} MB; its first ${HEAD_BYTES / (1024 * 1024)} MB and last ${TAIL_BYTES / (1024 * 1024)} MB were read. A PyTorch checkpoint keeps its pickle at the front, so this covers the usual payload - but not all of the file.`,
    remediation: 'Prefer a safetensors release of these weights, or run picklescan/fickling over the whole file before loading it.',
  };
}

function peek(full, n = 16) {
  const fd = fs.openSync(full, 'r');
  try {
    return readWindow(fd, 0, n);
  } finally {
    fs.closeSync(fd);
  }
}

function mismatchRow(rel, mismatch) {
  return {
    severity: 'HIGH',
    title: `${rel} is not the format its extension claims`,
    file: rel,
    detail: `Named as ${FORMAT_LABEL[mismatch.declared]}, but its bytes are ${FORMAT_LABEL[mismatch.actual]}. Loaders and reviewers route on the extension, so this is the file that skips the pickle check.`,
    remediation: 'Do not load it. Get the model from its original publisher and check the format before loading.',
  };
}

function scanKeras(full, rel, size, actual, formats, wholeMax) {
  formats.keras++;
  const zip = actual === 'zip';
  const { read, res } = zip
    ? readZipped(full, size, KERAS_ENTRY, wholeMax, (buf) => scanKerasModel(buf, rel), (r) => r.blindSpot)
    : { read: { partial: false }, res: scanKerasModel(readHead(full, size, KERAS_HEAD_BYTES), rel) };
  const findings = res.findings.map(fromSast);
  const coverage = read.partial || res.blindSpot ? 'partial' : 'read';
  if (coverage === 'partial' && findings.every((f) => RANK[f.severity] < RANK.HIGH)) {
    findings.push(partlyRead(
      rel,
      zip ? `The model config inside ${rel} could not be read in full, so a Lambda layer or module reference in it was not checked.` : `${rel} names a Keras model but its config was not in the first ${KERAS_HEAD_BYTES / MB} MB this scan reads, so a Lambda layer in it was not checked.`,
      'Load it with safe_mode=True, or scan it on the platform before trusting it.',
    ));
  }
  return { findings, coverage };
}

function scanOnnx(full, rel, size, formats, wholeMax) {
  formats.onnx++;
  const read = readOnnx(full, size, wholeMax);
  const res = scanOnnxModel(read.buf, rel);
  const findings = res.findings.map(fromSast);
  const coverage = read.note || res.truncated || res.blindSpot ? 'partial' : 'read';
  if (coverage === 'partial' && findings.every((f) => RANK[f.severity] < RANK.HIGH)) {
    findings.push(partlyRead(
      rel,
      read.note ?? `${rel} could not be read as an ONNX graph, so its operators and external-data paths were not checked.`,
      'Inspect it with onnx.checker and load it with load_external_data=False before trusting it.',
    ));
  }
  return { findings, coverage };
}

function scanTfGraph(full, rel, size, formats, wholeMax) {
  formats.tensorflow++;
  const whole = size <= wholeMax;
  const buf = whole ? readBytes(full, size, { whole: wholeMax }).buf : readHead(full, size, HEAD_BYTES);
  const res = scanSavedModel(buf, rel);
  const findings = res.findings.map(fromSast);
  const coverage = !whole || res.blindSpot ? 'partial' : 'read';
  if (coverage === 'partial' && findings.every((f) => RANK[f.severity] < RANK.HIGH)) {
    findings.push(partlyRead(
      rel,
      whole ? `${rel} could not be read as a TensorFlow graph, so its ops were not checked.` : `${rel} is ${Math.round(size / MB)} MB and only its first ${HEAD_BYTES / MB} MB were read, so an op past that point was not checked.`,
      'Load an untrusted SavedModel only in a sandbox, or scan it on the platform.',
    ));
  }
  return { findings, coverage };
}

function scanWeight(full, rel, size, formats, wholeMax = WHOLE_FILE_MAX) {
  const findings = [];
  let coverage = 'read';
  const head = peek(full);
  const actual = detectWeightFormat(head);
  const mismatch = detectFormatMismatch(rel, head);
  if (mismatch) findings.push(mismatchRow(rel, mismatch));

  if (actual === 'safetensors') {
    const res = scanSafetensors(readSafetensorsHeader(full, size), rel, size);
    findings.push(...res.findings.map(fromSast));
    if (res.blindSpot) coverage = 'partial';
    formats.safetensors++;
    return { findings, coverage };
  }

  if (actual === 'gguf') {
    formats.gguf++;
    const { buf } = readBytes(full, size, { head: GGUF_HEAD_BYTES, tail: 0, whole: GGUF_HEAD_BYTES });
    const res = scanGgufModel(buf, rel);
    findings.push(...res.findings.map(fromSast));
    if (!res.metadata || res.metadata.truncated) {
      coverage = 'partial';
      findings.push({
        severity: 'LOW',
        title: `GGUF metadata only partly read: ${rel}`,
        file: rel,
        detail: `The metadata of ${rel} did not fit in the ${GGUF_HEAD_BYTES / (1024 * 1024)} MB this scan reads, so a chat template after that point was not checked.`,
        remediation: 'Inspect the chat template with gguf-dump before loading the model in llama.cpp, LM Studio or Ollama.',
      });
    }
    return { findings, coverage };
  }

  const keras = actual === 'hdf5' || (isKerasScannable(rel) && actual !== 'pickle' && actual !== 'npy');
  if (keras) {
    const res = scanKeras(full, rel, size, actual, formats, wholeMax);
    return { findings: [...findings, ...res.findings], coverage: res.coverage };
  }
  if (actual === 'unknown' && isOnnxScannable(rel)) {
    const res = scanOnnx(full, rel, size, formats, wholeMax);
    return { findings: [...findings, ...res.findings], coverage: res.coverage };
  }
  if (actual === 'unknown' && isSavedModelScannable(rel)) {
    const res = scanTfGraph(full, rel, size, formats, wholeMax);
    return { findings: [...findings, ...res.findings], coverage: res.coverage };
  }

  const numpy = isNumpyScannable(rel) || actual === 'npy';
  const pickle = !numpy && (isPickleScannable(rel) || actual === 'pickle' || (mismatch && actual === 'zip'));
  let partial = false;
  let sparse = false;
  if (numpy || pickle) {
    formats.pickleFamily++;
    const scan = (buf) => (numpy ? scanNumpyModel(buf, rel) : scanPickleStream(buf, rel));
    let read;
    let res;
    if (actual === 'zip') ({ read, res } = readZipped(full, size, numpy ? NPY_ENTRY : PICKLE_ENTRY, wholeMax, scan, (r) => r.containerBlindSpot));
    else {
      read = readBytes(full, size, { whole: wholeMax });
      res = scan(read.buf);
    }
    partial = !!read.partial;
    sparse = !!read.sparse;
    findings.push(...res.findings.map(fromSast));
    if (partial || res.containerBlindSpot) coverage = 'partial';
  } else if (CODE_BEARING_FORMATS.has(actual)) {
    formats.other++;
    coverage = 'unread';
  } else {
    formats.other++;
  }
  if (partial && findings.every((f) => RANK[f.severity] < RANK.HIGH)) {
    findings.push(sparse
      ? partlyRead(rel, `Some entries inside ${rel} were too large to read, so what they hold was not checked.`, 'Prefer a safetensors release of these weights, or run picklescan/fickling over the whole file before loading it.')
      : partialRow(rel, size));
  }
  return { findings, coverage };
}

export function scanLocalModelPath(target, { limit = MAX_FILES, wholeFileMax = WHOLE_FILE_MAX } = {}) {
  const abs = path.resolve(String(target));
  const st = fs.statSync(abs);
  const base = st.isDirectory() ? abs : path.dirname(abs);
  const { files, truncated } = st.isDirectory() ? walk(abs, limit) : { files: [abs], truncated: false };
  const findings = [];
  const read = [];
  const partial = [];
  const unread = [];
  const formats = { pickleFamily: 0, safetensors: 0, gguf: 0, keras: 0, onnx: 0, tensorflow: 0, config: 0, other: 0 };

  for (const full of files) {
    const rel = path.relative(base, full).split(path.sep).join('/') || path.basename(full);
    let size;
    try {
      size = fs.statSync(full).size;
    } catch {
      continue;
    }
    const ext = extOf(rel);
    const unreadKind = NOT_READ_HERE.get(ext);
    try {
      if (unreadKind) {
        unread.push({ file: rel, kind: unreadKind, codeBearing: false });
        continue;
      }
      if (CONFIG_EXT_RE.test(rel) && size <= CONFIG_MAX) {
        const content = fs.readFileSync(full, 'utf8');
        if (!isModelConfigPath(rel, content)) continue;
        formats.config++;
        read.push(rel);
        for (const f of localModelConfig(content, { path: rel })) {
          findings.push({ severity: f.severity, title: f.title, file: rel, remediation: f.remediationText, ...(f.line ? { line: f.line } : {}) });
        }
        continue;
      }
      if (!['.safetensors', '.gguf'].includes(ext) && !isPickleScannable(rel) && !isNumpyScannable(rel) && !isKerasScannable(rel) && !isOnnxScannable(rel) && !isSavedModelScannable(rel)) {
        if (size < 8) continue;
        const kind = detectWeightFormat(peek(full));
        if (!['pickle', 'gguf', 'npy', 'safetensors', 'hdf5'].includes(kind)) continue;
      }
      const res = scanWeight(full, rel, size, formats, wholeFileMax);
      findings.push(...res.findings);
      if (res.coverage === 'unread') unread.push({ file: rel, kind: 'binary', codeBearing: true });
      else if (res.coverage === 'partial') partial.push(rel);
      else read.push(rel);
    } catch (error) {
      unread.push({ file: rel, kind: 'unreadable', codeBearing: true, reason: error.code || error.message });
    }
  }

  for (const u of unread) {
    findings.push({
      severity: u.codeBearing ? 'MEDIUM' : 'LOW',
      title: `Not read on this machine: ${u.file}`,
      file: u.file,
      detail: u.kind === 'unreadable'
        ? `${u.file} could not be opened (${u.reason}). Nothing observed what it contains, so it is unproven, not clean.`
        : `${u.file} is a ${u.kind} model file this on-machine scan does not decode.${u.codeBearing ? ' That format can run code when it is loaded, so the file is unproven, not clean.' : ''}`,
      remediation: u.codeBearing ? 'Load it in a sandbox (Keras: safe_mode=True), or scan it on the platform before trusting it.' : 'Scan it on the platform for a full read.',
    });
  }

  const worst = findings.reduce((m, f) => Math.max(m, RANK[f.severity] ?? 0), 0);
  const floor = truncated || partial.length > 0 || unread.some((u) => u.codeBearing);
  const graded = worst >= RANK.CRITICAL ? 'FAIL' : worst >= RANK.HIGH ? 'REVIEW' : 'PASS';
  return {
    target: abs,
    verdict: graded === 'PASS' && floor ? 'REVIEW' : graded,
    coverage: floor ? 'floor' : 'complete',
    files: { considered: files.length, read: read.length, partial: partial.length, unread: unread.length, truncated },
    formats,
    findings: findings.sort((a, b) => (RANK[b.severity] ?? 0) - (RANK[a.severity] ?? 0)),
  };
}
