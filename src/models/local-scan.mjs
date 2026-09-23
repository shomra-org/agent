import fs from 'node:fs';
import path from 'node:path';
import { SKIP_DIRS } from '../artifacts/matchers.mjs';
import { scanGgufModel } from '../detect/model-formats/gguf-scan.mjs';
import { CODE_BEARING_FORMATS, FORMAT_LABEL, detectFormatMismatch, detectWeightFormat, extOf } from '../detect/model-formats/model-format.mjs';
import { isNumpyScannable, scanNumpyModel } from '../detect/model-formats/numpy-scan.mjs';
import { isPickleScannable, scanPickleStream } from '../detect/model-formats/pickle-scan.mjs';
import { scanSafetensors } from '../detect/model-formats/safetensors-scan.mjs';
import { isModelConfigPath, localModelConfig } from '../detect/signals/model-config.mjs';

export const WHOLE_FILE_MAX = 128 * 1024 * 1024;
const HEAD_BYTES = 16 * 1024 * 1024;
const TAIL_BYTES = 1024 * 1024;
const GGUF_HEAD_BYTES = 64 * 1024 * 1024;
const SAFETENSORS_HEADER_MAX = 100 * 1024 * 1024;
const CONFIG_MAX = 2 * 1024 * 1024;
const MAX_FILES = 400;

const NOT_READ_HERE = new Map([
  ['.h5', 'hdf5'], ['.hdf5', 'hdf5'], ['.keras', 'keras'], ['.pb', 'tf-savedmodel'],
  ['.onnx', 'onnx'], ['.ort', 'onnx'], ['.tflite', 'tflite'], ['.mlmodel', 'coreml'], ['.pte', 'executorch'],
]);
const CODE_BEARING_UNREAD = new Set(['hdf5', 'keras', 'tf-savedmodel']);
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

function scanWeight(full, rel, size, formats) {
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

  const { buf, partial } = readBytes(full, size);
  if (partial) coverage = 'partial';
  if (isNumpyScannable(rel) || actual === 'npy') {
    formats.pickleFamily++;
    const res = scanNumpyModel(buf, rel);
    findings.push(...res.findings.map(fromSast));
    if (res.containerBlindSpot) coverage = 'partial';
  } else if (isPickleScannable(rel) || actual === 'pickle' || (mismatch && actual === 'zip')) {
    formats.pickleFamily++;
    const res = scanPickleStream(buf, rel);
    findings.push(...res.findings.map(fromSast));
    if (res.containerBlindSpot) coverage = 'partial';
  } else if (CODE_BEARING_FORMATS.has(actual)) {
    formats.other++;
    coverage = 'unread';
  } else {
    formats.other++;
  }
  if (partial && findings.every((f) => RANK[f.severity] < RANK.HIGH)) findings.push(partialRow(rel, size));
  return { findings, coverage };
}

export function scanLocalModelPath(target, { limit = MAX_FILES } = {}) {
  const abs = path.resolve(String(target));
  const st = fs.statSync(abs);
  const base = st.isDirectory() ? abs : path.dirname(abs);
  const { files, truncated } = st.isDirectory() ? walk(abs, limit) : { files: [abs], truncated: false };
  const findings = [];
  const read = [];
  const partial = [];
  const unread = [];
  const formats = { pickleFamily: 0, safetensors: 0, gguf: 0, config: 0, other: 0 };

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
        unread.push({ file: rel, kind: unreadKind, codeBearing: CODE_BEARING_UNREAD.has(unreadKind) });
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
      if (!['.safetensors', '.gguf'].includes(ext) && !isPickleScannable(rel) && !isNumpyScannable(rel)) {
        if (size < 8) continue;
        const kind = detectWeightFormat(peek(full));
        if (!['pickle', 'gguf', 'npy', 'safetensors'].includes(kind)) continue;
      }
      const res = scanWeight(full, rel, size, formats);
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
