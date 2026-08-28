import fs from 'node:fs';
import path from 'node:path';
import { MAX_ARTIFACT_BYTES, SKIP_DIRS } from '../artifacts/matchers.mjs';
import { INVISIBLE_CHARS_RE, downrankCodeContext, localScan } from '../detect/guard-signals.mjs';

export const CORPUS_TEXT_RE = /\.(md|markdown|txt|rst|adoc|html?|json|jsonl|ya?ml|csv|tsv|tex)$/i;
export const CORPUS_OPAQUE_RE = /\.(pdf|docx?|pptx?|xlsx?|epub|rtf|odt|pages|key|numbers)$/i;
export const CORPUS_DEFAULT_CHUNK = 1200;

const CORPUS_MAX_FILES = 5000;
const MAX_FINDINGS_PER_DOC = 6;
const OPAQUE_REASON = 'binary format - no text extractor';
const SCAN_CATEGORIES = ['injection', 'secret', 'pii'];

export function chunkIndexForLine(text, line, chunkSize) {
  if (!line || line < 1) return null;
  const lines = text.split(/\r?\n/);
  let offset = 0;
  for (let index = 0; index < Math.min(line - 1, lines.length); index += 1) offset += lines[index].length + 1;
  return Math.floor(offset / chunkSize);
}

export function walkCorpus(root) {
  const files = [];
  const opaque = [];
  const stack = [root];

  while (stack.length && files.length + opaque.length < CORPUS_MAX_FILES) {
    const dir = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) stack.push(full);
        continue;
      }
      const rel = path.relative(root, full).split(path.sep).join('/');
      if (CORPUS_TEXT_RE.test(entry.name)) files.push({ full, rel });
      else if (CORPUS_OPAQUE_RE.test(entry.name)) opaque.push({ full, rel, reason: OPAQUE_REASON });
    }
  }
  return { files, opaque };
}

export function collectCorpusFiles(absolutePath, isDirectory) {
  if (isDirectory) return walkCorpus(absolutePath);
  return {
    files: CORPUS_TEXT_RE.test(absolutePath) ? [{ full: absolutePath, rel: path.basename(absolutePath) }] : [],
    opaque: CORPUS_OPAQUE_RE.test(absolutePath)
      ? [{ full: absolutePath, rel: path.basename(absolutePath), reason: OPAQUE_REASON }]
      : [],
  };
}

function readDocument(file) {
  try {
    const { size } = fs.statSync(file.full);
    if (size > MAX_ARTIFACT_BYTES) return { reason: `too large (${Math.round(size / 1e6)}MB)` };
    const text = fs.readFileSync(file.full, 'utf8');
    if (text.includes('\0')) return { reason: 'not UTF-8 text' };
    return { text };
  } catch (error) {
    return { reason: error.message };
  }
}

function documentVerdict(scanFindings, rankedFindings, hasInvisibleChars) {
  const liveInjection = scanFindings.some((f) => f.category === 'injection' && !f.codeContext);
  const liveCritical = scanFindings.some((f) => f.severity === 'CRITICAL' && !f.codeContext);
  if (liveInjection || liveCritical || hasInvisibleChars) return 'BLOCK';
  return rankedFindings.length ? 'FLAG' : 'ALLOW';
}

function findingRows(findings, text, chunkSize) {
  return findings.slice(0, MAX_FINDINGS_PER_DOC).map((finding) => ({
    severity: finding.severity,
    category: finding.category,
    label: finding.label,
    line: finding.line ?? null,
    chunk: chunkIndexForLine(text, finding.line, chunkSize),
    codeContext: !!finding.codeContext,
    concealed: !!finding.concealed,
  }));
}

export function screenCorpus(files, opaque, chunkSize) {
  const results = [];
  const unreadable = [...opaque];

  for (const file of files) {
    const read = readDocument(file);
    if (!read.text) {
      unreadable.push({ ...file, reason: read.reason });
      continue;
    }

    const scan = localScan(read.text, { categories: SCAN_CATEGORIES });
    const ranked = downrankCodeContext(scan.findings || []);
    const hasInvisibleChars = INVISIBLE_CHARS_RE.test(read.text);
    const verdict = documentVerdict(scan.findings, ranked, hasInvisibleChars);

    if (verdict === 'ALLOW') {
      results.push({ path: file.rel, verdict, findings: [] });
      continue;
    }

    const rows = findingRows(ranked, read.text, chunkSize);
    if (hasInvisibleChars) {
      rows.unshift({
        severity: 'CRITICAL',
        category: 'injection',
        label: 'Invisible / bidirectional characters',
        line: null,
        chunk: null,
        codeContext: false,
      });
    }
    results.push({ path: file.rel, verdict, findings: rows });
  }

  return { results, unreadable };
}
