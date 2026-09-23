import fs from 'node:fs';
import { INDEX_FILE, readJson, writeJson } from './config.mjs';
import { ATTACK_EXEMPLARS, BENIGN_EXEMPLARS, CALIBRATION_ATTACKS, CALIBRATION_BENIGN, EXEMPLAR_VERSION, PROBE_TEXT } from './exemplars.mjs';
import { embed } from './runtime.mjs';

export const INDEX_VERSION = 1;
export const PROBE_MIN = 0.995;
export const MIN_RECALL = 0.5;
const BUFFER = 0.01;
const BATCH = 16;

export function normalize(v) {
  let s = 0;
  for (const x of v) s += x * x;
  const n = Math.sqrt(s) || 1;
  return Float32Array.from(v, (x) => x / n);
}

export function dot(a, b) {
  let s = 0;
  for (let i = 0; i < a.length; i++) s += a[i] * b[i];
  return s;
}

export function encodeVectors(rows) {
  const dims = rows[0]?.length ?? 0;
  const buf = new Float32Array(rows.length * dims);
  rows.forEach((r, i) => buf.set(r, i * dims));
  return Buffer.from(buf.buffer).toString('base64');
}

export function decodeVectors(b64, dims) {
  const bytes = Buffer.from(String(b64 ?? ''), 'base64');
  if (!dims || bytes.length % (dims * 4) !== 0) return null;
  const ab = new ArrayBuffer(bytes.length);
  new Uint8Array(ab).set(bytes);
  const all = new Float32Array(ab);
  const rows = [];
  for (let i = 0; i < all.length; i += dims) rows.push(all.subarray(i, i + dims));
  return rows;
}

export function scoreVector(index, v) {
  let att = -1;
  let nearest = -1;
  let ben = -1;
  index.attack.forEach((a, i) => {
    const s = dot(a, v);
    if (s > att) {
      att = s;
      nearest = i;
    }
  });
  for (const b of index.benign) ben = Math.max(ben, dot(b, v));
  return { att, ben, margin: att - ben, nearest };
}

export function fires(score, cal) {
  return !!cal && score.att >= cal.threshold && score.margin >= cal.margin;
}

const round = (n) => Math.round(n * 10_000) / 10_000;
const floor4 = (n) => Math.floor(n * 10_000) / 10_000;

export function calibrate(index, attackVectors, benignVectors) {
  const a = attackVectors.map((v) => scoreVector(index, v));
  const b = benignVectors.map((v) => scoreVector(index, v));
  const atts = [...new Set(a.map((s) => floor4(s.att)))];
  const margins = [...new Set(a.map((s) => floor4(s.margin)))];
  let best = null;
  for (const threshold of atts) {
    for (const margin of margins) {
      const benignClear = b.every((s) => s.att < threshold - BUFFER || s.margin < margin - BUFFER);
      if (!benignClear) continue;
      const hit = a.filter((s) => s.att >= threshold && s.margin >= margin).length;
      const better = !best || hit > best.hit || (hit === best.hit && threshold + margin > best.threshold + best.margin);
      if (better) best = { threshold, margin, hit };
    }
  }
  const recall = best ? best.hit / a.length : 0;
  return {
    threshold: best?.threshold ?? 1,
    margin: best?.margin ?? 1,
    recall: round(recall),
    attacks: a.length,
    benign: b.length,
    benignFired: 0,
    usable: recall >= MIN_RECALL,
  };
}

export async function embedAll(rt, model, texts, { timeoutMs = 120_000, onProgress } = {}) {
  const out = [];
  const deadline = Date.now() + timeoutMs;
  for (let i = 0; i < texts.length; i += BATCH) {
    const left = deadline - Date.now();
    if (left <= 0) throw new Error('timeout');
    const rows = await embed(rt, model, texts.slice(i, i + BATCH), { timeoutMs: left });
    out.push(...rows.map(normalize));
    onProgress?.(Math.min(i + BATCH, texts.length), texts.length);
  }
  return out;
}

export async function buildIndex(rt, model, opts = {}) {
  const texts = [PROBE_TEXT, ...ATTACK_EXEMPLARS, ...BENIGN_EXEMPLARS, ...CALIBRATION_ATTACKS, ...CALIBRATION_BENIGN];
  const vectors = await embedAll(rt, model, texts, opts);
  const dims = vectors[0].length;
  let at = 0;
  const take = (n) => vectors.slice(at, (at += n));
  const [probe] = take(1);
  const attack = take(ATTACK_EXEMPLARS.length);
  const benign = take(BENIGN_EXEMPLARS.length);
  const calAttack = take(CALIBRATION_ATTACKS.length);
  const calBenign = take(CALIBRATION_BENIGN.length);
  const calibration = calibrate({ attack, benign }, calAttack, calBenign);
  return {
    stored: {
      version: INDEX_VERSION,
      exemplars: EXEMPLAR_VERSION,
      runtime: rt.kind,
      model,
      dims,
      probe: encodeVectors([probe]),
      attack: encodeVectors(attack),
      benign: encodeVectors(benign),
      calibration,
      builtAt: new Date().toISOString(),
    },
    calibration,
  };
}

export function saveIndex(stored, file = INDEX_FILE) {
  writeJson(file, stored);
}

export function loadIndex(file = INDEX_FILE) {
  const raw = readJson(file);
  if (!raw || raw.version !== INDEX_VERSION || !Number.isInteger(raw.dims) || raw.dims <= 0) return null;
  const probe = decodeVectors(raw.probe, raw.dims)?.[0];
  const attack = decodeVectors(raw.attack, raw.dims);
  const benign = decodeVectors(raw.benign, raw.dims);
  if (!probe || !attack?.length || !benign?.length) return null;
  return { ...raw, probe, attack, benign };
}

export function removeIndex(file = INDEX_FILE) {
  try {
    fs.rmSync(file, { force: true });
  } catch {
  }
}
