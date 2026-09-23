import { redactLocally } from '../detect/local-redact.mjs';
import { pickWindows } from './chunks.mjs';
import { BACKOFF_MS, STATE_FILE, localBudgetMs, localDisabled, patchState, readState } from './config.mjs';
import { EXEMPLAR_VERSION, PROBE_TEXT } from './exemplars.mjs';
import { PROBE_MIN, dot, fires, loadIndex, normalize, scoreVector } from './index.mjs';
import { embed } from './runtime.mjs';

export const LOCAL_MODEL_LABEL = 'A local model read this as instructions addressed to the agent';
const TIMEOUT_BACKOFF_MS = 15_000;

export function localModelFinding(reading) {
  return { category: 'injection', severity: 'MEDIUM', label: LOCAL_MODEL_LABEL, basis: 'local-model', score: reading?.score ?? null };
}

export function indexProblem(index, settings) {
  if (!index) return 'no-index';
  if (index.exemplars !== EXEMPLAR_VERSION || index.model !== settings.embed.model || index.runtime !== settings.kind) return 'stale-index';
  if (!index.calibration?.usable) return 'not-discriminative';
  return null;
}

export async function screenWithLocalModel(text, settings, { budgetMs = localBudgetMs(), now = Date.now(), windows: pick = {}, index: preloaded, ignoreBackoff = false, stateFile = STATE_FILE } = {}) {
  if (!settings?.embed?.model) return { state: 'not-configured' };
  if (localDisabled()) return { state: 'off' };
  if (!ignoreBackoff) {
    const st = readState(stateFile);
    if (Number(st.backoffUntil) > now) return { state: 'backoff' };
  }
  const index = preloaded ?? loadIndex();
  const problem = indexProblem(index, settings);
  if (problem) return { state: problem };

  const windows = pickWindows(text, pick);
  if (!windows.length) return { state: 'quiet', windows: [] };
  const payload = settings.locality === 'loopback' ? windows : windows.map((w) => redactLocally(w).text);
  const started = performance.now();
  let vectors;
  try {
    vectors = await embed({ kind: settings.kind, url: settings.url }, settings.embed.model, [PROBE_TEXT, ...payload], { timeoutMs: budgetMs });
  } catch (error) {
    const timedOut = error?.message === 'timeout';
    patchState({ backoffUntil: now + (timedOut ? TIMEOUT_BACKOFF_MS : BACKOFF_MS), lastError: String(error?.message ?? error).slice(0, 160), lastErrorAt: now }, stateFile);
    return { state: timedOut ? 'timeout' : 'unavailable', error: String(error?.message ?? error).slice(0, 160) };
  }
  const [probe, ...rest] = vectors.map(normalize);
  if (probe.length !== index.dims || dot(probe, index.probe) < PROBE_MIN) {
    patchState({ modelChangedAt: now, backoffUntil: now + BACKOFF_MS }, stateFile);
    return { state: 'model-changed' };
  }
  const scored = rest.map((v, i) => ({ window: windows[i], ...scoreVector(index, v) }));
  const hits = scored.filter((s) => fires(s, index.calibration));
  const best = (hits.length ? hits : scored).reduce((m, s) => (!m || s.margin > m.margin ? s : m), null);
  return {
    state: hits.length ? 'raised' : 'quiet',
    windows: scored,
    score: best ? { att: best.att, margin: best.margin } : null,
    window: hits.length ? best.window : null,
    ms: Math.round(performance.now() - started),
  };
}
