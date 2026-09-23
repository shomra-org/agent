import { createRequire } from 'node:module';
import { CLI_ENTRY_PATH } from '../core/package-root.mjs';
import { STATE_FILE, localSettings, patchState, readState } from './config.mjs';
import { EXEMPLAR_VERSION, PROBE_TEXT } from './exemplars.mjs';
import { PROBE_MIN, buildIndex, dot, loadIndex, normalize, saveIndex } from './index.mjs';
import { currentDigest, embed } from './runtime.mjs';

const REINDEX_EVERY_MS = 30 * 60 * 1000;

export function onlySamplesChanged(index, settings) {
  return !!index && !!settings?.embed?.model && index.exemplars !== EXEMPLAR_VERSION && index.model === settings.embed.model && index.runtime === settings.kind;
}

export function maybeReindexInBackground(index, settings, { now = Date.now(), env = process.env, stateFile = STATE_FILE, spawnImpl } = {}) {
  if (env.SHOMRA_LOCAL_CHILD === '1' || !onlySamplesChanged(index, settings)) return false;
  if (now - Number(readState(stateFile).reindexAt ?? 0) < REINDEX_EVERY_MS) return false;
  patchState({ reindexAt: now }, stateFile);
  try {
    const run = spawnImpl ?? createRequire(import.meta.url)('node:child_process').spawn;
    const child = run(process.execPath, [CLI_ENTRY_PATH, 'local', 'reindex', '--quiet'], {
      detached: true,
      stdio: 'ignore',
      windowsHide: true,
      env: { ...env, SHOMRA_LOCAL_CHILD: '1', SHOMRA_TELEMETRY_CHILD: '1' },
    });
    child?.on?.('error', () => {});
    child?.unref?.();
    return true;
  } catch {
    return false;
  }
}

export async function reindex({ settings = localSettings(), index = loadIndex(), file, timeoutMs = 300_000 } = {}) {
  if (!onlySamplesChanged(index, settings)) return { ok: false, reason: 'not-needed' };
  const rt = { kind: settings.kind, url: settings.url };
  if (settings.kind === 'ollama' && settings.embed.digest) {
    const digest = await currentDigest(rt, settings.embed.model, { timeoutMs: 5_000 }).catch(() => null);
    if (digest !== settings.embed.digest) return { ok: false, reason: 'model-changed' };
  }
  const [probe] = (await embed(rt, settings.embed.model, [PROBE_TEXT], { timeoutMs: 10_000 })).map(normalize);
  if (!probe || probe.length !== index.dims || dot(probe, index.probe) < PROBE_MIN) return { ok: false, reason: 'model-changed' };
  const built = await buildIndex(rt, settings.embed.model, { timeoutMs });
  saveIndex(built.stored, file);
  return { ok: true, calibration: built.calibration };
}
