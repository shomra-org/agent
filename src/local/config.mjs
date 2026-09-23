import fs from 'node:fs';
import path from 'node:path';
import { CONFIG_DIR } from '../core/config.mjs';

export const LOCAL_DIR = path.join(CONFIG_DIR, 'local');
export const INDEX_FILE = path.join(LOCAL_DIR, 'index.json');
export const STATE_FILE = path.join(LOCAL_DIR, 'state.json');
export const SETTINGS_FILE = path.join(LOCAL_DIR, 'settings.json');

export const DEFAULT_BUDGET_MS = 250;
export const MAX_BUDGET_MS = 2_000;
export const BACKOFF_MS = 60_000;

const offValue = (v) => ['1', 'true', 'yes', 'on'].includes(String(v ?? '').trim().toLowerCase());

export function localDisabled(env = process.env) {
  return offValue(env.SHOMRA_LOCAL_OFF);
}

export function localBudgetMs(env = process.env) {
  const n = Number(env.SHOMRA_LOCAL_BUDGET_MS);
  return Number.isFinite(n) && n > 0 ? Math.min(Math.round(n), MAX_BUDGET_MS) : DEFAULT_BUDGET_MS;
}

export function localSettings(file = SETTINGS_FILE) {
  const local = readJson(file);
  if (!local || typeof local.url !== 'string' || !['ollama', 'openai'].includes(local.kind)) return null;
  return local;
}

export function readJson(file) {
  try {
    const v = JSON.parse(fs.readFileSync(file, 'utf8'));
    return v && typeof v === 'object' ? v : null;
  } catch {
    return null;
  }
}

export function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(value), { mode: 0o600 });
  fs.renameSync(tmp, file);
}

export function readState(file = STATE_FILE) {
  return readJson(file) ?? {};
}

export function patchState(patch, file = STATE_FILE) {
  try {
    writeJson(file, { ...readState(file), ...patch });
  } catch {
  }
}
