import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export const CONFIG_DIR = path.join(os.homedir(), '.shomra');

export const CONFIG_FILE = path.join(CONFIG_DIR, 'config.json');

export function loadConfig() {
  try {
    return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
  } catch {
    return {};
  }
}

export function saveConfig(cfg) {
  fs.mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
  try {
    fs.chmodSync(CONFIG_DIR, 0o700);
  } catch {}
  const tmp = `${CONFIG_FILE}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(cfg, null, 2), { mode: 0o600 });
  try {
    fs.chmodSync(tmp, 0o600);
  } catch {}
  fs.renameSync(tmp, CONFIG_FILE);
}

export function getMachineId(cfg) {
  if (cfg.machineId) return cfg.machineId;
  cfg.machineId = crypto.randomUUID();
  saveConfig(cfg);
  return cfg.machineId;
}

export function resolveSettings(cfg) {

  const raw = process.env.SHOMRA_URL || cfg.url || '';
  return {
    apiKey: process.env.SHOMRA_API_KEY || cfg.apiKey,
    url: raw ? raw.replace(/\/$/, '').replace('://localhost', '://127.0.0.1') : null,
  };
}
