import fs from 'node:fs';
import path from 'node:path';
import { CONFIG_DIR } from './config.mjs';
import { clampInt } from './numbers.mjs';

const BREAKER_FILE = path.join(CONFIG_DIR, 'guard-breaker.json');

export function guardTimeoutMs() {
  return clampInt(process.env.SHOMRA_GUARD_TIMEOUT_MS, 2000, 200, 30000);
}

export function breakerCooldownMs() {
  return clampInt(process.env.SHOMRA_GUARD_BREAKER_MS, 30000, 0, 600000);
}

export function breakerWindowOpen(at, now, cooldown) {
  if (!(cooldown > 0) || typeof at !== 'number' || !Number.isFinite(at)) return false;
  const age = now - at;
  return age >= 0 && age < cooldown;
}

export function breakerOpen() {
  const cooldown = breakerCooldownMs();
  if (cooldown === 0) return false;
  try {
    const { at } = JSON.parse(fs.readFileSync(BREAKER_FILE, 'utf8'));
    return breakerWindowOpen(at, Date.now(), cooldown);
  } catch {
    return false;
  }
}

export function breakerTrip() {
  try {
    fs.mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
    fs.writeFileSync(BREAKER_FILE, JSON.stringify({ at: Date.now() }), { mode: 0o600 });
  } catch {

  }
}

export function breakerReset() {
  try {
    fs.rmSync(BREAKER_FILE, { force: true });
  } catch {

  }
}
