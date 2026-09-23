import crypto from 'node:crypto';
import { createRequire } from 'node:module';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export const CONFIG_DIR = path.join(os.homedir(), '.shomra');

export const CONFIG_FILE = path.join(CONFIG_DIR, 'config.json');

export const PUBLIC_BACKEND_URL = 'https://shomra-backend-emgjg9b0fcdmc8hu.westeurope-01.azurewebsites.net';

export function machineConfigFile(platform = process.platform, env = process.env) {
  if (platform === 'win32') return path.win32.join(env.ProgramData || env.PROGRAMDATA || 'C:\\ProgramData', 'Shomra', 'config.json');
  return '/etc/shomra/config.json';
}

export const MACHINE_CONFIG_FILE = machineConfigFile();

const MACHINE_SCOPED = Symbol('shomra.machineConfig');

export function isMachineConfig(cfg) {
  return !!cfg?.[MACHINE_SCOPED];
}

export function markMachineConfig(cfg) {
  Object.defineProperty(cfg, MACHINE_SCOPED, { value: true });
  return cfg;
}

export function loadMachineConfig(file = MACHINE_CONFIG_FILE) {
  try {
    const cfg = JSON.parse(fs.readFileSync(file, 'utf8'));
    return cfg && typeof cfg === 'object' && !Array.isArray(cfg) ? cfg : null;
  } catch {
    return null;
  }
}

export function loadConfig() {
  let user;
  try {
    user = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
  } catch (e) {
    if (e?.code !== 'ENOENT') return {};
    const machine = loadMachineConfig();
    return machine ? markMachineConfig(machine) : {};
  }
  if (!user || typeof user !== 'object') return {};
  if (!user.apiKey || !user.url) {
    const machine = loadMachineConfig();
    for (const k of ['apiKey', 'url']) {
      if (!user[k] && machine?.[k]) Object.defineProperty(user, k, { value: machine[k], enumerable: false, writable: true, configurable: true });
    }
  }
  return user;
}

function restrictWindowsDir(dir, env = process.env) {
  const icacls = path.win32.join(env.SystemRoot || env.SYSTEMROOT || 'C:\\Windows', 'System32', 'icacls.exe');
  createRequire(import.meta.url)('node:child_process').execFileSync(icacls, [dir, '/inheritance:r', '/grant:r', '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F'], { stdio: 'ignore', timeout: 15000, windowsHide: true });
}

export function saveMachineConfig(cfg, file = MACHINE_CONFIG_FILE) {
  const dir = path.dirname(file);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  if (process.platform === 'win32') restrictWindowsDir(dir);
  else fs.chmodSync(dir, 0o700);
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify({ ...cfg }, null, 2), { mode: 0o600 });
  if (process.platform !== 'win32') fs.chmodSync(tmp, 0o600);
  fs.renameSync(tmp, file);
}

export function saveConfig(cfg) {
  if (isMachineConfig(cfg)) return saveMachineConfig(cfg);
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

export function inheritedMachineId(cfg, machine) {
  if (cfg?.machineId || isMachineConfig(cfg)) return null;
  return typeof machine?.machineId === 'string' && machine.machineId ? machine.machineId : null;
}

export function getMachineId(cfg, machine = loadMachineConfig()) {
  if (cfg.machineId) return cfg.machineId;
  const inherited = inheritedMachineId(cfg, machine);
  if (inherited) {
    cfg.machineId = inherited;
    try {
      saveConfig(cfg);
    } catch {}
    return cfg.machineId;
  }
  cfg.machineId = crypto.randomUUID();
  saveConfig(cfg);
  return cfg.machineId;
}

export function getMachineSerial(cfg, read) {
  if (cfg.serial) return cfg.serial;
  const serial = read();
  if (!serial) return null;
  cfg.serial = serial;
  try {
    saveConfig(cfg);
  } catch {}
  return serial;
}

export function resolveSettings(cfg) {

  const raw = process.env.SHOMRA_URL || cfg.url || '';
  return {
    apiKey: process.env.SHOMRA_API_KEY || cfg.apiKey,
    url: raw ? raw.replace(/\/$/, '').replace('://localhost', '://127.0.0.1') : null,
  };
}
