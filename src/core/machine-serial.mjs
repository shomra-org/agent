import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const PLACEHOLDERS = new Set([
  '',
  '0',
  'NONE',
  'N/A',
  'NA',
  'DEFAULT STRING',
  'TO BE FILLED BY O.E.M.',
  'SYSTEM SERIAL NUMBER',
  'NOT SPECIFIED',
  'NOT APPLICABLE',
  'CHASSIS SERIAL NUMBER',
  'INVALID',
  '123456789',
  '0123456789',
]);

export function cleanSerial(raw) {
  const v = String(raw ?? '').replace(/\0/g, '').trim();
  if (v.length < 4 || v.length > 64) return null;
  if (PLACEHOLDERS.has(v.toUpperCase())) return null;
  if (/^0+$/.test(v) || /^[xX*.\- ]+$/.test(v)) return null;
  return v;
}

export function parseIoregSerial(text) {
  const m = /"IOPlatformSerialNumber"\s*=\s*"([^"]*)"/.exec(String(text ?? ''));
  return m ? cleanSerial(m[1]) : null;
}

function run(bin, args) {
  try {
    if (!fs.statSync(bin).isFile()) return null;
    return execFileSync(bin, args, { stdio: ['ignore', 'pipe', 'ignore'], timeout: 5000, windowsHide: true }).toString();
  } catch {
    return null;
  }
}

export function readMachineSerial(platform = process.platform, env = process.env) {
  if (platform === 'darwin') return parseIoregSerial(run('/usr/sbin/ioreg', ['-c', 'IOPlatformExpertDevice', '-d', '2']));
  if (platform === 'win32') {
    const root = env.SystemRoot || env.SYSTEMROOT || 'C:\\Windows';
    const ps = path.win32.join(root, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
    return cleanSerial(run(ps, ['-NoProfile', '-NonInteractive', '-Command', '(Get-CimInstance -ClassName Win32_BIOS).SerialNumber']));
  }
  if (platform === 'linux') {
    for (const f of ['/sys/class/dmi/id/product_serial', '/sys/class/dmi/id/chassis_serial']) {
      try {
        const v = cleanSerial(fs.readFileSync(f, 'utf8'));
        if (v) return v;
      } catch {
        /* root-only on most distributions */
      }
    }
  }
  return null;
}
