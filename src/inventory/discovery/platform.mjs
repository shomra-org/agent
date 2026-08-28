import os from 'node:os';
import path from 'node:path';

export const HOME = os.homedir();

export const APPDATA = process.env.APPDATA || path.join(HOME, 'AppData', 'Roaming');

export const LOCALAPPDATA = process.env.LOCALAPPDATA || path.join(HOME, 'AppData', 'Local');

export const PLAT = process.platform;

export function vscodeUserDir(variant = 'Code') {
  if (PLAT === 'win32') return path.join(APPDATA, variant, 'User');
  if (PLAT === 'darwin') return path.join(HOME, 'Library', 'Application Support', variant, 'User');
  return path.join(HOME, '.config', variant, 'User');
}
