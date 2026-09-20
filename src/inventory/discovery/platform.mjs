import os from 'node:os';
import path from 'node:path';

export const HOME = os.homedir();

export const APPDATA = process.env.APPDATA || path.join(HOME, 'AppData', 'Roaming');

export const LOCALAPPDATA = process.env.LOCALAPPDATA || path.join(HOME, 'AppData', 'Local');

export const PLAT = process.platform;

const sameDir = (a, b) => (PLAT === 'win32' ? path.resolve(a).toLowerCase() === path.resolve(b).toLowerCase() : path.resolve(a) === path.resolve(b));

export function userDirs(home = HOME) {
  const own = !home || sameDir(home, HOME);
  const h = own ? HOME : home;
  const appdata = own ? APPDATA : path.join(h, 'AppData', 'Roaming');
  const localAppdata = own ? LOCALAPPDATA : path.join(h, 'AppData', 'Local');
  const vscode = (variant = 'Code') => {
    if (PLAT === 'win32') return path.join(appdata, variant, 'User');
    if (PLAT === 'darwin') return path.join(h, 'Library', 'Application Support', variant, 'User');
    return path.join(h, '.config', variant, 'User');
  };
  return { HOME: h, APPDATA: appdata, LOCALAPPDATA: localAppdata, vscodeUserDir: vscode, own };
}

export function vscodeUserDir(variant = 'Code') {
  return userDirs().vscodeUserDir(variant);
}
