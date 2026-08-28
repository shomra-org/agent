import fs from 'node:fs';
import { PACKAGE_MANIFEST_PATH } from './package-root.mjs';

const FALLBACK_VERSION = '0.0.0';

function readPackageVersion() {
  try {
    return JSON.parse(fs.readFileSync(PACKAGE_MANIFEST_PATH, 'utf8')).version ?? FALLBACK_VERSION;
  } catch {
    return FALLBACK_VERSION;
  }
}

export const VERSION = readPackageVersion();
