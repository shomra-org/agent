import path from 'node:path';
import { fileURLToPath } from 'node:url';

const CORE_DIR = path.dirname(fileURLToPath(import.meta.url));

export const PACKAGE_ROOT = path.resolve(CORE_DIR, '..', '..');

export const PACKAGE_MANIFEST_PATH = path.join(PACKAGE_ROOT, 'package.json');

export const CLI_ENTRY_PATH = path.join(PACKAGE_ROOT, 'shomra.mjs');
