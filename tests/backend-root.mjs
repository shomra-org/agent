import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const BACKEND_ROOT = ['Shomra.Backend', 'Dragox.Backend']
  .map((name) => path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', name))
  .find((dir) => fs.existsSync(path.join(dir, 'src', 'modules'))) ?? null;
