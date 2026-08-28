import fs from 'node:fs';
import path from 'node:path';
import { IGNORE_DIRS, MAX_DEPTH } from './limits.mjs';

export function walkRoot(dir, budget) {
  const out = [];
  const seen = new Set();
  const queue = [{ d: dir, depth: 0 }];
  while (queue.length && budget.dirs > 0) {
    const { d, depth } = queue.shift();
    let real;
    try {
      real = fs.realpathSync(d);
    } catch {
      continue;
    }
    if (seen.has(real)) continue;
    seen.add(real);
    budget.dirs--;
    let entries;
    try {
      entries = fs.readdirSync(d, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      const full = path.join(d, e.name);
      if (e.isDirectory()) {
        if (depth < MAX_DEPTH && !IGNORE_DIRS.has(e.name)) queue.push({ d: full, depth: depth + 1 });
      } else if (e.isFile()) {
        out.push(full);
      }
    }
  }
  return out;
}
