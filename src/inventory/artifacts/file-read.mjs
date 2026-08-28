import fs from 'node:fs';
import { MAX_FILE_BYTES } from './limits.mjs';

export function readJsonAt(file) {
  let raw;
  try {
    raw = fs.readFileSync(file, 'utf8');
  } catch {
    return null;
  }
  try {
    return JSON.parse(stripJsonComments(raw));
  } catch {
    return undefined;
  }
}

export function readText(file, cap = MAX_FILE_BYTES) {
  try {
    const st = fs.statSync(file);
    if (!st.isFile()) return null;
    const fd = fs.openSync(file, 'r');
    try {
      const len = Math.min(st.size, cap);
      const buf = Buffer.alloc(len);
      fs.readSync(fd, buf, 0, len, 0);

      if (buf.includes(0)) return null;
      return { text: buf.toString('utf8'), truncated: st.size > cap, bytes: st.size };
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return null;
  }
}

export function stripJsonComments(s) {
  return String(s)
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:])\/\/.*$/gm, '$1');
}
