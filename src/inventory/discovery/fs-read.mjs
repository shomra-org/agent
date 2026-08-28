import fs from 'node:fs';

export function readJson(file) {
  try {
    return JSON.parse(stripJsonComments(fs.readFileSync(file, 'utf8')));
  } catch {
    return null;
  }
}

function stripJsonComments(s) {
  return String(s)
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:])\/\/.*$/gm, '$1');
}

export function readText(file, cap = 200_000) {
  try {
    const b = fs.readFileSync(file, 'utf8');
    return b.length > cap ? b.slice(0, cap) : b;
  } catch {
    return null;
  }
}

export function exists(p) {
  try {
    return fs.existsSync(p);
  } catch {
    return false;
  }
}

export function firstExisting(paths) {
  return paths.find((p) => p && exists(p)) || null;
}
