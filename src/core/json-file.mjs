import fs from 'node:fs';
import { EXIT_USAGE } from './exit-codes.mjs';
import { red } from './terminal.mjs';

export function readJsonFile(file) {
  if (!fs.existsSync(file)) return {};
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    console.error(red('✗') + ` ${file} is not valid JSON - fix or move it first.`);
    process.exit(EXIT_USAGE);
  }
}
