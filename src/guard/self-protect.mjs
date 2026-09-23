import path from 'node:path';
import { CONFIG_DIR } from '../core/config.mjs';

const STATE_FILE_RE = /\.shomra[\\/]+(?:allows|org-allows|asks|config|machine|trusted-repos)\.json\b/i;
const IGNORE_FILE_RE = /(?:^|[\s'"=/\\])\.shomraignore\b/;
const SHELL_WRITE_RE = /(?:>>?|\btee\b|\bcp\b|\bmv\b|\bsed\b[^\n;|&]*\s-i|\brm\b|\bdd\b|\btruncate\b|\bln\b|\binstall\b|\bchmod\b|\bnode\b|\bpython[0-9.]*\b|\bperl\b|\bruby\b|\bjq\b[^\n;|&]*>|\bSet-Content\b|\bAdd-Content\b|\bOut-File\b)/i;

export const SELF_MODIFY = {
  id: 'shomra-self-modify',
  label: "Modifies Shomra's own allowlist or configuration",
  severity: 'CRITICAL',
  category: 'shell',
};

export const IGNORE_EDIT = {
  id: 'shomra-ignore-edit',
  label: 'Edits the Shomra ignore file (.shomraignore)',
  severity: 'HIGH',
  category: 'shell',
  confirm: true,
};

function underConfigDir(p, cwd) {
  if (!p) return false;
  const abs = path.resolve(cwd || process.cwd(), String(p).replace(/^~(?=$|[\\/])/, path.dirname(CONFIG_DIR)));
  const rel = path.relative(CONFIG_DIR, abs);
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

export function selfProtectionFindings({ isWrite, targetPath, command, cwd }) {
  const out = [];
  if (isWrite && targetPath) {
    if (underConfigDir(targetPath, cwd)) out.push({ ...SELF_MODIFY });
    else if (path.basename(String(targetPath)) === '.shomraignore') out.push({ ...IGNORE_EDIT });
  }
  if (typeof command === 'string' && command) {
    if (STATE_FILE_RE.test(command) && SHELL_WRITE_RE.test(command)) out.push({ ...SELF_MODIFY });
    else if (IGNORE_FILE_RE.test(command) && SHELL_WRITE_RE.test(command)) out.push({ ...IGNORE_EDIT });
  }
  return out;
}
