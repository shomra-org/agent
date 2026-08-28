export const INSTALL_LURE = [
  { name: 'Instructs downloading an executable/archive to run', re: /\b(download|install|fetch|grab|extract)\b[^\n]{0,180}\.(zip|exe|dmg|pkg|msi|bin|appimage|jar|scr|apk|deb|rpm|tar\.gz|tgz)\b/i, severity: 'MEDIUM' },
  { name: 'Password-protected archive (evades AV / scanners)', re: /\b(extract|unzip|decompress|archive|zip|password)\b[^\n]{0,50}\b(pass(word|phrase)?|pwd)\s*[:=]\s*\S/i, severity: 'HIGH' },
  { name: 'Coercion: claims a helper is required before the task works', re: /\b(required to (function|work|deploy|run)|will not (work|function|run)( correctly| properly)?( without)?|does not work without|otherwise it is impossible|cannot [a-z ]{0,24} without (installing|running)|must (be )?(install(ed)?|run) (this |the )?)/i, severity: 'MEDIUM' },
  { name: 'Coercion: re-run / retry until it succeeds', re: /\b(re-?run (if needed|until|the command)|run (it |the command )?again|try again after)/i, severity: 'LOW' },
];

export const MALICIOUS_PACKAGE_SEED = new Set([
  'event-stream', 'eslint-scope-malware', 'electron-native-notify', 'rc-malware',
  'crossenv', 'mongose', 'expresss',
]);

export const POPULAR_PACKAGES = [
  'express', 'react', 'lodash', 'axios', 'chalk', 'commander',
  'mongoose', 'cross-env', 'dotenv', 'request', 'puppeteer', 'playwright',
];

export function editDistance(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++)
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
    }
  return dp[m][n];
}

export function packageFromCommand(command, args) {
  const tokens = [command, ...(args ?? [])].filter(Boolean).map(String);
  if (!tokens.length) return null;
  const runners = new Set(['npx', 'npm', 'pnpm', 'yarn', 'bunx', 'bun']);
  const skips = new Set(['exec', 'dlx', 'run', 'install', 'add', 'create', '-y', '--yes']);
  const start = runners.has(tokens[0].split('/').pop() ?? tokens[0]) ? 1 : -1;
  if (start === -1) return null;
  for (let i = start; i < tokens.length; i++) {
    const t = tokens[i];
    if (t.startsWith('-') || skips.has(t)) continue;
    const name = t.startsWith('@') ? t.split('/').slice(0, 2).join('/') : t.split('@')[0];
    return name.replace(/@[\d^~].*$/, '');
  }
  return null;
}
