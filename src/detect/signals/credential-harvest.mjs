import { isDocumentationLine, prohibitsAt } from './prose-context.mjs';

const HARVEST_PROMPTS = [
  { re: /\bosascript\b[\s\S]{0,200}?\bdisplay\s+dialog\b[\s\S]{0,200}?\bhidden\s+answer\b/i, label: 'osascript password dialog (hidden answer)' },
  { re: /\bdo\s+shell\s+script\b[\s\S]{0,160}?\bwith\s+administrator\s+privileges\b/i, label: 'AppleScript privilege elevation' },
  { re: /\bosascript\b[\s\S]{0,200}?\bdisplay\s+dialog\b[\s\S]{0,160}?\b(?:password|passcode|credential|keychain|unlock)\b/i, label: 'osascript credential dialog' },
  { re: /\b(?:zenity|kdialog|yad)\b[^\n]{0,120}?--password\b/i, label: 'desktop password dialog' },
  { re: /\bSUDO_ASKPASS\s*=|\bsudo\s+-A\b/i, label: 'sudo askpass helper' },
  { re: /\b(?:Get-Credential|PromptForCredential|CredUIPromptForCredentials)\b/i, label: 'Windows credential prompt' },
];

const HARVEST_STORES = [
  { re: /\bsecurity\s+(?:dump-keychain|find-(?:generic|internet)-password|export)\b/i, family: 'credential-store', label: 'macOS keychain read' },
  { re: /(?:~|\$HOME|\/Users\/[^/\s]+)\/Library\/Keychains\b/i, family: 'credential-store', label: 'macOS keychain files' },
  { re: /\bLogin\s?Data\b|\bLocal\s?State\b(?=[\s\S]{0,80}(?:Chrome|Chromium|Edge|Brave))/i, family: 'credential-store', label: 'Chromium credential database' },
  { re: /\b(?:logins\.json|key[34]\.db|cert9\.db)\b/i, family: 'credential-store', label: 'Firefox credential database' },
  { re: /\bcookies\.sqlite\b|\bCookies\b(?=[\s\S]{0,80}(?:Chrome|Chromium|Edge|Brave|Safari))/i, family: 'credential-store', label: 'browser cookie store' },
  { re: /(?:~|\$HOME)\/\.(?:mozilla|config\/google-chrome|config\/chromium|config\/BraveSoftware)\b/i, family: 'credential-store', label: 'browser profile directory' },
  { re: /\b(?:Exodus|Electrum|Coinomi|Atomic\s?Wallet|MetaMask|Ledger\s?Live|Trezor\s?Suite)\b|\bwallet\.dat\b|(?:~|\$HOME)\/\.ethereum\/keystore\b/i, family: 'wallet', label: 'cryptocurrency wallet store' },
];

const HARVEST_TOKEN_PATH =
  /(?:~|\$HOME)\/\.(?:npmrc|pypirc|netrc|docker\/config\.json|kube\/config|config\/gh\/hosts\.yml|config\/gcloud\/credentials\.db|cargo\/credentials(?:\.toml)?)\b/i;

const HARVEST_EXFIL_VERB = /\b(?:cp|copy|mv|scp|rsync|tar|zip|curl|wget|base64|cat|xxd|upload|post|send|exfil\w*)\b/i;

const HARVEST_MOVE_VERB = /\b(?:cp|copy|mv|scp|rsync|tar|zip|curl|wget|base64|xxd|upload|post|send|exfil\w*)\b/i;

const HARVEST_READ_VERB = /\b(?:cat|cp|copy|mv|scp|rsync|tar|zip|dd|xxd|base64|open|read|sqlite3?|strings|python\d?|node|osascript|security|plutil|defaults)\b|[<>|]/i;

export function detectCredentialHarvest(text) {
  const body = String(text ?? '');
  if (!body.trim()) return [];
  const out = [];
  const seen = new Set();
  const push = (family, label, severity, i, line) => {
    if (seen.has(label) || out.length >= 12) return;
    seen.add(label);
    out.push({ family, label, severity, line: i + 1, sample: line.trim().slice(0, 200) });
  };
  const lines = body.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line.trim() || line.length > 2000) continue;
    for (const p of HARVEST_PROMPTS) {
      const m = p.re.exec(line);
      if (!m) continue;
      if (isDocumentationLine(line) || prohibitsAt(line, m.index)) continue;
      push('interactive-prompt', p.label, 'CRITICAL', i, line);
    }
    for (const s of HARVEST_STORES) {
      const m = s.re.exec(line);
      if (!m) continue;
      if (!HARVEST_READ_VERB.test(line)) continue;
      if (isDocumentationLine(line) || prohibitsAt(line, m.index)) continue;
      push(s.family, s.label, HARVEST_EXFIL_VERB.test(line) ? 'CRITICAL' : 'HIGH', i, line);
    }
    const t = HARVEST_TOKEN_PATH.exec(line);
    if (t && HARVEST_EXFIL_VERB.test(line) && !isDocumentationLine(line) && !prohibitsAt(line, t.index)) {
      push('token-store', `developer token file (${t[0]})`, HARVEST_MOVE_VERB.test(line) ? 'HIGH' : 'MEDIUM', i, line);
    }
  }
  return out;
}
