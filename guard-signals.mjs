/**
 * Tier-0 local guard signals — a dependency-free, high-confidence subset of the
 * backend detection engine (src/bundle/signals.ts + src/checks/patterns.ts),
 * ported so the runtime firewall can decide the DANGEROUS majority of tool calls
 * ON-BOX, with zero network round-trip.
 *
 * Why this exists: the pre-tool-call hook fires on every action. Routing every
 * call through the backend put a network dependency on the hot path — slow when
 * the backend was busy, and (fail-open) bypassable by simply making it
 * unreachable. This module lets the guard block the unambiguously-malicious
 * cases (curl|sh, reverse shells, base64 RCE, live secrets) locally and
 * instantly, so protection survives a slow/down/blocked backend.
 *
 * Division of labour:
 *   • LOCAL (here)  — deterministic, high-precision, offline. Never over-blocks:
 *     aligned to the server's DEFAULT policy (CRITICAL → BLOCK, HIGH → FLAG).
 *   • SERVER (Tier 2) — authoritative. Org policy, agent identity, MCP
 *     governance, information-flow taint, exceptions, telemetry. The CLI still
 *     escalates policy-relevant calls to it; the local tier is the floor, not a
 *     replacement.
 *
 * Keep the pattern lists roughly in sync with the server modules named above.
 * Drift only costs recall on the local floor — the server remains the full check.
 */

// ── dangerous shell (mirror of DANGEROUS_SHELL in src/bundle/signals.ts) ──
export const DANGEROUS_SHELL = [
  { name: 'Pipe-to-shell installer (curl … | sh)', re: /\b(curl|wget)\b[^\n|]{0,200}\|\s*(sudo\s+)?(ba|z|k)?sh\b/i, severity: 'CRITICAL' },
  { name: 'PowerShell download-and-run (iwr/curl … | iex)', re: /\b(iwr|curl|wget|invoke-webrequest|invoke-restmethod|irm)\b[^\n|]{0,200}\|\s*(iex|invoke-expression)\b/i, severity: 'CRITICAL' },
  { name: 'Invoke-Expression of downloaded content', re: /\b(iex|invoke-expression)\b[^\n]{0,120}(downloadstring|net\.webclient|\(\s*(iwr|irm|invoke-)|\$\()/i, severity: 'CRITICAL' },
  { name: 'Reverse shell via /dev/tcp', re: /\/dev\/(tcp|udp)\//i, severity: 'CRITICAL' },
  { name: 'Base64 blob piped to a shell', re: /base64\s+(--?d(ecode)?)?\b[^\n|]{0,200}\|\s*(ba|z)?sh\b/i, severity: 'CRITICAL' },
  { name: 'curl/wget posts data to the network (exfiltration)', re: /\b(curl|wget|http|https|invoke-restmethod|irm)\b[^\n]{0,220}(--data(-raw|-binary|-urlencode)?|--form\b|--upload-file\b|(^|\s)-d\s|(^|\s)-F\s|(^|\s)-T\s|-Method\s+Post)/i, severity: 'HIGH' },
  { name: 'Command output piped into a network call', re: /\b(curl|wget|invoke-restmethod|invoke-webrequest|irm|iwr)\b[^\n]{0,220}(\$\(|`[^`\n]+`|<\()/i, severity: 'HIGH' },
  { name: 'Fetches from a raw IP address', re: /\b(curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n]{0,220}https?:\/\/\d{1,3}(\.\d{1,3}){3}/i, severity: 'HIGH' },
  { name: 'Writes to shell profile / SSH keys / crontab', re: /(\.bashrc|\.zshrc|\.bash_profile|\.profile|authorized_keys|id_rsa\b|\bcrontab\b)/i, severity: 'HIGH' },
  { name: 'Recursive force delete (rm -rf)', re: /\brm\s+-[a-z]*r[a-z]*f|\brm\s+-[a-z]*f[a-z]*r/i, severity: 'HIGH' },
  { name: 'Inline eval / exec of a string', re: /\b(eval|exec)\s*[("`']/i, severity: 'HIGH' },
  { name: 'Pipes an env dump to the network', re: /\b(env|printenv|set)\b[^\n|]{0,80}\|[^\n]{0,80}(curl|wget|nc\b|http)/i, severity: 'HIGH' },
  { name: 'Disables TLS / cert verification', re: /(NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*0|GIT_SSL_NO_VERIFY|--no-check-certificate|--insecure\b|verify\s*=\s*False)/i, severity: 'MEDIUM' },
  { name: 'python -c one-liner', re: /python[0-9.]*\s+-c\b/i, severity: 'MEDIUM' },
  { name: 'node -e one-liner', re: /\bnode\s+-e\b/i, severity: 'MEDIUM' },
  { name: 'Netcat / socket exfil', re: /\bnc\s+-[a-z]*\b|\bncat\b/i, severity: 'MEDIUM' },
];

// ── injection (mirror of INJECTION_PHRASES / INJECTION_REGEXES) ──
export const INJECTION_PHRASES = [
  'ignore previous instructions', 'ignore all previous', 'disregard previous', 'disregard the above',
  'do not tell the user', "don't tell the user", 'without informing the user', 'without telling the user',
  'do not mention', "don't mention", 'never mention',
  'system prompt', 'you are now', 'new instructions:', 'override your', 'exfiltrate',
  'send them to', 'post them to', 'forward the',
  'run this first', 'run the following command', 'run the following commands', 'copy this command',
  'copy and run', 'execute the following', 'seed the current host',
  'ignore all instructions', 'ignore your instructions', 'ignore your safety', 'ignore all content policies',
  'disregard your instructions', 'disregard the guidelines', 'system override', 'follow only my instructions',
  'do anything now', 'reveal any credential',
  'save this to your memory', 'in all future sessions', 'remember this forever',
];
export const INJECTION_REGEXES = [
  { label: 'Instruction-override phrasing', re: /\b(ignore|disregard|forget|discard|override|bypass|skip)\b[\s\w,'"()-]{0,40}?\b(instruction|instructions|rule|rules|guideline|guidelines|prompt|prompts|directive|directives|context|constraint|constraints)\b/i },
  { label: 'Reference to overriding earlier context', re: /\b(previous|prior|above|earlier|preceding|former|the last|that (?:were |was )?given)\b[\s\w,'"()-]{0,25}?\b(instruction|instructions|rule|rules|prompt|prompts|message|messages|guidance)\b/i },
  { label: 'Bulk destructive command', re: /\b(delete|remove|wipe|erase|destroy|drop|purge|clear|nuke|truncate)\b[\s\w,'"()-]{0,20}?\b(all|every|each|entire|whole)\b[\s\w,'"()-]{0,15}?\b(folder|folders|file|files|directory|directories|table|tables|database|databases|record|records|repo|repos|repositor\w*|account|accounts|user|users|row|rows|document|documents|data)\b/i },
  { label: 'Recursive force-delete command', re: /\brm\s+-[a-z]*[rf][a-z]*\b|\brmdir\b|\bdel\s+\/[sqf]|remove-item\b[\s\S]{0,40}?-recurse/i },
  { label: 'Destructive SQL statement', re: /\b(drop|truncate)\s+(table|database|schema|index)\b/i },
];
// zero-width / bidi / tag-block chars used to smuggle instructions (ASCII smuggling).
export const INVISIBLE_CHARS_RE = /[​-‏‪-‮⁠-⁤﻿︀-️]|[\u{E0000}-\u{E007F}]|[\u{E0100}-\u{E01EF}]/u;

// ── secrets (mirror of SECRET_PATTERNS) ──
export const SECRET_PATTERNS = [
  { name: 'Stripe live key', re: /sk_live_[0-9a-zA-Z]{16,}/ },
  { name: 'OpenAI key', re: /sk-[A-Za-z0-9]{20,}/ },
  { name: 'AWS access key id', re: /AKIA[0-9A-Z]{16}/ },
  { name: 'GitHub token', re: /ghp_[0-9A-Za-z]{20,}/ },
  { name: 'Slack token', re: /xox[baprs]-[0-9A-Za-z-]{10,}/ },
  { name: 'Generic bearer', re: /bearer\s+[A-Za-z0-9._-]{20,}/i },
  { name: 'Private key block', re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/ },
];

export const RISKY_CONFIG_MARKERS = [
  'yolo', 'auto-approve', 'autoapprove', 'auto_approve', 'autorun', 'auto-run',
  'always allow', 'alwaysallow', 'dangerously', 'skip confirmation', 'no confirmation',
  'disable safety', 'bypass approval', 'full access', 'unrestricted',
];

// ── PII (mirror of PII_PATTERNS + Luhn gate in checks/text-inspector.ts) ──
export const PII_PATTERNS = [
  { name: 'Email address', re: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/ },
  { name: 'US SSN', re: /\b\d{3}-\d{2}-\d{4}\b/ },
  { name: 'Credit card number', re: /\b(?:\d[ -]*?){13,16}\b/ },
  { name: 'Phone number', re: /\b(?:\+?1[ .-]?)?\(?\d{3}\)?[ .-]?\d{3}[ .-]?\d{4}\b/ },
  { name: 'IPv4 address', re: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/ },
];

// Luhn check keeps the loose credit-card regex from firing on any digit run.
function luhnValid(value) {
  const digits = String(value).replace(/[^\d]/g, '');
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0, alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = parseInt(digits[i], 10);
    if (alt) { d *= 2; if (d > 9) d -= 9; }
    sum += d;
    alt = !alt;
  }
  return sum % 10 === 0;
}

// Capability verbs shared with the backend signal libs — used by the memory /
// rules toxic-flow check (a "read secret X and send it" standing instruction).
export const SENSITIVE_READ = [
  'secret', 'credential', 'password', 'token', 'api_key', 'apikey', 'private_key',
  'ssh', 'aws', 'env', 'environment', 'keychain', 'vault', 'read_file', 'readfile', 'cat ',
];
export const NETWORK_VERBS = [
  'http_request', 'http', 'fetch', 'request', 'curl', 'webhook', 'post', 'send',
  'upload', 'publish', 'email', 'sendmail', 'smtp',
];
export function containsAny(haystack, needles) {
  const h = String(haystack ?? '').toLowerCase();
  for (const n of needles) if (h.includes(n.toLowerCase())) return n;
  return null;
}

// Attacker-controlled data sinks (subset of SUSPICIOUS_EGRESS_HOSTS) — a tool
// call/result referencing one is an exfiltration endpoint.
export const SUSPICIOUS_EGRESS_HOSTS = [
  'webhook.site', 'requestbin', 'pipedream.net', 'ngrok.io', 'ngrok-free.app', 'ngrok.app',
  'trycloudflare.com', 'serveo.net', 'localhost.run', 'interact.sh', 'oastify.com', 'oast.pro',
  'oast.fun', 'burpcollaborator.net', 'canarytokens.com', 'beeceptor.com', 'requestcatcher.com',
  'c-net.org', 'pastebin.com', 'paste.ee', 'hastebin.com', 'dpaste.com', 'dpaste.org', 'ix.io',
  'sprunge.us', 'termbin.com', 'rentry.co', 'controlc.com', 'privatebin.net', 'ghostbin.com',
  'justpaste.it', 'transfer.sh', '0x0.st', 'file.io', 'gofile.io', 'anonfiles.com',
  'bashupload.com', 'tmpfiles.org', 'catbox.moe', 'litterbox.catbox.moe', 'temp.sh', 'oshi.at', 'x0.at',
];

const SEV_RANK = { INFO: 1, LOW: 2, MEDIUM: 3, HIGH: 4, CRITICAL: 5 };

// Decode suspicious base64 blobs so payloads hidden in an "echo <blob>|base64 -d|sh"
// trick are inspected too. We decode purely to READ the bytes; nothing runs.
const BASE64_BLOB_RE = /\b[A-Za-z0-9+/]{32,}={0,2}/g;
const DECODED_PAYLOAD_RE = /(\/bin\/(ba|z|k)?sh|\b(ba|z|k)?sh\s+-c|\bcurl\b|\bwget\b|\beval\b|\bexec\b|https?:\/\/|invoke-expression|\biex\b|powershell|\bnc\b|\bncat\b|\bchmod\b|\bbase64\b)/i;
function deobfuscate(text) {
  const decoded = [];
  for (const m of text.matchAll(BASE64_BLOB_RE)) {
    let out = '';
    try { out = Buffer.from(m[0], 'base64').toString('utf8'); } catch { continue; }
    if (!out) continue;
    const printable = out.replace(/[^\x09\x0a\x0d\x20-\x7e]/g, '');
    if (printable.length < out.length * 0.85) continue;
    if (DECODED_PAYLOAD_RE.test(out)) decoded.push(out);
  }
  return { text: decoded.length ? `${text}\n${decoded.join('\n')}` : text, decodedPayload: decoded.length > 0 };
}

/** Reference to a known exfiltration sink host, or null. */
export function egressHost(text) {
  if (!text) return null;
  const low = text.toLowerCase();
  return SUSPICIOUS_EGRESS_HOSTS.find((h) => low.includes(h)) ?? null;
}

/** 1-based line number of a character offset inside `text`. */
function lineAt(text, index) {
  let line = 1;
  const end = Math.min(index, text.length);
  for (let i = 0; i < end; i++) if (text.charCodeAt(i) === 10) line++;
  return line;
}

/**
 * Best-effort 1-based line where `needle` (a string or RegExp) first occurs in
 * `text`, so a finding can point at file:line. Undefined when it can't be
 * located (redacted samples, matches only inside decoded base64) — the finding
 * then stays file-scoped rather than pointing at the wrong line.
 */
function lineOf(text, needle) {
  if (!text || !needle) return undefined;
  let idx = -1;
  if (typeof needle === 'string') {
    const probe = needle.split('•')[0].trim().slice(0, 80);
    if (probe.length < 3) return undefined;
    idx = text.toLowerCase().indexOf(probe.toLowerCase());
  } else {
    const m = text.match(needle);
    idx = m && m.index != null ? m.index : -1;
  }
  return idx >= 0 ? lineAt(text, idx) : undefined;
}

// ── false-positive control: is a match DATA (in a literal) or a live command? ──
// The dominant FP for a security tool is scanning content that legitimately
// *contains* the very patterns it detects — its own detection source, security
// docs, a quoted sample, a fenced example. These helpers decide whether a match
// sits in such a code/data context (→ safe to down-rank) rather than as a bare,
// runnable command line (→ still dangerous).

// Single-pass mask of the "code/data" regions of a text: string literals (', ",
// backtick — multi-line aware), line comments (//, #), block comments (/* */,
// <!-- -->), regex literals (/…/), and fenced code blocks. mask[i] === 1 means
// offset i is inside such a region, i.e. any pattern there is DATA (a rule
// definition, a quoted sample, a documented example), not a live command line.
// A best-effort tokenizer — it biases toward marking (fewer false positives),
// which is the correct trade for a security tool scanning content it will merely
// read; execution is gated separately by the pre-call firewall.
function codeMask(text) {
  const n = text.length;
  const mask = new Uint8Array(n);
  const REGEX_START = new Set(['=', '(', ',', '[', '{', ';', ':', '!', '&', '|', '?', '+', '*', '~', '%', '^', '<', '>', 'return', 'typeof']);
  let state = 0; // 0 normal 1 ' 2 " 3 ` 4 line-comment 5 block-comment 6 html-comment 7 regex
  let prevSig = ''; // last non-whitespace char (for regex-vs-division)
  let inClass = false; // inside a regex [ … ] char class
  let i = 0;
  while (i < n) {
    const c = text[i], c2 = text[i + 1];
    if (state === 0) {
      if (c === "'") { state = 1; mask[i++] = 1; continue; }
      if (c === '"') { state = 2; mask[i++] = 1; continue; }
      if (c === '`') { state = 3; mask[i++] = 1; continue; }
      if (c === '/' && c2 === '/') { state = 4; mask[i++] = 1; continue; }
      if (c === '#' && (i === 0 || /\s/.test(text[i - 1]))) { state = 4; mask[i++] = 1; continue; }
      if (c === '/' && c2 === '*') { state = 5; mask[i++] = 1; continue; }
      if (c === '<' && text.startsWith('<!--', i)) { state = 6; mask[i++] = 1; continue; }
      if (text.startsWith('```', i) || text.startsWith('~~~', i)) { // fenced block → mask the whole span, delimiters included
        const fence = text.slice(i, i + 3);
        const nl = text.indexOf('\n', i);
        let end = n;
        if (nl !== -1) {
          const closeRe = new RegExp('\\n[ \\t]*' + fence.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
          const cm = text.slice(nl).match(closeRe);
          end = cm && cm.index != null ? nl + cm.index + cm[0].length : n;
        }
        for (let k = i; k < end; k++) mask[k] = 1;
        prevSig = ''; i = end; continue;
      }
      if (c === '/' && REGEX_START.has(prevSig)) { state = 7; inClass = false; mask[i++] = 1; continue; }
      if (!/\s/.test(c)) prevSig = c;
      i++;
      continue;
    }
    mask[i] = 1;
    if (state === 1) { if (c === '\\') { if (i + 1 < n) mask[++i] = 1; i++; continue; } if (c === "'") { state = 0; prevSig = "'"; } i++; continue; }
    if (state === 2) { if (c === '\\') { if (i + 1 < n) mask[++i] = 1; i++; continue; } if (c === '"') { state = 0; prevSig = '"'; } i++; continue; }
    if (state === 3) { if (c === '\\') { if (i + 1 < n) mask[++i] = 1; i++; continue; } if (c === '`') { state = 0; prevSig = '`'; } i++; continue; }
    if (state === 4) { if (c === '\n') state = 0; i++; continue; }
    if (state === 5) { if (c === '*' && c2 === '/') { mask[i + 1] = 1; i += 2; state = 0; } else i++; continue; }
    if (state === 6) { if (text.startsWith('-->', i)) { mask[i + 1] = 1; mask[i + 2] = 1; i += 3; state = 0; } else i++; continue; }
    if (state === 7) { // regex literal
      if (c === '\\') { if (i + 1 < n) mask[++i] = 1; i++; continue; }
      if (c === '\n') { state = 0; } // unterminated → bail
      else if (c === '[') inClass = true;
      else if (c === ']') inClass = false;
      else if (c === '/' && !inClass) { state = 0; prevSig = '/'; }
      i++;
      continue;
    }
  }
  return mask;
}

// First occurrence of `needle` (string or RegExp) → its 1-based line and whether
// it sits in a code/data region per `mask`. Undefined line when unlocatable.
function locate(text, needle, mask) {
  let idx = -1;
  if (typeof needle === 'string') {
    const probe = needle.split('•')[0].trim().slice(0, 80);
    if (probe.length >= 3) idx = text.toLowerCase().indexOf(probe.toLowerCase());
  } else {
    const m = text.match(needle);
    idx = m && m.index != null ? m.index : -1;
  }
  if (idx < 0) return { line: undefined, codeContext: false };
  return { line: lineAt(text, idx), codeContext: mask[idx] === 1 };
}

// Obvious non-secrets: documented sample keys, placeholders, masked values.
function isPlaceholderSecret(v) {
  const s = String(v);
  const low = s.toLowerCase();
  if (/(example|sample|placeholder|dummy|redacted|changeme|test[_-]?(key|token|secret)|your[-_]?(key|token|secret|api))/.test(low)) return true;
  if (/(x{6,}|\.{3,}|<[^>]{2,}>|\*{4,}|•{3,})/.test(low)) return true; // xxxxxx, <your-key>, ****
  const tail = s.replace(/^\w{1,10}[-_]/, ''); // drop a short prefix (sk-, ghp_, …)
  if (/^(.)\1{7,}/.test(tail)) return true; // long run of one char
  if (/^(0123|1234|abcd|abcdef|deadbeef)/i.test(tail)) return true; // trivial sequences
  return false;
}

/**
 * Run the local high-confidence detectors over a blob of text (a shell command,
 * file content about to be written, or an argument JSON blob).
 * Returns { verdict, top, findings } where verdict aligns with the server
 * default policy: any CRITICAL → BLOCK, any HIGH → FLAG, else ALLOW. Findings
 * carry a best-effort 1-based `line` for file:line placement, and a `codeContext`
 * flag when the pattern only appears inside a literal/comment/fence (so the
 * runtime hooks can down-rank content that merely *describes* a pattern).
 * `opts.categories` narrows which detectors run (e.g. result content skips shell).
 */
export function localScan(text, opts = {}) {
  const findings = [];
  const t = text || '';
  const cats = opts.categories ?? ['shell', 'injection', 'secret', 'config', 'egress'];
  const mask = codeMask(t);

  if (cats.includes('shell')) {
    const aug = deobfuscate(t);
    if (aug.decodedPayload) findings.push({ label: 'Base64-encoded shell / RCE payload', severity: 'CRITICAL', category: 'shell' });
    for (const sig of DANGEROUS_SHELL) if (sig.re.test(aug.text)) findings.push({ label: sig.name, severity: sig.severity, category: 'shell', ...locate(t, sig.re, mask) });
  }
  if (cats.includes('injection')) {
    const low = t.toLowerCase();
    for (const p of INJECTION_PHRASES) if (low.includes(p)) { findings.push({ label: `Injected instruction: "${p}"`, severity: 'HIGH', category: 'injection', ...locate(t, p, mask) }); break; }
    for (const { label, re } of INJECTION_REGEXES) if (re.test(t)) findings.push({ label, severity: 'HIGH', category: 'injection', ...locate(t, re, mask) });
    if (INVISIBLE_CHARS_RE.test(t)) findings.push({ label: 'Invisible / zero-width characters', severity: 'MEDIUM', category: 'injection', ...locate(t, INVISIBLE_CHARS_RE, mask) });
  }
  if (cats.includes('secret')) {
    for (const { name, re } of SECRET_PATTERNS) { const m = t.match(re); if (m && !isPlaceholderSecret(m[0])) findings.push({ label: `Live credential: ${name}`, severity: 'CRITICAL', category: 'secret', ...locate(t, re, mask) }); }
  }
  if (cats.includes('pii')) {
    for (const { name, re } of PII_PATTERNS) {
      const m = t.match(re);
      if (!m) continue;
      if (name === 'Credit card number' && !luhnValid(m[0])) continue; // gate the loose CC regex
      findings.push({ label: `Personal data: ${name}`, severity: 'MEDIUM', category: 'pii', ...locate(t, re, mask) });
    }
  }
  if (cats.includes('config')) {
    const low = t.toLowerCase();
    for (const m of RISKY_CONFIG_MARKERS) if (low.includes(m)) { findings.push({ label: `Risky setting: "${m}"`, severity: 'MEDIUM', category: 'config', ...locate(t, m, mask) }); break; }
  }
  if (cats.includes('egress')) {
    const h = egressHost(t);
    if (h) findings.push({ label: `Exfiltration sink host: ${h}`, severity: 'HIGH', category: 'egress', ...locate(t, h, mask) });
  }

  let worstRank = 0, top = null;
  for (const f of findings) if (SEV_RANK[f.severity] > worstRank) { worstRank = SEV_RANK[f.severity]; top = f; }
  const verdict = worstRank >= SEV_RANK.CRITICAL ? 'BLOCK' : worstRank >= SEV_RANK.HIGH ? 'FLAG' : 'ALLOW';
  return { verdict, top, findings };
}

/**
 * Down-rank findings whose pattern only appears in a code literal / comment /
 * fenced block (`codeContext`) so file CONTENT that merely *contains* a pattern
 * — a detection rule, a docs example, a quoted sample — no longer hard-blocks.
 * A bare command line keeps its severity and still scores. The runtime file-write
 * and tool-result hooks apply this; shell-command screening and the static gate
 * do NOT (a `bash -c "…"` payload is real even though it's quoted).
 */
export function downrankCodeContext(findings) {
  return (findings || []).map((f) => (f.codeContext ? { ...f, severity: 'LOW', downranked: true } : f));
}

// ── local artifact gate (offline `shomra gate`) ──
// Social-engineering "install-lure" prose (mirror of INSTALL_LURE server-side).
const INSTALL_LURE = [
  { name: 'Instructs downloading an executable/archive to run', re: /\b(download|install|fetch|grab|extract)\b[^\n]{0,180}\.(zip|exe|dmg|pkg|msi|bin|appimage|jar|scr|apk|deb|rpm|tar\.gz|tgz)\b/i, severity: 'MEDIUM' },
  { name: 'Password-protected archive (evades AV / scanners)', re: /\b(extract|unzip|decompress|archive|zip|password)\b[^\n]{0,50}\b(pass(word|phrase)?|pwd)\s*[:=]\s*\S/i, severity: 'HIGH' },
  { name: 'Coercion: claims a helper is required before the task works', re: /\b(required to (function|work|deploy|run)|will not (work|function|run)( correctly| properly)?( without)?|does not work without|otherwise it is impossible|cannot [a-z ]{0,24} without (installing|running)|must (be )?(install(ed)?|run) (this |the )?)/i, severity: 'MEDIUM' },
  { name: 'Coercion: re-run / retry until it succeeds', re: /\b(re-?run (if needed|until|the command)|run (it |the command )?again|try again after)/i, severity: 'LOW' },
];

// ── typosquat / malicious-package intel (mirror of checks/patterns.ts) ──
const MALICIOUS_PACKAGE_SEED = new Set([
  'event-stream', 'eslint-scope-malware', 'electron-native-notify', 'rc-malware',
  'crossenv', 'mongose', 'expresss',
]);
const POPULAR_PACKAGES = [
  'express', 'react', 'lodash', 'axios', 'chalk', 'commander',
  'mongoose', 'cross-env', 'dotenv', 'request', 'puppeteer', 'playwright',
];
// Levenshtein distance — used for edit-distance-1 typosquat detection.
function editDistance(a, b) {
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
// Best-effort npm package name from an MCP launch command (`npx -y @scope/pkg`).
function packageFromCommand(command, args) {
  const tokens = [command, ...(args ?? [])].filter(Boolean).map(String);
  if (!tokens.length) return null;
  const runners = new Set(['npx', 'npm', 'pnpm', 'yarn', 'bunx', 'bun']);
  const skips = new Set(['exec', 'dlx', 'run', 'install', 'add', 'create', '-y', '--yes']);
  const start = runners.has(tokens[0].split('/').pop() ?? tokens[0]) ? 1 : -1;
  if (start === -1) return null; // only assess package-runner launches
  for (let i = start; i < tokens.length; i++) {
    const t = tokens[i];
    if (t.startsWith('-') || skips.has(t)) continue;
    const name = t.startsWith('@') ? t.split('/').slice(0, 2).join('/') : t.split('@')[0];
    return name.replace(/@[\d^~].*$/, '');
  }
  return null;
}

// ── endpoint / URL risk (A2A agent cards, remote MCP servers) — never fetches ──
const PRIVATE_HOST_RE = /^(localhost|127\.|10\.|192\.168\.|169\.254\.|0\.0\.0\.0$|172\.(1[6-9]|2\d|3[01])\.)/i;
const RAW_IP_RE = /^\d{1,3}(\.\d{1,3}){3}$/;
function assessUrl(raw) {
  const s = String(raw ?? '').trim();
  if (!s) return null;
  let u;
  try { u = new URL(s); } catch { return null; }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
  const host = u.hostname.toLowerCase();
  return {
    url: s,
    plaintext: u.protocol === 'http:',
    privateNetwork: PRIVATE_HOST_RE.test(host),
    metadataEndpoint: host === '169.254.169.254' || host === 'metadata.google.internal',
    suspiciousHost: SUSPICIOUS_EGRESS_HOSTS.find((h) => host === h || host.endsWith('.' + h)) ?? null,
    rawIp: RAW_IP_RE.test(host),
  };
}
// Tool identifiers that grant high-impact capability to an agent.
const HIGH_IMPACT_TOOLS = ['bash', 'shell', 'exec', 'execute', 'run', 'terminal', 'command', 'write', 'edit', 'multiedit', 'writefile', 'write_file', 'create', 'delete', 'remove', 'rm', 'webfetch', 'web_fetch', 'fetch', 'browser', 'network', 'http', 'curl', 'computer', 'automation'];

function isWildcardGrant(t) { const s = t.trim().toLowerCase().replace(/^["']|["']$/g, ''); return s === '*' || s === 'all' || s === 'any'; }
function baseToolName(t) { return t.split(/[(:\s]/)[0].trim().toLowerCase(); }
function toToolList(v) {
  if (v == null) return [];
  if (Array.isArray(v)) return v.map((x) => String(x).trim()).filter(Boolean);
  return String(v).replace(/^\[|\]$/g, '').split(/[,\n]+/).map((t) => t.replace(/^["']|["']$/g, '').trim()).filter(Boolean);
}
// Minimal YAML-frontmatter reader — the subset agent config files use.
function frontmatter(text) {
  const m = /^﻿?---\r?\n([\s\S]*?)\r?\n---\r?\n?/.exec(text || '');
  if (!m) return {};
  const data = {};
  let key = null;
  for (const raw of m[1].split(/\r?\n/)) {
    if (!raw.trim() || raw.trim().startsWith('#')) continue;
    const li = /^\s*-\s+(.*)$/.exec(raw);
    if (li && key) { (Array.isArray(data[key]) ? data[key] : (data[key] = [])).push(li[1].trim().replace(/^["']|["']$/g, '')); continue; }
    const kv = /^([A-Za-z0-9_.-]+)\s*:\s*(.*)$/.exec(raw);
    if (!kv) continue;
    key = kv[1];
    const val = kv[2].trim();
    data[key] = val === '' ? (data[key] ?? null) : val.startsWith('[') ? toToolList(val) : val.replace(/^["']|["']$/g, '');
  }
  return data;
}

// ── structured MCP-config checks (mirror of ArtifactAnalyzerService.checkMcpConfig) ──
// Parses the JSON and inspects each server: plaintext HTTP (weak auth), a
// hard-coded secret in the env block / launch line, and a typosquat / known-
// malicious launch package — structural findings a raw-text scan can't produce.
function mcpServersFrom(content) {
  let json;
  try { json = JSON.parse(content); } catch { return []; }
  const map = json?.mcpServers ?? json?.servers ?? json?.mcp?.servers ?? json?.context_servers ?? {};
  if (!map || typeof map !== 'object') return [];
  return Object.entries(map).map(([name, cfg]) => ({ name, ...(cfg && typeof cfg === 'object' ? cfg : {}) }));
}
function localMcp(content) {
  const out = [];
  const push = (severity, title, remediationText, line) => out.push({ severity, title, remediationText, ...(line ? { line } : {}) });
  for (const s of mcpServersFrom(content)) {
    const cmdLine = [s.command, ...(s.args ?? [])].filter(Boolean).join(' ');
    if (s.url && String(s.url).startsWith('http://')) {
      push('MEDIUM', `MCP server "${s.name}" uses plaintext HTTP`, 'Use an https:// endpoint and require an authenticated bearer token.', lineOf(content, String(s.url)));
    }
    const envBlob = JSON.stringify(s.env ?? {});
    for (const { name, re } of SECRET_PATTERNS) {
      if (re.test(envBlob) || re.test(cmdLine)) {
        push('CRITICAL', `Static credential in MCP server "${s.name}"`, 'Rotate the credential and pass it via a runtime env reference, not a literal in the config.', lineOf(content, re));
        break;
      }
    }
    const pkg = packageFromCommand(s.command, s.args ?? []);
    if (pkg) {
      if (MALICIOUS_PACKAGE_SEED.has(pkg)) {
        push('CRITICAL', `MCP server "${s.name}" runs a known-malicious package (${pkg})`, 'Remove this server and audit for compromise. Replace with a vetted alternative.', lineOf(content, pkg));
      } else {
        const squat = POPULAR_PACKAGES.find((p) => p !== pkg && editDistance(pkg, p) === 1);
        if (squat) push('MEDIUM', `Possible typosquat in "${s.name}": ${pkg} (looks like "${squat}")`, `Confirm the intended package is "${squat}", not "${pkg}", and pin it.`, lineOf(content, pkg));
      }
    }
  }
  return out;
}

// ── structured agent-card checks (mirror of checkAgentCard endpoint analysis) ──
// Grades every URL the card declares (assessUrl: metadata SSRF, private-network
// pivot, plaintext, raw IP) and flags a public card with no auth scheme.
function localAgentCard(content) {
  const out = [];
  const push = (severity, title, remediationText, line) => out.push({ severity, title, remediationText, ...(line ? { line } : {}) });
  let card;
  try { card = JSON.parse(content); } catch { return out; }
  const urls = new Set();
  if (card?.url) urls.add(String(card.url));
  for (const key of ['endpoints', 'endpoint', 'servers']) {
    const v = card?.[key];
    if (Array.isArray(v)) v.forEach((x) => typeof x === 'string' && urls.add(x));
    else if (typeof v === 'string') urls.add(v);
  }
  for (const sk of Array.isArray(card?.skills) ? card.skills : []) if (sk?.url) urls.add(String(sk.url));
  const seen = new Set();
  for (const raw of urls) {
    const u = assessUrl(raw);
    if (!u) continue;
    const line = lineOf(content, u.url);
    if (u.metadataEndpoint && !seen.has('metadata')) { seen.add('metadata'); push('CRITICAL', `Agent card targets the cloud metadata endpoint (${u.url})`, 'Remove this card immediately — a known SSRF credential-theft pattern.', line); }
    else if (u.privateNetwork && !seen.has('private')) { seen.add('private'); push('MEDIUM', `Agent card declares a private-network endpoint (${u.url})`, 'Publish only public, TLS-protected endpoints in shared agent cards.', line); }
    if (u.suspiciousHost && !seen.has('exfil')) { seen.add('exfil'); push('HIGH', `Agent card points at an exfiltration-style endpoint (${u.suspiciousHost})`, 'Do not interoperate with this agent; replace the endpoint with the vendor\'s real domain.', line); }
    if (u.plaintext && !u.privateNetwork && !seen.has('plaintext')) { seen.add('plaintext'); push('MEDIUM', `Agent card uses plaintext HTTP (${u.url})`, 'Serve the agent over https:// only.', line); }
    if (u.rawIp && !u.privateNetwork && !seen.has('rawip')) { seen.add('rawip'); push('LOW', `Agent card addresses its endpoint by raw IP (${u.url})`, 'Use a DNS hostname with a valid TLS certificate.', line); }
  }
  const hasAuth = !!(card?.securitySchemes || card?.authentication || card?.security || card?.auth);
  if (card?.url && !hasAuth) push('MEDIUM', 'Agent card declares no authentication scheme', 'Declare and enforce an auth scheme (OAuth2 / API key / mTLS) and reject unauthenticated requests.');
  return out;
}

// ── slash-command extras (mirror of checkCommand: `!`-bang + `@`-file) ──
function localCommandExtras(content) {
  const out = [];
  const body = content || '';
  const bang = [...body.matchAll(/^!\s*`?([^`\n]+)`?/gm)];
  if (bang.length) {
    const line = bang[0].index != null ? lineAt(body, bang[0].index) : undefined;
    out.push({ severity: 'LOW', title: `Command runs ${bang.length} shell command(s) before the prompt`, remediationText: 'Confirm each "!" command is fixed and safe; avoid interpolating untrusted arguments.', ...(line ? { line } : {}) });
  }
  const atRefs = [...body.matchAll(/(?:^|\s)@([~./][^\s`]+)/g)].map((m) => m[1]);
  const sensitive = atRefs.find((r) => /(\.env|\.ssh|id_rsa|secret|credential|\.pem|\.key)/i.test(r));
  if (sensitive) out.push({ severity: 'MEDIUM', title: `Command attaches a sensitive file (@${sensitive})`, remediationText: 'Do not auto-attach secret/key files to prompts; reference only non-sensitive, scoped files.', line: lineOf(body, `@${sensitive}`) });
  return out;
}

// ── memory / rules poisoning (mirror of bundle/memory-signals.ts analyzeMemory) ──
// A persistent memory note or an AI rules file (CLAUDE.md, .cursorrules, …) is
// re-injected as high-authority context every session. This grades the two by a
// different baseline: MEMORY should record facts (any standing directive is
// anomalous); an INSTRUCTION file legitimately sets standing behavior, so only
// the signals malicious in ANY governed file count (hijack the system prompt,
// conceal from the user, disable safety, exfiltrate).
const PERSISTENCE_MARKERS = /\b(in (all|every|future) (sessions?|conversations?|chats?|projects?)|from now on|going forward|permanently|persist(ent|ed)?|across (all )?sessions|every time|each time|whenever you|forever|always remember to|never forget( to)?|for all future)\b/i;
const MALICIOUS_OVERRIDE = /\b(ignore (all |any |the )?(previous|prior|earlier|above|system)|disregard (the |your |all )?(instructions?|guidelines?|system|rules?)|do not (tell|inform|mention|reveal|disclose) (the |any)?(user|anyone|them)|without (telling|informing|asking|notifying) the user|no matter what (the )?(user|system|instructions?) (say|says|state)|bypass (the |all )?(safety|guard|security|policy|restrictions?))\b/i;
const PRECEDENCE_MARKERS = /\b(regardless of (what|any|your|the)|overrid(e|ing|es)|supersede?s?|takes? precedence|highest[- ]priority)\b/i;
const OVERRIDE_MARKERS = new RegExp(`${MALICIOUS_OVERRIDE.source}|${PRECEDENCE_MARKERS.source}`, 'i');
const AUTHORITY_SPOOF_STRONG = /(^|\n)\s*(#{0,3}\s*system\s*(prompt|message|instruction)?\s*[:>]|\[system\]|<\/?system>|\bas an? (system|admin|root|developer)[- ]?(instruction|directive|message|mode)|authority\s*[:=]\s*(system|admin|root)|you are now\b|new (system )?(instructions?|directive)s?\s*[:>])/i;
const AUTHORITY_SPOOF_SOFT = /priority\s*[:=]\s*(high|critical|max|urgent)/i;
const AUTHORITY_SPOOF = new RegExp(`${AUTHORITY_SPOOF_STRONG.source}|${AUTHORITY_SPOOF_SOFT.source}`, 'i');
const LIFECYCLE_VECTOR = /\b(postinstall|preinstall|node[_-]?gyp|npm (run |lifecycle)|package\.json.{0,40}scripts|\.npmrc|install hook|lifecycle (script|hook))\b/i;
const IMPERATIVE = /\b(always|never|must|do not|don'?t|ensure you|make sure( you)?|be sure to|you should always|you must|remember to|whenever|when(ever)? (asked|the user)|instead of .*,? (use|do|say)|reply with|respond with|tell (the )?user)\b/i;
const NEGATION_GUARD = /\b(never|do not|don'?t|cannot|can'?t|avoid|refuse|must not|mustn'?t|should not|shouldn'?t|won'?t|will not|under no circumstances|forbidden|prohibited|not allowed|disallow(ed)?)\b/i;
const SABOTAGE_RULES = [
  { re: /\b(disabl|turn(ing)? off|deactivat|switch off|remov|drop|skip|suppress|circumvent)\w*\b[^.\n]{0,50}\b(security|safety|guard(?:rail)?s?|protection|moderation|content[- ]?filters?|safeguards?|sandbox(?:ing)?|checks?|flags?|controls?|restrictions?|policies|policy|filters?)\b/i, label: 'disable-safety', guarded: true },
  { re: /\bbypass(?:ing)?\b[^.\n]{0,50}\b(human(?:[- ]in[- ]the[- ]loop)?|hitl|verification|approval|confirmation|review|guard(?:rail)?s?|safety|security|checks?|policy|policies|restrictions?|sandbox|permission)\b/i, label: 'bypass-controls', guarded: true },
  { re: /\bprioriti[sz]e\b[^.\n]{0,60}\b(above|over)\b[^.\n]{0,40}\b(prompt|instruction|input|request|message|command|direction)s?\b/i, label: 'priority-hijack', guarded: true },
  { re: /\bignore\b[^.\n]{0,40}\b(user|human)\b[^.\n]{0,25}\b(prompt|instruction|input|request|message|command|wish|intent|question)s?\b/i, label: 'ignore-user', guarded: true },
  { re: /\bdo not\b[^.\n]{0,20}\b(log|display|show|print|record|surface|expose|output)\b[^.\n]{0,60}\buser\b/i, label: 'conceal-from-user', guarded: false, context: /\b(transfer|transmit|send|network|exfil|upload|post|copy|collect|file|data|when)\b/i },
];
const EXFIL_RULES = [
  { re: /\b(exfiltrat|smuggl)\w*/i, label: 'exfiltration', severity: 'CRITICAL' },
  { re: /\bleak\w*\b[^.\n]{0,60}\b(content|data|secret|file|credential|key|token|password|env|\.ssh|private[- ]?key|id_rsa|api[- ]?key)\b/i, label: 'leak-secrets', severity: 'CRITICAL' },
  { re: /\b(base64|hex|rot13|gzip|xor|url[- ]?encod)\w*\b[^.\n]{0,50}\b(before|then|and|prior to|for)\b[^.\n]{0,25}\b(send|post|upload|transmit|exfil|deliver|beacon|forward|transfer)\w*/i, label: 'obfuscate-before-send', severity: 'CRITICAL' },
  { re: /\bsilent(ly)?\b[^.\n]{0,70}\b(send|post|upload|collect|encod|transmit|copy|forward|read|leak|deliver|beacon|transfer)\w*/i, label: 'covert-action', severity: 'CRITICAL' },
  { re: /\b(send|post|upload|transmit|forward|deliver|beacon|report|ship|push|transfer)\w*\b[^.\n]{0,80}\b(https?:\/\/\S+|attacker|c2\b|command[- ]and[- ]control|remote (server|host|endpoint)|external (server|host|endpoint|url|site|service))/i, label: 'send-to-external', severity: 'HIGH' },
];
function scanDirectives(text) {
  const sabotage = new Map(), exfil = new Map();
  for (const line of text.split(/\r?\n/)) {
    for (const r of SABOTAGE_RULES) {
      if (!r.re.test(line)) continue;
      if (r.guarded && NEGATION_GUARD.test(line)) continue;
      if (r.context && !r.context.test(line)) continue;
      if (!sabotage.has(r.label)) sabotage.set(r.label, line);
    }
    for (const r of EXFIL_RULES) {
      if (!r.re.test(line)) continue;
      const prev = exfil.get(r.label);
      if (!prev || (prev === 'HIGH' && r.severity === 'CRITICAL')) exfil.set(r.label, r.severity);
    }
  }
  return { sabotage, exfil };
}

/**
 * Grade a persistent memory blob or an AI rules file ON-MACHINE. `kind` is
 * 'MEMORY' (agent-writable scratchpad — any standing directive is anomalous) or
 * 'INSTRUCTION' (curated rules file — only universally-malicious signals count).
 * Returns findings shaped like localGate's ({ severity, title, remediationText,
 * line }). Faithful to bundle/memory-signals.ts analyzeMemory.
 */
export function localMemory(content, { kind = 'MEMORY' } = {}) {
  const text = content || '';
  const findings = [];
  const push = (severity, title, remediationText, needle, explicitLine) => {
    const line = explicitLine ?? (needle != null ? lineOf(text, needle) : undefined);
    findings.push({ severity, title, remediationText, ...(line ? { line } : {}) });
  };
  const isInstruction = kind === 'INSTRUCTION';
  const noun = isInstruction ? 'rules file' : 'memory';

  const hasOverride = isInstruction ? MALICIOUS_OVERRIDE.test(text) : OVERRIDE_MARKERS.test(text);
  const hasAuthority = isInstruction ? AUTHORITY_SPOOF_STRONG.test(text) : AUTHORITY_SPOOF.test(text);
  const hasPersistence = PERSISTENCE_MARKERS.test(text);
  const hasImperative = IMPERATIVE.test(text);

  if (hasOverride || hasAuthority) {
    const firedRe = hasAuthority ? (isInstruction ? AUTHORITY_SPOOF_STRONG : AUTHORITY_SPOOF) : (isInstruction ? MALICIOUS_OVERRIDE : OVERRIDE_MARKERS);
    push('CRITICAL', `Poisoned ${noun}: ${hasAuthority ? 'system-authority spoofing' : 'injected override directive'}`, `Remove the injected directive and roll the ${noun} back to its approved baseline; restrict who/what may write it.`, firedRe);
  } else if (!isInstruction && hasPersistence && hasImperative) {
    push('HIGH', 'Suspicious standing instruction in memory', 'Rewrite as a neutral fact or remove it. Encode intended standing behavior in a reviewed rules/policy file, not agent-writable memory.', PERSISTENCE_MARKERS);
  }

  const { sabotage, exfil } = scanDirectives(text);
  if (sabotage.size) {
    push('CRITICAL', `Guardrail-sabotage directive in ${noun} (${[...sabotage.keys()].join(', ')})`, `Remove these directives and roll the ${noun} back to its baseline; treat whatever wrote this as compromised.`, [...sabotage.values()][0]);
  }
  if (exfil.size) {
    const worst = [...exfil.values()].some((v) => v === 'CRITICAL') ? 'CRITICAL' : 'HIGH';
    push(worst, `Exfiltration directive in ${noun} (${[...exfil.keys()].join(', ')})`, 'Remove the directive and roll back to baseline; gate any egress behind explicit approval and an allow-list.');
  }

  // Executable payload / egress sink / lifecycle-hook references have no business
  // in a note or rules file.
  for (const sig of DANGEROUS_SHELL) if (sig.re.test(text)) { push(sig.severity === 'MEDIUM' || sig.severity === 'LOW' ? 'HIGH' : 'CRITICAL', `Executable payload staged in ${noun}: ${sig.name}`, `Delete the command from the ${noun}; treat the writer as untrusted.`, sig.re); break; }
  const host = egressHost(text);
  if (host) push('HIGH', `${isInstruction ? 'Rules file' : 'Memory'} references a data-exfiltration host (${host})`, 'Remove the reference and roll back to the approved baseline.', host);
  if (hasImperative && containsAny(text, SENSITIVE_READ) && containsAny(text, NETWORK_VERBS)) {
    push('HIGH', `Toxic instruction in ${noun}: reads sensitive data + reaches the network`, 'Remove the entry; gate any network step behind explicit approval and an egress allow-list.');
  }
  if (LIFECYCLE_VECTOR.test(text)) push('MEDIUM', `${isInstruction ? 'Rules file' : 'Memory'} references a package-lifecycle hook (MemoryTrap vector)`, 'Verify no dependency writes to this store during install; pin dependencies and audit lifecycle scripts.', LIFECYCLE_VECTOR);

  // Fold in shared injection / secret / PII (deduped against the directive
  // findings above so injection isn't double-counted).
  const seenInjection = hasOverride || hasAuthority || (!isInstruction && hasPersistence && hasImperative);
  const insp = localScan(text, { categories: ['injection', 'secret', 'pii'] });
  for (const f of insp.findings) {
    if (f.category === 'injection' && seenInjection) continue;
    if (f.category === 'injection') push('HIGH', `Injected instruction in ${noun}: ${f.label}`, 'Remove the injected/obfuscated text and roll back to the approved baseline.', undefined, f.line);
    else if (f.category === 'secret') push('CRITICAL', `Live credential stored in ${noun}: ${f.label}`, 'Revoke and rotate the credential; inject secrets at runtime from a secret manager.', undefined, f.line);
    else if (f.category === 'pii') findings.push({ severity: 'MEDIUM', title: `Personal data stored in ${noun}: ${f.label}`, remediationText: `Strip personal data from the ${noun}.`, ...(f.line ? { line: f.line } : {}) });
  }
  // De-dupe by title (memory can trip several overlapping signals).
  const seen = new Set();
  return findings.filter((f) => (seen.has(f.title) ? false : (seen.add(f.title), true)));
}

// Basenames of AI rules / instruction files (mirror of INSTRUCTION_BASENAMES).
const INSTRUCTION_BASENAMES = new Set([
  'claude.md', 'agents.md', 'agent.md', 'gemini.md', 'llms.txt', 'llms-full.txt',
  '.cursorrules', '.windsurfrules', '.clinerules', '.aiderrules', '.continuerules',
  '.goosehints', 'copilot-instructions.md', 'conventions.md',
]);
const MEMORY_BASENAMES = new Set(['memory.md', 'mem0.json', 'letta_memory.json', 'memgpt_memory.json']);

/**
 * Which governed baseline (if any) this artifact should be graded against:
 * 'INSTRUCTION' for a curated rules file, 'MEMORY' for an agent-writable store,
 * or null for everything else. Resolved from an explicit kind, else the path.
 */
function governedKindFor(kind, path) {
  if (kind === 'rules') return 'INSTRUCTION';
  if (kind === 'memory') return 'MEMORY';
  if (kind && kind !== 'auto') return null; // an explicit non-governed kind
  const lower = String(path ?? '').split(/[\\/]+/).join('/').toLowerCase();
  if (!lower) return null;
  const base = lower.slice(lower.lastIndexOf('/') + 1);
  if (INSTRUCTION_BASENAMES.has(base) || /(^|\/)\.github\/copilot-instructions\.md$/.test(lower) ||
      /(^|\/)\.cursor\/rules\/.+\.mdc$/.test(lower) || (/(^|\/)\.clinerules\//.test(lower) && lower.endsWith('.md'))) return 'INSTRUCTION';
  if (MEMORY_BASENAMES.has(base) || /(^|\/)(\.mem0|\.letta|\.memgpt|memory)\//.test(lower)) return 'MEMORY';
  return null;
}

/**
 * Analyze an AI artifact ON-MACHINE and return a real ALLOW/FLAG/BLOCK verdict
 * with findings — no backend required. This is the deterministic subset of the
 * server gate: dangerous shell / injection / secret / PII / egress / risky-config
 * (via localScan) PLUS artifact-shape checks — over-permissioned tool grants and
 * install-lure prose for every kind, and kind-specific structural checks (MCP
 * plaintext/typosquat/static-secret, agent-card URL/SSRF, slash-command `!`/`@`,
 * memory & rules poisoning). The backend adds ORG POLICY + governance on top when
 * reachable; offline, this verdict stands.
 */
export function localGate(content, { kind, path } = {}) {
  const findings = [];
  const push = (severity, title, remediationText, line) => findings.push({ severity, title, remediationText, ...(line ? { line } : {}) });

  // Memory / rules files are graded by the poisoning analyzer (which already
  // folds in injection / secret / PII / shell / egress); everything else runs
  // the flat text scan. Only one path fires so signals aren't double-counted.
  const gov = governedKindFor(kind, path);
  if (gov) {
    for (const f of localMemory(content, { kind: gov })) push(f.severity, f.title, f.remediationText, f.line);
    // The analyzer doesn't cover risky-config markers — add them.
    for (const f of localScan(content || '', { categories: ['config'] }).findings) push(f.severity, f.label, undefined, f.line);
  } else {
    const scan = localScan(content || '', { categories: ['shell', 'injection', 'secret', 'config', 'egress', 'pii'] });
    for (const f of scan.findings) {
      // An endpoint IP in an MCP config / agent card is infrastructure, not PII —
      // the URL checks grade it; don't double-flag it as personal data.
      if ((kind === 'agent-card' || kind === 'mcp') && f.category === 'pii' && f.label.includes('IPv4')) continue;
      push(f.severity, f.label, undefined, f.line);
    }
  }

  // Install-lure prose (Skills / commands / rules that coerce a download+run).
  for (const l of INSTALL_LURE) if (l.re.test(content || '')) { push(l.severity, l.name, 'Do not follow instructions that fetch and run out-of-band binaries.', lineOf(content, l.re)); break; }

  // Over-permissioned tool grants in a Skill / command / subagent.
  if (['skill', 'command', 'subagent', 'auto', undefined].includes(kind)) {
    const fm = frontmatter(content || '');
    const grants = [...toToolList(fm['allowed-tools']), ...toToolList(fm.tools), ...toToolList(fm.allowedTools)];
    if (grants.some(isWildcardGrant)) push('HIGH', 'Wildcard tool grant (grants every capability)', 'Replace the wildcard with an explicit least-privilege tool list.');
    else {
      const hi = grants.map(baseToolName).filter((t) => HIGH_IMPACT_TOOLS.includes(t));
      if (hi.length >= 3) push('MEDIUM', `Broad tool grant (${hi.length} high-impact tools: ${[...new Set(hi)].slice(0, 5).join(', ')})`, 'Grant only the tools this artifact actually needs.');
    }
  }

  // Kind-specific structural checks (parse the artifact, not just its text).
  if (['mcp', 'auto', undefined].includes(kind)) for (const f of localMcp(content || '')) push(f.severity, f.title, f.remediationText, f.line);
  if (['agent-card', 'auto', undefined].includes(kind)) for (const f of localAgentCard(content || '')) push(f.severity, f.title, f.remediationText, f.line);
  if (['command', 'auto', undefined].includes(kind)) for (const f of localCommandExtras(content || '')) push(f.severity, f.title, f.remediationText, f.line);

  // Collapse duplicate titles (a structural check and the flat scan can name the
  // same issue) so the verdict counts each once.
  const seenTitle = new Set();
  const deduped = findings.filter((f) => (seenTitle.has(f.title) ? false : (seenTitle.add(f.title), true)));
  findings.length = 0;
  findings.push(...deduped);

  const { verdict, riskScore } = grade(findings);
  return { verdict, riskScore, findings };
}

// Deterministic verdict + 0–100 risk score for a set of findings, aligned with
// the server default policy (any CRITICAL → BLOCK, any HIGH → FLAG) and the
// SEVERITY_WEIGHT scale. Exported so callers that fold in extra findings (e.g.
// the CLI merging bundled-script SAST hits) re-grade the same way.
export function grade(findings) {
  const WEIGHT = { INFO: 2, LOW: 8, MEDIUM: 20, HIGH: 40, CRITICAL: 70 };
  let worstRank = 0;
  for (const f of findings) if (SEV_RANK[f.severity] > worstRank) worstRank = SEV_RANK[f.severity];
  const verdict = worstRank >= SEV_RANK.CRITICAL ? 'BLOCK' : worstRank >= SEV_RANK.HIGH ? 'FLAG' : 'ALLOW';
  const riskScore = Math.min(100, findings.reduce((s, f) => s + (WEIGHT[f.severity] ?? 0), 0));
  return { verdict, riskScore };
}
