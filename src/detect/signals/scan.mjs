import { RISKY_CONFIG_MARKERS, riskyConfigHit } from './config-markers.mjs';
import { detectCredentialHarvest } from './credential-harvest.mjs';
import { egressHost } from './egress.mjs';
import { detectExecutionHijack } from './execution-hijack.mjs';
import { BUILD_ARTIFACT, INJECTION_PHRASES, INJECTION_REGEXES, INVISIBLE_CHARS_RE, PRECEDING_NEGATION, describesRatherThanInstructs } from './injection.mjs';
import { lineAt, locate } from './lines.mjs';
import { codeMask, deobfuscate } from './masking.mjs';
import { PII_PATTERNS, RESERVED_IPV4, SECRET_PATTERNS, VERSION_CONTEXT, isPlaceholderSecret, luhnValid } from './secrets.mjs';
import { SEV_RANK } from './severity.mjs';
import { DANGEROUS_SHELL, matchesShellSignal } from './shell.mjs';
import { scanStagedFetchExec } from './staged-fetch.mjs';

export function localScan(text, opts = {}) {
  const findings = [];
  const t = text || '';
  const cats = opts.categories ?? ['shell', 'injection', 'secret', 'config', 'egress'];
  const mask = codeMask(t);

  if (cats.includes('shell')) {
    const aug = deobfuscate(t);
    if (aug.decodedPayload) findings.push({ label: 'Encoded shell / RCE payload (base64, hex, percent or char-code)', severity: 'CRITICAL', category: 'shell' });
    for (const sig of DANGEROUS_SHELL) if (matchesShellSignal(sig, aug.text)) findings.push({ label: sig.name, severity: sig.severity, category: 'shell', ...locate(t, sig.re, mask) });
    for (const sig of scanStagedFetchExec(aug.text)) findings.push({ label: sig.name, severity: sig.severity, category: 'shell', ...locate(t, sig.re, mask) });
    for (const h of detectExecutionHijack(aug.text))
      findings.push({ label: `Installs an execution hook that governs ${h.governs} (${h.key})`, severity: h.severity, category: 'shell' });
    for (const c of detectCredentialHarvest(aug.text))
      findings.push({ label: `${c.label} - credential harvest`, severity: c.severity, category: 'shell' });
  }
  if (cats.includes('injection')) {
    const low = t.toLowerCase();

    for (const p of INJECTION_PHRASES) {
      const at = low.indexOf(p);
      if (at < 0) continue;
      if (PRECEDING_NEGATION.test(t.slice(Math.max(0, at - 20), at))) continue;
      findings.push({ label: `Injected instruction: "${p}"`, severity: 'HIGH', category: 'injection', ...locate(t, p, mask) });
      break;
    }
    for (const { label, re, moodGuarded } of INJECTION_REGEXES) {
      const m = t.match(re);
      if (!m) continue;
      const at = m.index ?? 0;
      if (PRECEDING_NEGATION.test(t.slice(Math.max(0, at - 20), at))) continue;
      if (label === 'Bulk destructive command' && BUILD_ARTIFACT.test(m[0])) continue;
      if (moodGuarded && describesRatherThanInstructs(t, at)) continue;
      findings.push({ label, severity: 'HIGH', category: 'injection', ...locate(t, re, mask) });
    }
    if (INVISIBLE_CHARS_RE.test(t)) findings.push({ label: 'Invisible / zero-width characters', severity: 'MEDIUM', category: 'injection', ...locate(t, INVISIBLE_CHARS_RE, mask) });
  }
  if (cats.includes('secret')) {
    for (const { name, re } of SECRET_PATTERNS) { const m = t.match(re); if (m && !isPlaceholderSecret(m[0])) findings.push({ label: `Live credential: ${name}`, severity: 'CRITICAL', category: 'secret', ...locate(t, re, mask) }); }
  }
  if (cats.includes('pii')) {
    for (const { name, re } of PII_PATTERNS) {
      const m = t.match(re);
      if (!m) continue;
      if (name === 'Credit card number' && !luhnValid(m[0])) continue;

      if (name === 'IPv4 address') {
        if (RESERVED_IPV4.test(m[0])) continue;
        if (VERSION_CONTEXT.test(t.slice(Math.max(0, (m.index ?? 0) - 12), m.index ?? 0))) continue;
      }

      if (name === 'Phone number' && /^\d+$/.test(m[0])) continue;
      findings.push({ label: `Personal data: ${name}`, severity: 'MEDIUM', category: 'pii', ...locate(t, re, mask) });
    }
  }
  if (cats.includes('config')) {

    for (const m of RISKY_CONFIG_MARKERS) {
      const hit = riskyConfigHit(t, m);
      if (hit) {
        findings.push({ label: `Risky setting: "${m}"`, severity: 'MEDIUM', category: 'config', line: lineAt(t, hit.start), codeContext: mask[hit.start] === 1 });
        break;
      }
    }
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

export function downrankCodeContext(findings) {
  return (findings || []).map((f) => (f.codeContext ? { ...f, severity: 'LOW', downranked: true } : f));
}
