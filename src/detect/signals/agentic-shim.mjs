import { assessUrl } from './egress.mjs';
import { lineOf } from './lines.mjs';
import { describesAt, prohibitsAt } from './prose-context.mjs';
import { localScan } from './scan.mjs';

export { describesAt, prohibitsAt };

const signalFinding = (f, where) => ({
  class: f.category === 'egress' ? 'TOXIC_FLOW' : 'INSECURE_CONFIG',
  severity: f.severity,
  title: `${where} ${f.category === 'egress' ? 'sends data to an exfiltration host' : 'runs a dangerous command'}`,
  detail: `${f.label} in ${where}.`,
  remediationText: 'Remove the command or destination, or move the node to an isolated sandbox with no credentials.',
  remediationTier: 1,
  evidence: { signal: f.label },
});

export function shellFindings(artifact, text, where) {
  return localScan(String(text ?? ''), { categories: ['shell'] }).findings.map((f) => signalFinding(f, where));
}

export function egressFindings(artifact, text, where) {
  return localScan(String(text ?? ''), { categories: ['egress'] }).findings.map((f) => signalFinding(f, where));
}

export function codeFindings() {
  return [];
}

export function ssrfFindings(artifact, url, where) {
  const u = assessUrl(url);
  if (!u || !(u.metadataEndpoint || u.privateNetwork || u.rawIp)) return [];
  return [{
    class: 'INSECURE_CONFIG',
    severity: u.metadataEndpoint ? 'HIGH' : 'MEDIUM',
    title: `${where} calls ${u.metadataEndpoint ? 'a cloud metadata endpoint' : 'an internal address'}`,
    detail: `${u.url} is reachable from the flow server's network position, so whoever can steer the node can read what that address serves.`,
    remediationText: 'Point the node at a public, allow-listed host, or block internal ranges at the flow server.',
    remediationTier: 2,
    evidence: { url: u.url },
  }];
}

export function locate(needle, ...texts) {
  for (const t of texts) {
    const line = lineOf(t ?? '', needle);
    if (line) return { line };
  }
  return {};
}

const RANK = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

export function textFindings(artifact, text, injectionClass = 'PROMPT_INJECTION', opts = {}) {
  const { findings } = localScan(String(text ?? ''), { categories: opts.injection === false ? ['secret'] : ['injection', 'secret'] });
  const out = [];
  const injection = findings.filter((f) => f.category === 'injection');
  if (injection.length) {
    const primary = injection.reduce((w, f) => (RANK[f.severity] > RANK[w.severity] ? f : w));
    out.push({
      class: injectionClass,
      severity: primary.severity,
      title: `Injected instruction in "${artifact?.name ?? 'artifact'}"`,
      detail: `${injection.map((f) => f.label).join('; ')}.`,
      remediationText: 'Remove the injected text and restrict who can edit this file.',
      remediationTier: 1,
      evidence: { signals: injection.map((f) => f.label), ...(primary.line ? { line: primary.line } : {}) },
    });
  }
  for (const f of findings.filter((x) => x.category === 'secret')) {
    out.push({
      class: 'SECRET_EXPOSURE',
      severity: 'CRITICAL',
      title: `Credential in "${artifact?.name ?? 'artifact'}" - ${f.label}`,
      detail: `A ${f.label} appears in this file.`,
      remediationText: 'Rotate the credential and read it from the environment or a secret store.',
      remediationTier: 1,
      evidence: { secret: f.label, ...(f.line ? { line: f.line } : {}) },
    });
  }
  return out;
}
