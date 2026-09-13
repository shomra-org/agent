import { lineOf } from './lines.mjs';
import { gradeModelConfig, modelConfigFormat } from './model-config-rules.mjs';
import { extractChatTemplates, isChatTemplateFile, scanChatTemplate } from './chat-template.mjs';

const MODELFILE_RE = /^(?:.*\.)?modelfile$/i;
const base = (p) => String(p ?? '').replace(/\\/g, '/').split('/').pop() ?? '';

export function isModelConfigPath(path, content) {
  const b = base(path);
  if (MODELFILE_RE.test(b) || isChatTemplateFile(b)) return true;
  return modelConfigFormat(path, content ?? 'x') !== null;
}

const SENSITIVE_LOCAL = /(?:^|[\\/])(?:\.ssh|\.aws|\.gnupg|\.kube|\.docker|\.config[\\/]gcloud|\.netrc|\.git-credentials|\.env)(?:[\\/]|$)|^\/(?:etc|root|proc|sys)(?:\/|$)|id_(?:rsa|ed25519|ecdsa|dsa)\b|shadow$|passwd$|\.pem$|\.key$/i;
const localRef = (r) => /^(?:\/|~|\.{1,2}[\\/]|[A-Za-z]:[\\/])/.test(r);

function modelfileFindings(content, name) {
  const out = [];
  const push = (severity, title, remediationText, needle) => out.push({ severity, title, remediationText, needle });
  const from = content.match(/^\s*FROM\s+(\S+)/im)?.[1] ?? null;
  const adapters = [...content.matchAll(/^\s*ADAPTER\s+(\S+)/gim)].map((m) => m[1]).slice(0, 10);
  const tmpl = content.match(/^\s*TEMPLATE\s+(?:"""([\s\S]*?)"""|(.*))$/im);
  const template = tmpl ? (tmpl[1] ?? tmpl[2] ?? '').trim() : '';

  for (const h of template ? scanChatTemplate(template, name, { sink: 'TEMPLATE', renderer: 'Ollama' }) : []) push(h.severity, h.title, h.remediation, 'TEMPLATE');

  for (const ref of [from, ...adapters].filter((x) => x && localRef(x))) {
    const dev = /^\/dev\//.test(ref);
    if (!dev && !SENSITIVE_LOCAL.test(ref) && !/(?:^|[\\/])\.\.(?:[\\/]|$)/.test(ref)) continue;
    push(dev ? 'MEDIUM' : SENSITIVE_LOCAL.test(ref) ? 'HIGH' : 'MEDIUM',
      dev ? `Model "${name}" reads a device file as weights (${ref})` : `Model "${name}" bundles a local file from outside the model directory (${ref})`,
      'Reference weights/adapters inside the model directory only, and run Ollama 0.1.34+.', ref);
  }
  if (from && !localRef(from)) {
    const remote = /^https?:\/\//i.test(from);
    const host = /^([a-z0-9-]+(?:\.[a-z0-9-]+)+(?::\d+)?)\//i.exec(from)?.[1] ?? null;
    if (host && !remote && !/^(?:registry\.ollama\.ai|ollama\.com|hf\.co|huggingface\.co)$/i.test(host)) push('MEDIUM', `Model "${name}" is pulled from a third-party registry (${host})`, 'Pull from a registry you control or trust, pinned by digest.', from);
    if (remote) push('HIGH', `Model "${name}" is built from weights fetched over the network`, 'Reference a registry model by name and digest, or vendor the weights and pin them by hash.', from);
    else if (!/@sha256[:-][0-9a-f]{12,}/i.test(from) && !(/:[\w.-]+$/.test(from) && !/:latest$/i.test(from))) push('LOW', `Model "${name}" is built from an unpinned base`, 'Pin the base to an explicit version or digest and update it deliberately.', from);
  }
  if (adapters.length) push('MEDIUM', `Model "${name}" applies a fine-tuning adapter`, 'Pin the adapter by digest, record who trained it and on what data, and re-evaluate the composed model.', adapters[0]);
  return out;
}

export function localModelConfig(content, { path } = {}) {
  const text = String(content ?? '');
  if (!text.trim()) return [];
  const name = base(path) || 'model-config';
  const rows = [];
  if (MODELFILE_RE.test(name) && /^\s*FROM\s+\S+/im.test(text)) rows.push(...modelfileFindings(text, name));
  else {
    for (const f of gradeModelConfig(path ?? name, text)) rows.push({ severity: f.severity, title: f.title, remediationText: f.remediation, needle: f.anchor });
    for (const t of extractChatTemplates(text, path ?? name)) {
      for (const h of scanChatTemplate(t.text, name, { sink: t.name })) rows.push({ severity: h.severity, title: h.title, remediationText: h.remediation, needle: t.name });
    }
  }
  return rows.map(({ needle, ...r }) => {
    const line = needle ? lineOf(text, needle) : undefined;
    return { ...r, ...(line ? { line } : {}) };
  });
}
