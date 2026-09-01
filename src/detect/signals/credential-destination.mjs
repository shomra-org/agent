import { SUSPICIOUS_EGRESS_HOSTS } from './egress.mjs';

export const CREDENTIAL_ISSUERS = [
  { issuer: 'GitHub', labels: ['GitHub token', 'GitHub fine-grained PAT', 'GitHub OAuth / refresh / server token'], hosts: ['github.com', 'githubusercontent.com', 'ghcr.io', 'githubapp.com'], nameTokens: ['github', 'ghcr'] },
  { issuer: 'GitLab', labels: ['GitLab PAT'], hosts: ['gitlab.com'], nameTokens: ['gitlab'] },
  { issuer: 'Slack', labels: ['Slack token'], hosts: ['slack.com', 'slack-edge.com'], nameTokens: ['slack'] },
  { issuer: 'Stripe', labels: ['Stripe live key'], hosts: ['stripe.com', 'stripe.network'], nameTokens: ['stripe'] },
  { issuer: 'AWS', labels: ['AWS access key id'], hosts: ['amazonaws.com', 'amazonaws.com.cn', 'aws.amazon.com'], nameTokens: ['amazonaws'] },
  { issuer: 'Google', labels: ['Google API key'], hosts: ['googleapis.com', 'google.com', 'googleusercontent.com'], nameTokens: ['googleapis'] },
  { issuer: 'npm', labels: ['npm token'], hosts: ['npmjs.org', 'npmjs.com'], nameTokens: ['npm', 'artifactory', 'nexus', 'verdaccio'] },
  { issuer: 'Hugging Face', labels: ['Hugging Face token'], hosts: ['huggingface.co', 'hf.co'], nameTokens: ['huggingface'] },
  { issuer: 'Telegram', labels: ['Telegram bot token'], hosts: ['telegram.org', 't.me'], nameTokens: ['telegram'] },
  { issuer: 'Pinecone', labels: ['Pinecone API key'], hosts: ['pinecone.io'], nameTokens: ['pinecone'] },
  { issuer: 'DigitalOcean', labels: ['DigitalOcean token'], hosts: ['digitalocean.com', 'digitaloceanspaces.com'], nameTokens: ['digitalocean'] },
  { issuer: 'Shopify', labels: ['Shopify access token'], hosts: ['myshopify.com', 'shopify.com'], nameTokens: ['shopify', 'myshopify'] },
  { issuer: 'SendGrid', labels: ['SendGrid API key'], hosts: ['sendgrid.com', 'sendgrid.net'], nameTokens: ['sendgrid'] },
  { issuer: 'Azure', labels: ['Azure storage account key'], hosts: ['core.windows.net', 'azure.com', 'azure.net'], nameTokens: ['azure'] },
  { issuer: 'OpenAI', labels: ['OpenAI key', 'OpenAI project key'], hosts: ['openai.com', 'openai.azure.com'], nameTokens: ['openai'], llm: true },
  { issuer: 'Anthropic', labels: ['Anthropic API key'], hosts: ['anthropic.com'], nameTokens: ['anthropic'], llm: true },
  { issuer: 'Groq', labels: ['Groq API key'], hosts: ['groq.com'], nameTokens: ['groq'], llm: true },
  { issuer: 'Replicate', labels: ['Replicate API token'], hosts: ['replicate.com', 'replicate.delivery'], nameTokens: ['replicate'], llm: true },
  { issuer: 'Perplexity', labels: ['Perplexity API key'], hosts: ['perplexity.ai'], nameTokens: ['perplexity'], llm: true },
  { issuer: 'Fireworks', labels: ['Fireworks API key'], hosts: ['fireworks.ai'], nameTokens: ['fireworks'], llm: true },
  { issuer: 'xAI', labels: ['xAI API key'], hosts: ['x.ai'], nameTokens: ['x.ai'], llm: true },
  { issuer: 'OpenRouter', labels: ['OpenRouter API key'], hosts: ['openrouter.ai'], nameTokens: ['openrouter'], llm: true },
  { issuer: 'LangSmith', labels: ['LangSmith API key'], hosts: ['langchain.com', 'smith.langchain.com'], nameTokens: ['langchain', 'langsmith'], llm: true },
];

export const UNATTRIBUTED_SECRET_LABELS = [
  'Generic bearer',
  'JSON web token',
  'Private key block',
  'Database URL with password',
  'AWS secret access key (keyed)',
  'Registry auth blob (docker config)',
  'Provider API key (named env var)',
  'Discord webhook',
  'Slack incoming webhook',
  'Sentry DSN with secret',
];

export const LLM_RELAY_HOSTS = [
  'openrouter.ai', 'gateway.ai.cloudflare.com', 'portkey.ai', 'helicone.ai', 'hconeai.com',
  'braintrust.dev', 'braintrustdata.com', 'langfuse.com', 'humanloop.com', 'litellm.ai',
  'unify.ai', 'requesty.ai', 'llmproxy.io',
];

const INTERNAL_SUFFIXES = ['.local', '.internal', '.lan', '.intranet', '.localdomain', '.home.arpa', '.test', '.invalid'];
const IP_LITERAL_RE = /^(?:\d{1,3}(?:\.\d{1,3}){3}|\[?[0-9a-f:]+\]?)$/i;
const PRIVATE_HOST_RE = /^(localhost|127\.|10\.|192\.168\.|169\.254\.|0\.0\.0\.0$|172\.(1[6-9]|2\d|3[01])\.)/i;
const AUTH_HEADER_RE = /(?:authorization|proxy-authorization|x-api-key|x-auth-token|api[-_]?key|private[-_]token|access[-_]token|auth[-_]token)["'\]]?\s*[:=]\s*["'`]?\s*(?:bearer|token|basic|key)?[\s:]*$/i;
const CURL_USER_RE = /-(?:u|-user|-header|H)\s+["']?[^\s"']*$/i;
const AUTH_WINDOW = 96;

export function extractHosts(text) {
  const hosts = new Set();
  for (const raw of String(text ?? '').match(/https?:\/\/[^\s"'<>\\)]+/gi) ?? []) {
    try { hosts.add(new URL(raw).hostname.toLowerCase()); } catch { /* unparseable contributes no host */ }
  }
  return [...hosts];
}

export function isGradeableDestination(host) {
  const h = String(host ?? '').toLowerCase().replace(/:\d+$/, '');
  if (!h || !h.includes('.')) return false;
  if (IP_LITERAL_RE.test(h)) return false;
  if (PRIVATE_HOST_RE.test(h)) return false;
  if (INTERNAL_SUFFIXES.some((s) => h.endsWith(s))) return false;
  return true;
}

function servesIssuer(host, def) {
  const h = host.toLowerCase().replace(/:\d+$/, '');
  if (def.hosts.some((d) => h === d || h.endsWith('.' + d))) return 'issuer-host';
  if (def.nameTokens.some((t) => h.split('.').some((p) => p === t || p.startsWith(t + '-') || p.endsWith('-' + t)) || h.includes(t + '.'))) return 'issuer-name';
  if (def.llm && LLM_RELAY_HOSTS.some((d) => h === d || h.endsWith('.' + d))) return 'relay';
  return null;
}

function positionOf(text, start) {
  if (typeof start !== 'number') return 'payload';
  const window = text.slice(Math.max(0, start - AUTH_WINDOW), start);
  return AUTH_HEADER_RE.test(window) || CURL_USER_RE.test(window) ? 'auth-header' : 'payload';
}

export function gradeCredentialDestinations(text, sightings, sinks = []) {
  const body = String(text ?? '');
  if (!body.trim()) return [];
  const secrets = (sightings ?? []).filter((s) => s && s.label);
  if (!secrets.length) return [];

  const hosts = extractHosts(body);
  const gradeable = hosts.filter(isGradeableDestination);
  const out = [];
  const seen = new Set();

  for (const m of secrets) {
    if (seen.has(m.label)) continue;
    seen.add(m.label);
    const position = positionOf(body, m.start);
    const def = CREDENTIAL_ISSUERS.find((c) => c.labels.includes(m.label));
    if (!def) { out.push({ state: 'UNBOUND', label: m.label, position, hosts }); continue; }
    if (!gradeable.length) { out.push({ state: hosts.length ? 'UNBOUND' : 'NOT_APPLICABLE', label: m.label, issuer: def.issuer, position, hosts }); continue; }

    let basis = null, bound;
    for (const h of gradeable) { const b = servesIssuer(h, def); if (b) { basis = b; bound = h; break; } }
    if (basis) { out.push({ state: 'BOUND', label: m.label, issuer: def.issuer, destination: bound, basis, position, hosts }); continue; }

    const destination = gradeable[0];
    const rival = CREDENTIAL_ISSUERS.find((c) => c.issuer !== def.issuer && servesIssuer(destination, c) === 'issuer-host');
    const sink = sinks.find((s) => destination === s || destination.endsWith('.' + s));
    out.push({ state: 'FOREIGN', label: m.label, issuer: def.issuer, destination, crossVendor: rival?.issuer, sink, position, hosts });
  }
  return out;
}

export function credentialDestinationFindings(text, sightings) {
  const sinks = SUSPICIOUS_EGRESS_HOSTS.filter((h) => extractHosts(text).some((d) => d === h || d.endsWith('.' + h)));
  return gradeCredentialDestinations(text, sightings, sinks)
    .filter((b) => b.state === 'FOREIGN')
    .map((b) => ({
      label: `${b.issuer} credential sent to ${b.destination}, which ${b.issuer} does not serve`,
      severity: b.crossVendor || b.sink ? 'HIGH' : 'MEDIUM',
      category: 'egress',
      issuer: b.issuer,
      destination: b.destination,
      position: b.position,
    }));
}
