export const SECRET_PATTERNS = [

  { name: 'Stripe live key', re: /\bsk_live_[0-9a-zA-Z]{16,}/ },
  { name: 'OpenAI key', re: /\bsk-[A-Za-z0-9]{20,}/ },
  { name: 'AWS access key id', re: /\bAKIA[0-9A-Z]{16}/ },
  { name: 'GitHub token', re: /ghp_[0-9A-Za-z]{20,}/ },

  { name: 'Anthropic API key', re: /\bsk-ant-[A-Za-z0-9_-]{20,}/ },
  { name: 'OpenAI project key', re: /\bsk-proj-[A-Za-z0-9_-]{20,}/ },
  { name: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { name: 'Hugging Face token', re: /\bhf_[A-Za-z0-9]{30,}/ },
  { name: 'GitLab PAT', re: /\bglpat-[A-Za-z0-9_-]{20,}/ },
  { name: 'npm token', re: /\bnpm_[A-Za-z0-9]{30,}/ },
  { name: 'Slack token', re: /xox[baprs]-[0-9A-Za-z-]{10,}/ },

  { name: 'AWS secret access key (keyed)', re: /\bAWS_SECRET_ACCESS_KEY\s*[=:]\s*['"]?[A-Za-z0-9/+=]{40}\b/ },

  {
    name: 'Database URL with password',
    re: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/(?!(?:user|username|admin|root|myuser|dbuser):(?:pass|password|passwd|secret|changeme|mypassword|yourpassword|xxx+|123456)@)[^\s:@/]+:[^\s:@/]{4,}@/i,
  },
  { name: 'Generic bearer', re: /bearer\s+[A-Za-z0-9._-]{20,}/i },
  { name: 'Private key block', re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/ },

  { name: 'Groq API key', re: /\bgsk_[A-Za-z0-9]{40,}/ },
  { name: 'Replicate API token', re: /\br8_[A-Za-z0-9]{30,}/ },
  { name: 'Perplexity API key', re: /\bpplx-[A-Za-z0-9]{32,}/ },
  { name: 'Fireworks API key', re: /\bfw_[A-Za-z0-9]{20,}/ },
  { name: 'xAI API key', re: /\bxai-[A-Za-z0-9]{40,}/ },
  { name: 'LangSmith API key', re: /\blsv2_(?:pt|sk)_[A-Za-z0-9]{24,}_[A-Za-z0-9]{8,}/ },
  { name: 'Pinecone API key', re: /\bpcsk_[A-Za-z0-9_]{30,}/ },
  { name: 'OpenRouter API key', re: /\bsk-or-v1-[A-Za-z0-9]{32,}/ },
  { name: 'DigitalOcean token', re: /\bdop_v1_[a-f0-9]{60,}/ },
  { name: 'Shopify access token', re: /\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{30,}/ },
  { name: 'GitHub fine-grained PAT', re: /\bgithub_pat_[A-Za-z0-9_]{60,}/ },
  { name: 'GitHub OAuth / refresh / server token', re: /\bgh[osur]_[A-Za-z0-9]{20,}/ },
  { name: 'SendGrid API key', re: /\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{40,}/ },
  { name: 'Slack incoming webhook', re: /\bhooks\.slack\.com\/services\/T[A-Z0-9]{6,}\/B[A-Z0-9]{6,}\/[A-Za-z0-9]{20,}/ },
  { name: 'Discord webhook', re: /\bdiscord(?:app)?\.com\/api\/webhooks\/\d{17,}\/[A-Za-z0-9_-]{40,}/ },
  { name: 'Telegram bot token', re: /\b\d{8,12}:AA[A-Za-z0-9_-]{30,}/ },
  { name: 'Sentry DSN with secret', re: /\bhttps:\/\/[a-f0-9]{32}(?::[a-f0-9]{32})?@[\w.-]*(?:sentry\.io|ingest\.[\w.-]+)\/\d+/ },
  { name: 'Azure storage account key', re: /\bAccountKey\s*=\s*[A-Za-z0-9+/]{60,}={0,2}/ },
  { name: 'JSON web token', re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{20,}/ },
  { name: 'Registry auth blob (docker config)', re: /"auth"\s*:\s*"[A-Za-z0-9+/]{24,}={0,2}"/ },
  {
    name: 'Provider API key (named env var)',
    re: /\b(?:AZURE_OPENAI_API_KEY|MISTRAL_API_KEY|COHERE_API_KEY|CO_API_KEY|TOGETHER_API_KEY|DEEPSEEK_API_KEY|DD_API_KEY|DATADOG_API_KEY|TWILIO_AUTH_TOKEN|VERCEL_TOKEN|CLOUDFLARE_API_TOKEN|WEAVIATE_API_KEY|VOYAGE_API_KEY|NVIDIA_API_KEY|CEREBRAS_API_KEY|SAMBANOVA_API_KEY)\s*[=:]\s*["']?[A-Za-z0-9_-]{24,}\b/,
  },
];

export const GENERIC_SECRET_LABELS = new Set(['Generic bearer', 'JSON web token']);

export const ORDERED_SECRET_PATTERNS = [
  ...SECRET_PATTERNS.filter((p) => !GENERIC_SECRET_LABELS.has(p.name)),
  ...SECRET_PATTERNS.filter((p) => GENERIC_SECRET_LABELS.has(p.name)),
];

export const PII_PATTERNS = [
  { name: 'Email address', re: /[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}/ },
  { name: 'US SSN', re: /\b\d{3}-\d{2}-\d{4}\b/ },
  { name: 'Credit card number', re: /\b(?:\d[ -]?){13,16}\b/ },
  { name: 'Phone number', re: /\b(?:\+?1[ .-]?)?\(?\d{3}\)?[ .-]?\d{3}[ .-]?\d{4}\b/ },
  { name: 'IPv4 address', re: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/ },
];

export const RESERVED_IPV4 = /^(0\.|255\.255\.255\.255|127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|8\.8\.(8\.8|4\.4)|1\.1\.1\.1|1\.0\.0\.1|224\.)/;

export const VERSION_CONTEXT = /\b(v|ver|version|release|rev|build|semver|tag)\.?\s*$/i;

export function luhnValid(value) {
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

export function isPlaceholderSecret(v) {
  const s = String(v);
  const low = s.toLowerCase();
  if (/(example|sample|placeholder|dummy|redacted|changeme|test[_-]?(key|token|secret)|your[-_]?(key|token|secret|api))/.test(low)) return true;
  if (/(x{6,}|\.{3,}|<[^>]{2,}>|\*{4,}|•{3,})/.test(low)) return true;
  const tail = s.replace(/^\w{1,10}[-_]/, '');
  if (/^(.)\1{7,}/.test(tail)) return true;
  if (/^(0123|1234|abcd|abcdef|deadbeef)/i.test(tail)) return true;
  return false;
}
