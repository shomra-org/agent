export const SECRET_PATTERNS                                 = [
  { name: 'Stripe live key', re: /\bsk_live_[0-9a-zA-Z]{16,}/ },
  { name: 'OpenAI admin / service-account key', re: /\bsk-(?:svcacct|admin)-[A-Za-z0-9_-]{20,}/ },
  { name: 'OpenAI key', re: /\bsk-[A-Za-z0-9]{20,}/ },
  { name: 'AWS access key id', re: /\bAKIA[0-9A-Z]{16}/ },
  { name: 'AWS temporary key id (STS)', re: /\bASIA[0-9A-Z]{16}/ },
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
    re: /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver|oracle|clickhouse|cockroachdb|snowflake|neo4j(?:\+s)?|couchbases?):\/\/(?!(?:user|username|admin|root|myuser|dbuser):(?:pass|password|passwd|secret|changeme|mypassword|yourpassword|xxx+|123456)@)(?!([^\s:@/]+):\1@)(?!(?:some|my|your|our|the|test|demo|example|dummy|fake|sample|foo|bar|placeholder)[\w-]*:(?:some|my|your|our|the|test|demo|example|dummy|fake|sample|foo|bar|placeholder)[\w-]*@)[^\s:@/]+:(?![$<[{])[^\s:@/]{4,}@/i,
  },
  { name: 'Generic bearer', re: /bearer\s+[A-Za-z0-9._-]{20,}/i },
  { name: 'Encrypted private key block', re: /-----BEGIN ENCRYPTED PRIVATE KEY-----|-----BEGIN [A-Z ]{2,20}PRIVATE KEY-----\r?\nProc-Type: ?4, ?ENCRYPTED|PuTTY-User-Key-File-\d{1,2}:[^\r\n]{1,80}\r?\nEncryption: ?(?!none\b)[\w-]{2,40}/ },
  { name: 'PuTTY private key', re: /PuTTY-User-Key-File-\d{1,2}:[^\r\n]{1,80}\r?\nEncryption: ?none\b/ },
  { name: 'Private key block', re: /-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----\r?\n(?:[\w-]{1,40}: [^\r\n]{1,200}\r?\n){0,4}(?:\r?\n)?[ \t]{0,8}[A-Za-z0-9+/]{12,}/ },
  { name: 'Groq API key', re: /\bgsk_[A-Za-z0-9]{40,}/ },
  { name: 'Replicate API token', re: /\br8_[A-Za-z0-9]{30,}/ },
  { name: 'Perplexity API key', re: /\bpplx-[A-Za-z0-9]{32,}/ },
  { name: 'Fireworks API key', re: /\bfw_[A-Za-z0-9]{20,}/ },
  { name: 'xAI API key', re: /\bxai-[A-Za-z0-9]{40,}/ },
  { name: 'LangSmith API key', re: /\blsv2_(?:pt|sk)_[A-Za-z0-9]{24,}_[A-Za-z0-9]{8,}/ },
  { name: 'Pinecone API key', re: /\bpcsk_[A-Za-z0-9_]{30,}/ },
  { name: 'OpenRouter API key', re: /\bsk-or-v1-[A-Za-z0-9]{32,}/ },
  { name: 'Discord webhook', re: /\bdiscord(?:app)?\.com\/api\/webhooks\/\d{17,}\/[A-Za-z0-9_-]{40,}/ },
  { name: 'Telegram bot token', re: /\b\d{8,12}:AA[A-Za-z0-9_-]{30,}/ },
  { name: 'Sentry DSN with secret', re: /\bhttps:\/\/[a-f0-9]{32}(?::[a-f0-9]{32})?@[\w.-]*(?:sentry\.io|ingest\.[\w.-]+)\/\d+/ },
  { name: 'Registry auth blob (docker config)', re: /"auth"\s*:\s*"[A-Za-z0-9+/]{24,}={0,2}"/ },
  {
    name: 'Provider API key (named env var)',
    re: /\b(?:AZURE_OPENAI_API_KEY|MISTRAL_API_KEY|COHERE_API_KEY|CO_API_KEY|TOGETHER_API_KEY|DEEPSEEK_API_KEY|DD_API_KEY|DATADOG_API_KEY|TWILIO_AUTH_TOKEN|VERCEL_TOKEN|CLOUDFLARE_API_TOKEN|WEAVIATE_API_KEY|VOYAGE_API_KEY|NVIDIA_API_KEY|CEREBRAS_API_KEY|SAMBANOVA_API_KEY)\s*[=:]\s*["']?[A-Za-z0-9_-]{24,}\b/,
  },
];

export const ENTERPRISE_SECRET_PATTERNS                                 = [
  { name: 'Anthropic API key', re: /\bsk-ant-[A-Za-z0-9_-]{24,}/ },
  { name: 'OpenAI key', re: /\bsk-(?:proj-)?[A-Za-z0-9]{20,}/ },
  { name: 'OpenAI project/org', re: /\b(?:org|proj)-[A-Za-z0-9]{20,}/ },
  { name: 'Hugging Face token', re: /\bhf_[A-Za-z0-9]{30,}/ },
  { name: 'Cohere key', re: /\bco-[A-Za-z0-9]{40,}/ },
  { name: 'Google AI / API key', re: /\bAIza[0-9A-Za-z_-]{35}/ },
  { name: 'AWS access key id', re: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}/ },
  { name: 'AWS secret access key (keyed)', re: /aws_secret_access_key\s*[=:]\s*["']?[A-Za-z0-9/+]{40}/i },
  { name: 'GCP service-account private key id', re: /"private_key_id"\s*:\s*"[0-9a-f]{40}"/ },
  { name: 'GCP API key', re: /\bAIza[0-9A-Za-z_-]{35}/ },
  { name: 'Azure storage key', re: /AccountKey\s*=\s*[A-Za-z0-9+/]{80,}==/ },
  { name: 'GitHub personal token (classic)', re: /\bghp_[0-9A-Za-z]{36}/ },
  { name: 'GitHub fine-grained token', re: /\bgithub_pat_[0-9A-Za-z_]{60,}/ },
  { name: 'GitHub OAuth/app token', re: /\bgh[osur]_[0-9A-Za-z]{36}/ },
  { name: 'GitLab personal token', re: /\bglpat-[0-9A-Za-z_-]{20,}/ },
  { name: 'npm token', re: /\bnpm_[0-9A-Za-z]{36}/ },
  { name: 'PyPI upload token', re: /\bpypi-AgEIcHlwaS[A-Za-z0-9_-]{50,}/ },
  { name: 'Stripe live secret key', re: /\b[rs]k_(?:live|prod)_[0-9a-zA-Z]{10,99}/ },
  { name: 'Stripe webhook secret', re: /\bwhsec_[A-Za-z0-9+/=]{32,}/ },
  { name: 'Slack token', re: /\bxox[baprs]-[0-9A-Za-z-]{10,}/ },
  { name: 'Slack webhook', re: /https:\/\/hooks\.slack\.com\/services\/T[0-9A-Za-z_]+\/B[0-9A-Za-z_]+\/[0-9A-Za-z]+/ },
  { name: 'SendGrid key', re: /\bSG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}/ },
  { name: 'Twilio account SID', re: /\bAC[0-9a-f]{32}/ },
  { name: 'Twilio API key', re: /\bSK[0-9a-f]{32}/ },
  { name: 'Mailgun key', re: /\bkey-[0-9a-f]{32}/ },
  { name: 'Datadog API key', re: /\bdd[ap]i_[0-9a-f]{32,}/i },
  { name: 'Shopify access token', re: /\bshp(?:at|ca|pa|ss)_[0-9a-fA-F]{32}/ },
  { name: 'Square access token', re: /\bsq0(?:atp|csp|idp)-[0-9A-Za-z_-]{22,}/ },
  { name: 'DigitalOcean token', re: /\bdop_v1_[0-9a-f]{64}/ },
  { name: 'Cloudflare API token', re: /\b[A-Za-z0-9_-]{40}\b(?=[^\n]{0,40}cloudflare)/i },
  { name: 'Azure AD client secret', re: /(?<![\w~.-])[a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.-]{31,34}(?![\w~.-])/ },
  { name: 'Azure SAS token', re: /[?&]sig=[A-Za-z0-9%+/]{40,120}(?:%3D|=){0,2}/ },
  { name: 'Azure Service Bus / Event Hub key', re: /\bSharedAccessKey=[A-Za-z0-9+/]{42,44}=/ },
  { name: 'AWS Bedrock API key', re: /\bABSK[A-Za-z0-9+/]{109,269}={0,2}|\bbedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t[A-Za-z0-9+/=%]{20,}/ },
  { name: 'Databricks token', re: /\bdapi[a-f0-9]{32}(?:-\d)?\b/ },
  { name: 'Google OAuth client secret', re: /\bGOCSPX-[A-Za-z0-9_-]{28}\b/ },
  { name: 'Google OAuth access token', re: /\bya29\.[0-9A-Za-z_-]{50,}/ },
  { name: 'GitLab CI / deploy / runner token', re: /\b(?:gldt|glrt|glsoat|glft|glimt|glagent|gloas)-[0-9A-Za-z_-]{20,}|\bglptt-[0-9a-f]{40}\b|\bglcbt-[0-9A-Za-z]{1,5}_[0-9A-Za-z_-]{20,}|\bGR1348941[\w-]{20,}/ },
  { name: 'Slack app token', re: /\bxapp-\d-[A-Z0-9]{8,}-\d{6,}-[a-z0-9]{32,}/i },
  { name: 'Mailchimp API key', re: /\b[a-f0-9]{32}-us\d{1,2}\b/ },
  { name: 'HashiCorp Vault token', re: /\bhvs\.[\w-]{90,120}|\bhvb\.[\w-]{138,300}/ },
  { name: 'Terraform Cloud token', re: /\b[a-z0-9]{14}\.atlasv1\.[a-z0-9_=-]{60,70}/i },
  { name: 'Doppler token', re: /\bdp\.(?:pt|st|sa|scim|audit|ct)\.[A-Za-z0-9]{40,44}\b/ },
  { name: '1Password service-account token', re: /\bops_eyJ[A-Za-z0-9+/]{250,}={0,3}/ },
  { name: '1Password secret key', re: /\bA3-[A-Z0-9]{6}-(?:[A-Z0-9]{11}|[A-Z0-9]{6}-[A-Z0-9]{5})-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\b/ },
  { name: 'age secret key', re: /\bAGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}\b/ },
  { name: 'Grafana token', re: /\bglc_[A-Za-z0-9+/]{32,400}={0,3}|\bglsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}\b/ },
  { name: 'Sentry auth token', re: /\bsntryu_[a-f0-9]{64}\b|\bsntrys_eyJ[A-Za-z0-9+/=_-]{60,}/ },
  { name: 'Linear API key', re: /\blin_api_[A-Za-z0-9]{40}\b/ },
  { name: 'Notion token', re: /\bntn_\d{11}[A-Za-z0-9]{35}\b|\bsecret_[A-Za-z0-9]{43}\b/ },
  { name: 'Postman API key', re: /\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b/i },
  { name: 'Pulumi token', re: /\bpul-[a-f0-9]{40}\b/ },
  { name: 'Heroku API key', re: /\bHRKU-AA[0-9A-Za-z_-]{58}\b/ },
  { name: 'Hugging Face org token', re: /\bapi_org_[A-Za-z]{34}\b/ },
  { name: 'Atlassian API token', re: /\bATATT3[A-Za-z0-9_=-]{180,200}/ },
  { name: 'Fly.io token', re: /\bfo1_[\w-]{43}\b|\bfm[12][ar]?_[A-Za-z0-9+/]{100,}={0,3}/ },
  { name: 'PlanetScale token', re: /\bpscale_(?:tkn|pw|oauth)_[\w=.-]{32,64}\b/ },
  { name: 'RubyGems API key', re: /\brubygems_[a-f0-9]{48}\b/ },
  { name: 'Clojars token', re: /\bCLOJARS_[a-z0-9]{60}\b/i },
  { name: 'NuGet API key', re: /\boy2[a-z0-9]{43}\b/ },
  { name: 'Docker Hub token', re: /\bdckr_pat_[A-Za-z0-9_-]{27,}/ },
  { name: 'JFrog Artifactory token', re: /\bAKCp[A-Za-z0-9]{69}\b|\bcmVmd[A-Za-z0-9]{59}\b/ },
  { name: 'Dynatrace token', re: /\bdt0c01\.[A-Za-z0-9]{24}\.[A-Za-z0-9]{64}\b/ },
  { name: 'Prefect API key', re: /\bpnu_[A-Za-z0-9]{36}\b/ },
  { name: 'Brevo API key', re: /\bxkeysib-[a-f0-9]{64}-[A-Za-z0-9]{16}\b/ },
  { name: 'Supabase access token', re: /\bsbp_[a-f0-9]{40}\b/ },
  { name: 'Alibaba Cloud access key', re: /\bLTAI[A-Za-z0-9]{20}\b/ },
  { name: 'Tencent Cloud secret id', re: /\bAKID[A-Za-z0-9]{32}\b/ },
  { name: 'Harness token', re: /\b(?:pat|sat)\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9]{24}\.[A-Za-z0-9]{20}\b/ },
  { name: 'Sourcegraph token', re: /\bsgp_(?:[a-fA-F0-9]{16}|local)_[a-fA-F0-9]{40}\b/ },
  { name: 'Microsoft Teams webhook', re: /\bhttps:\/\/[a-z0-9-]{1,63}\.webhook\.office\.com\/webhookb2\/[a-f0-9-]{36}@[a-f0-9-]{36}\/IncomingWebhook\/[a-f0-9]{32}\/[a-f0-9-]{36}/i },
  { name: 'dotenvx private key', re: /\bDOTENV_PRIVATE_KEY(?:_[A-Z0-9_]{1,40})?[ \t]{0,4}=[ \t]{0,4}["']?[a-f0-9]{64}\b/ },
  { name: 'Credential in URL', re: /\b(?:https?|git|ssh|ftps?|smb|ldaps?):\/\/(?![^\s:@/]{1,64}:(?:\$|\{\{|<|\[|x{3}|\*{3}|password\b|passwd\b|pass\b|secret\b|token\b|changeme\b)[^\s@/]{0,64}@)[^\s:@/{}<>]{1,64}:[^\s:@/{}<>]{8,128}@(?!(?:example\.(?:com|org|net)|localhost|127\.0\.0\.1)(?:[:/\s]|$))[A-Za-z0-9.-]{3,}/i },
  { name: 'JWT', re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/ },
  { name: 'Generic bearer', re: /bearer\s+[A-Za-z0-9._~+/-]{20,}=*/i },
];

export const GENERIC_SECRET_LABELS = new Set(['Generic bearer', 'JWT', 'JSON web token', 'Credential in URL']);

export const ALL_SECRET_PATTERNS                                 = [
  ...[...SECRET_PATTERNS, ...ENTERPRISE_SECRET_PATTERNS].filter((p) => !GENERIC_SECRET_LABELS.has(p.name)),
  ...[...SECRET_PATTERNS, ...ENTERPRISE_SECRET_PATTERNS].filter((p) => GENERIC_SECRET_LABELS.has(p.name)),
];

export function textCarriesSecret(text                           )          {
  if (!text) return false;
  return ALL_SECRET_PATTERNS.some((p) => p.re.test(text));
}

export function shannonEntropy(s        )         {
  if (!s) return 0;
  const freq = new Map                ();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let bits = 0;
  for (const c of freq.values()) {
    const p = c / s.length;
    bits -= p * Math.log2(p);
  }
  return bits;
}

export const SECRET_KEY_RE =
  /\b(\w*(?:secret|token|passw(?:or)?d|api[_-]?key|apikey|access[_-]?key|client[_-]?secret|auth[_-]?token|private[_-]?key|credential|session[_-]?key|encryption[_-]?key|signing[_-]?key)\w*)\b/i;

const ASSIGNMENT_RE =
  /([A-Za-z_$][\w.$-]{0,127})[ \t]{0,32}[:=][ \t]{0,32}(?:(["'`])([^"'`\r\n]{12,512})\2|([A-Za-z0-9_./+=~!@#$%^&*?:,-]{12,512}))/g;

const ENV_VAR_KEY_RE = /^[A-Z][A-Z0-9_]{2,}$/;

const NON_SECRET_SHAPE = [
  /^[0-9a-f]{7,40}$/i,
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
  /^\d[\d.]+\d$/,
  /^(?:[A-Za-z]+[-_/.])+[A-Za-z]+$/,
  /^(?:~|\.{1,2}|\$\{?\w+\}?:?)?\/(?:[\w.-]+\/)*[\w.-]+$/,
  /^[a-z][a-z0-9+.-]{1,30}:\/\/[^\s@]*$/i,
  /^[\w.-]+(?:[\\/][\w.-]+)+\.[a-z0-9]{1,6}$/i,
  /^\$(?:2[abxy]|1|5|6|apr1|argon2(?:i|d|id)|scrypt|pbkdf2(?:-sha\d+)?)\$/,
  /^(?:pk\.eyJ|pk_(?:live|test)_)/,
  /^6LeIxAcTAAAAA(?:JcZVRqyHh71UMIEGNQ_MXjiZKhI|GG-vFI1TnRWxMZNFuojJ4WifJWe)$/,
];

export const isNonSecretShape = (v        )          => NON_SECRET_SHAPE.some((r) => r.test(v.trim()));
export const NAMES_ITS_ROLE_RE = /passw(?:or)?d|passwd|secret|token|api[_-]?key|credential/i;

const ENTROPY_MIN_MIXED = 3.5;
const ENTROPY_MIN_HEX = 3.0;

export function isPlaceholderValue(v        )          {
  const low = v.toLowerCase();
  if (/(your|my|the|some|placeholder|example|sample|dummy|test|fake|changeme|redacted|x{3,64}|\.\.\.|todo|replace|insert|here|value|token|secret|key)$/i.test(low)) return true;
  if (/^[x*.\-_0]+$/i.test(v)) return true;
  if (/(.)\1{7,}/.test(v)) return true;
  if (/^(?:abc|123|test|foo|bar|qwerty)/i.test(low)) return true;
  return false;
}

export const SECRET_REFERENCE_RE =
  /^(?:\$\{[^}]{1,120}\}|\$\([^)]{1,200}\)|\$[A-Za-z_][A-Za-z0-9_]{1,80}$|\{\{[^}]{1,160}\}\}|%\{[\w.]{1,80}\}|op:\/\/|vault:|sm:\/\/|awssm:\/\/|gcpsm:\/\/|azkv:\/\/|doppler:\/\/|infisical:\/\/|arn:aws[\w-]{0,20}:(?:secretsmanager|ssm):|projects\/[^/\s]{1,80}\/secrets\/|@Microsoft\.KeyVault\(|!vault\b)/i;
export const ENCRYPTED_VALUE_RE = /^(?:ENC\[[A-Z0-9_]{3,20},|encrypted:|\$ANSIBLE_VAULT;|-----BEGIN (?:AGE ENCRYPTED FILE|PGP MESSAGE)-----|AgA[A-Za-z0-9+/]{100,})/;
export const isSecretReference = (v        )          => SECRET_REFERENCE_RE.test(v.trim());
export const isEncryptedValue = (v        )          => ENCRYPTED_VALUE_RE.test(v.trim());
export const IDENTIFIER_SECRET_LABELS = new Set(['Twilio account SID', 'OpenAI project/org']);
export const MAX_SECRET_HITS = 500;

const URL_PLACEHOLDER_PASSWORD_RE =
  /^(?:[$<[{%]|.*(?:passw|secret|change|replace|your|example|placeholder|insecure|dummy|sample|xxx|\*\*\*|todo|fill))/i;
export function urlCredentialIsPlaceholder(match        )          {
  const m = /:\/\/([^\s:@/]*):([^\s@/]*)@/.exec(match);
  return !!m && (URL_PLACEHOLDER_PASSWORD_RE.test(m[2]) || m[2] === m[1]);
}

export function scanSecrets(text                           )              {
  const s = text ?? '';
  if (!s) return [];
  const out              = [];
  const claimed                          = [];

  const overlaps = (a        , b        ) => claimed.some(([x, y]) => a < y && x < b);

  for (const { name, re } of ALL_SECRET_PATTERNS) {
    if (out.length >= MAX_SECRET_HITS) break;
    const g = new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g');
    for (const m of s.matchAll(g)) {
      if (out.length >= MAX_SECRET_HITS) break;
      const at = m.index ?? 0;
      if (overlaps(at, at + m[0].length)) continue;

      if (m[0].length < 200 && !/private key/i.test(name) && isPlaceholderValue(m[0])) continue;
      if ((name === 'Database URL with password' || name === 'Credential in URL') && urlCredentialIsPlaceholder(m[0])) continue;
      claimed.push([at, at + m[0].length]);
      out.push({ name, match: m[0], index: at, kind: 'named', tier: 'structure' });
    }
  }

  for (const m of s.matchAll(ASSIGNMENT_RE)) {
    if (out.length >= MAX_SECRET_HITS) break;
    const key = m[1];
    const quoted = m[2] !== undefined;
    const raw = (quoted ? m[3] : m[4]) ?? '';
    const value = raw.replace(/[=]{1,64}$/, '');
    const at = (m.index ?? 0) + m[0].lastIndexOf(raw);
    if (overlaps(at, at + value.length)) continue;
    if (!SECRET_KEY_RE.test(key)) continue;

    if (!quoted && !ENV_VAR_KEY_RE.test(key)) continue;
    if (value.length < 16 || /\s/.test(value)) continue;
    if (isPlaceholderValue(value) || isSecretReference(value) || isEncryptedValue(value) || NAMES_ITS_ROLE_RE.test(value)) continue;
    if (NON_SECRET_SHAPE.some((r) => r.test(value))) continue;
    const isHex = /^[0-9a-f]+$/i.test(value);
    const ent = shannonEntropy(value);
    if (ent < (isHex ? ENTROPY_MIN_HEX : ENTROPY_MIN_MIXED)) continue;
    claimed.push([at, at + value.length]);
    out.push({ name: `High-entropy secret in "${key}"`, match: value, index: at, kind: 'entropy', tier: 'heuristic' });
  }

  return out.sort((a, b) => a.index - b.index);
}

