
export const SOURCE_CAPS = ['injection', 'readsSensitive', 'filesystem'];
export const SINK_CAPS = ['network', 'exec', 'destructive'];

export const CAP_LABEL = {
  injection: 'untrusted input',
  readsSensitive: 'sensitive data',
  filesystem: 'filesystem access',
  network: 'network egress',
  exec: 'code execution',
  destructive: 'destructive action',
};

const DISCLAIMER_RE = /\b(no|never|not|without|excludes?|excluding|neither|nor)\b[^.\n]{0,30}\b(access|read|write|permission|abilit|able|connection|integration)\w*|\b(does |do |will |can |must )(not|n't)\b|\bout of scope\b|\bnon-goals?\b|\bis not (able|permitted|allowed)\b/i;
const CAP_RULES = [

  { cap: 'injection', what: 'end-user or customer text', re: /\b(user|customer|client|end[- ]user)[- ]?(input|message|text|query|prompt|request|content|submission)\b/i },
  { cap: 'injection', what: 'inbound email', re: /\b(inbound |incoming |receiv\w+ )?e-?mails?\b|\bmailbox\b|\bimap\b|\bsupport inbox\b/i },
  { cap: 'injection', what: 'support tickets', re: /\b(support |help[- ]?desk |zendesk |intercom |freshdesk )?tickets?\b|\bcase notes?\b/i },
  { cap: 'injection', what: 'issues and PR descriptions', re: /\b(github |gitlab |jira |linear )?(issues?|pull[- ]requests?|PR) (body|description|comments?)\b|\bissue tracker\b/i },

  { cap: 'injection', what: 'uploaded documents', re: /\b(upload(ed|s)?|attach(ed|ment)s?)\b.{0,30}\b(files?|documents?|pdfs?|images?|csvs?|spreadsheets?)\b|\b(pdf|docx|csv)s? (upload|ingest|pars\w+)/i },

  { cap: 'injection', what: 'content received from outside', re: /\b(ingest|receiv|accept|import|process|pull|collect|read|fetch)\w*\b[^.\n]{0,40}\bfrom\b[^.\n]{0,25}\b(customers?|users?|clients?|end[- ]users?|the public|third[- ]part\w+|external|partners?|vendors?|suppliers?)\b/i },
  { cap: 'injection', what: 'scraped or fetched web content', re: /\b(scrap\w+|crawl\w+|fetch\w+|browse\w*)\b.{0,30}\b(web|site|page|url|internet)\b|\bweb (page|content|search results?)\b/i },
  { cap: 'injection', what: 'retrieved documents (RAG)', re: /\bRAG\b|\bretrieval[- ]augmented\b|\b(retriev\w+|search\w*) (documents?|chunks?|context|corpus)\b|\bvector (store|db|database|search)\b|\bknowledge base\b/i },
  { cap: 'injection', what: 'third-party API responses', re: /\bthird[- ]party\b.{0,30}\b(api|response|data|feed|service)\b|\bexternal (api|service|feed) (response|data|content)\b/i },
  { cap: 'injection', what: 'public form submissions', re: /\bpublic\b.{0,25}\b(form|endpoint|api|submission|chat|widget)\b|\bunauthenticated (user|request|caller)\b/i },
  { cap: 'injection', what: 'chat or comment history', re: /\b(chat|conversation|comment|review|forum|slack|discord|teams) (history|thread|messages?|log)\b/i },
  { cap: 'injection', what: 'MCP tool results', re: /\bMCP\b.{0,40}\b(tool|server|response|result)\b|\btool (result|response|output)s?\b.{0,20}\b(back into|into (the )?context)\b/i },

  { cap: 'readsSensitive', what: 'customer records', re: /\b(customer|user|client|member|patient|employee)s?[- ]?(data|records?|profiles?|list|database|table|pii)\b|\bPII\b|\bpersonal(ly)?[- ]identifiab\w+/i },
  { cap: 'readsSensitive', what: 'credentials or secrets', re: /\b(secret|credential|api[- ]?key|access[- ]?token|password|private[- ]?key|service[- ]account)s?\b|\bvault\b|\bkeychain\b|\b\.env\b/i },
  { cap: 'readsSensitive', what: 'regulated data', re: /\b(PHI|HIPAA|GDPR|PCI([- ]DSS)?|SOC ?2|health (records?|data)|medical|financial (records?|data)|payroll|salar(y|ies)|SSN|social security|tax)\b/i },
  { cap: 'readsSensitive', what: 'the production database', re: /\bprod(uction)?\b.{0,25}\b(database|db|data|warehouse|replica|store)\b|\b(database|db|warehouse) (read|query|access|connection)\b|\bread[- ]replica\b/i },
  { cap: 'readsSensitive', what: 'private source code', re: /\bprivate (repo|repositor\w+|source|code)\b|\bproprietary (code|source)\b|\binternal (repo|codebase|wiki|docs?)\b/i },
  { cap: 'readsSensitive', what: 'object storage', re: /\bS3 bucket\b|\b(blob|object) storage\b|\bGCS bucket\b|\bdata lake\b/i },

  { cap: 'filesystem', what: 'file writes', re: /\bwrit\w+\b[^.\n]{0,25}\b(files?|disks?|filesystems?|director(y|ies)|folders?|repos?|repositor(y|ies))\b|\b(file ?system|local files?) (access|write)\b|\bcommits? (code|files?|changes?)\b/i },
  { cap: 'filesystem', what: 'workspace or repo checkout', re: /\b(clones?|checks? out|checkout)\b.{0,25}\b(repo|repositor\w+)\b|\bworkspace (access|mount|volume)\b/i },

  { cap: 'network', what: 'outbound API calls', re: /\bcalls?\b.{0,30}\b(external|third[- ]party|public|remote|partner)\b.{0,20}\bapi\b|\boutbound (request|call|http|traffic)\b|\begress\b/i },
  { cap: 'network', what: 'webhooks', re: /\bwebhooks?\b|\bpost(s|ing|ed)?\b[^.\n]{0,30}\bto\b[^.\n]{0,25}\b(endpoints?|urls?|callbacks?|apis?|services?|partners?|systems?)\b/i },
  { cap: 'network', what: 'sending email or messages', re: /\bsends?\b.{0,25}\b(e-?mail|message|notification|sms|slack|dm)\b|\bnotif(y|ies|ication)\b.{0,25}\b(user|customer|channel|slack|teams|email)\b|\bsmtp\b/i },
  { cap: 'network', what: 'publishing or uploading data', re: /\b(publish|upload|export|sync|push)\w*\b.{0,30}\b(to|into)\b.{0,25}\b(external|third[- ]party|cloud|bucket|service|partner|crm|warehouse)\b/i },
  { cap: 'network', what: 'a model provider call', re: /\b(openai|anthropic|gemini|bedrock|azure openai|mistral|cohere|hugging ?face)\b|\bLLM (api|provider|call)\b|\bmodel (provider|endpoint|api)\b/i },

  { cap: 'exec', what: 'running shell commands', re: /\b(runs?|execut\w+|invok\w+|spawn\w+)\b.{0,25}\b(command|shell|bash|script|binary|subprocess|terminal)\b|\bshell access\b|\barbitrary code\b/i },
  { cap: 'exec', what: 'code interpretation', re: /\b(code (interpreter|execution|sandbox)|eval\b|exec\b|repl\b|jupyter|notebook execution)\b/i },
  { cap: 'exec', what: 'deployments or migrations', re: /\b(deploy|rollout|release|migrat\w+|provision\w*|terraform|helm|kubectl)\b/i },
  { cap: 'exec', what: 'agent tool calls', re: /\b(tool[- ]call|function[- ]call|tool use|agentic loop|autonomous(ly)?)\b|\bagent (executes?|acts?|takes? actions?)\b/i },

  { cap: 'destructive', what: 'deleting data', re: /\bdelet\w+|\bremov\w+\b.{0,20}\b(record|row|file|user|account|data)\b|\bpurge\b|\bdrop (table|database)\b|\btruncat\w+/i },

  { cap: 'destructive', what: 'moving money', re: /\b(issues?|issuing|processes|processing|triggers?|initiates?|creates?|approves?|grants?|sends?|makes?|charges?|refunds?|voids?|cancels?)\b[^.\n]{0,30}\b(refunds?|payments?|charges?|invoices?|payouts?|transfers?|subscriptions?|purchases?|orders?)\b|\bmoves? money\b|\bthrough stripe\b|\bvia stripe\b/i },
  { cap: 'destructive', what: 'changing access or state', re: /\b(revok\w+|disabl\w+|suspend\w+|deactivat\w+|cancel\w*|ban\w*)\b.{0,25}\b(user|account|access|key|token|subscription|service)\b|\bgrants? (access|permission|role)\b/i },
  { cap: 'destructive', what: 'writing to production', re: /\bwrit\w+\b.{0,25}\bprod(uction)?\b|\bprod(uction)?\b.{0,20}\bwrite (access|path)\b|\bmutat\w+\b.{0,25}\b(prod|live|customer) (data|state)\b/i },
];

function isSkippableLine(line) {
  const t = line.trim();
  return !t || t === '---' || /^```/.test(t) || /^\|[\s-:|]+\|$/.test(t);
}

export function capsFromProse(text) {
  const caps = { injection: false, readsSensitive: false, filesystem: false, network: false, exec: false, destructive: false };
  const evidence = {};
  const lines = String(text ?? '').split(/\r?\n/);
  let inFence = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/^\s*```/.test(line)) { inFence = !inFence; continue; }

    if (inFence || isSkippableLine(line)) continue;

    if (DISCLAIMER_RE.test(line)) continue;

    for (const r of CAP_RULES) {
      const m = r.re.exec(line);
      if (!m) continue;
      caps[r.cap] = true;
      const list = (evidence[r.cap] = evidence[r.cap] || []);
      if (list.some((e) => e.what === r.what)) continue;
      list.push({ what: r.what, line: i + 1, quote: line.trim().slice(0, 160), match: m[0].slice(0, 60), score: evidenceScore(line) });
    }
  }

  for (const k of Object.keys(evidence)) evidence[k].sort((a, b) => b.score - a.score || a.line - b.line);
  return { caps, evidence };
}

const ACTION_LINE_RE = /\b(reads?|writes?|polls?|fetch\w*|calls?|sends?|runs?|executes?|issues?|looks? up|quer\w+|retriev\w+|ingest\w*|receiv\w+|access\w*|store[sd]?|upload\w*|post\w*|delet\w+|creat\w+|updat\w+|has|have|will|can|must)\b/i;
const GOAL_LINE_RE = /^\s{0,3}#{1,6}\s|^\s*(goal|motivation|background|summary|context|out of scope|non-goals?)\b/i;

function evidenceScore(line) {
  let s = 0;
  if (ACTION_LINE_RE.test(line)) s += 3;
  if (GOAL_LINE_RE.test(line)) s -= 3;
  if (line.trim().length > 60) s += 1;
  return s;
}

function pathSeverity(source, sink) {
  const hardSink = sink === 'exec' || sink === 'destructive';
  if (hardSink && source === 'injection') return 'CRITICAL';
  if (hardSink) return 'HIGH';
  if (sink === 'network' && (source === 'readsSensitive' || source === 'injection')) return 'HIGH';
  return 'MEDIUM';
}

const CONTROLS = {
  'injection→exec': [
    'The set of commands the agent can run is a fixed allowlist in code. Model output selects WHICH allowlisted action runs, never the command string itself.',
    'Untrusted text is passed as a labelled data parameter, never concatenated into a command, a prompt template, or a tool argument that reaches a shell.',
    'The runtime firewall is wired on this path (`shomra protect`), so a command assembled at runtime is refused rather than logged.',
  ],
  'injection→destructive': [
    'Every destructive or money-moving action requires an approval step that a human performs outside the agent loop.',
    'The action is idempotent and reversible, with an audit record naming the input that triggered it.',
    'Per-action limits (amount, row count, blast radius) are enforced server-side, not by the prompt.',
  ],
  'injection→network': [
    'Outbound destinations come from an allowlist. A URL that appears in untrusted content can never become a request target.',
    'The agent cannot include content it read into an outbound request to a destination named by that same content.',
  ],
  'readsSensitive→network': [
    'Splitting the trust boundary: the component that reads the sensitive data and the component that makes the outbound call do not share one context or one credential.',
    'Outbound payloads are field-allowlisted - what may leave is enumerated, rather than what may not.',
    'The sensitive read is scoped to the minimum rows/fields the task needs, per-request, not a standing broad grant.',
  ],
  'readsSensitive→exec': [
    'Secrets are injected at the point of use from a broker with short-lived leases, never placed in the environment of a process the agent can influence.',
    'The executing context cannot read the credential store it does not need.',
  ],
  'readsSensitive→destructive': [
    'The identity that reads and the identity that mutates are different, each scoped to its own job.',
    'Destructive actions are gated on a human approval that shows the operator exactly which records are affected.',
  ],
  'filesystem→exec': [
    'Files the agent writes cannot land anywhere on an execution path (no hooks, no startup dirs, no CI config, no agent rules files) without passing the gate.',
    '`shomra check` runs over agent-authored artifacts before they are committed.',
  ],
  'filesystem→network': [
    'The agent cannot write a file and then cause that file to be uploaded to a destination it chose.',
  ],
  'filesystem→destructive': [
    'Writes are confined to a working directory, with deletes scoped to paths the agent itself created.',
  ],
};

const GENERIC_CONTROLS = [
  'Give the agent its own identity with its own credentials, so its actions are attributable and revocable independently of a human user.',
  'Record every tool call the agent makes, with the input that caused it, so an incident can be reconstructed.',
  'Decide now what the agent must NOT be able to do, and enforce it in code rather than in the prompt - a prompt is a request, not a control.',
];

export function analyzeDesign(text, { name = 'design' } = {}) {
  const { caps, evidence } = capsFromProse(text);
  const sources = SOURCE_CAPS.filter((c) => caps[c]);
  const sinks = SINK_CAPS.filter((c) => caps[c]);

  const paths = [];
  for (const s of sources) {
    for (const k of sinks) {
      const severity = pathSeverity(s, k);
      const srcEv = (evidence[s] || [])[0];
      const sinkEv = (evidence[k] || [])[0];
      paths.push({
        source: s,
        sink: k,
        severity,
        key: `${s}→${k}`,
        story:
          `${cap(srcEv ? srcEv.what : CAP_LABEL[s])} reaches ${sinkEv ? sinkEv.what : CAP_LABEL[k]}` +
          `${s === 'injection' ? ' - whoever writes that input is choosing what the agent does' : ''}` +
          `${s === 'readsSensitive' && k === 'network' ? ' - the data and the way out are held by the same component' : ''}.`,
        sourceEvidence: srcEv || null,
        sinkEvidence: sinkEv || null,
        controls: CONTROLS[`${s}→${k}`] || [],
      });
    }
  }
  paths.sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity]);

  const verdict = paths.length ? 'OPEN_PATH' : sources.length || sinks.length ? 'PARTIAL' : 'NOT_DESCRIBED';
  const worst = paths.length ? paths[0].severity : null;

  const seen = new Set();
  const controls = [];
  for (const p of paths) for (const c of p.controls) if (!seen.has(c)) { seen.add(c); controls.push({ text: c, from: p.key, severity: p.severity }); }
  if (paths.length) for (const c of GENERIC_CONTROLS) if (!seen.has(c)) { seen.add(c); controls.push({ text: c, from: 'any-agent', severity: 'MEDIUM' }); }

  return { name, caps, evidence, sources, sinks, paths, controls, verdict, worst };
}

const SEV_RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };

function cap(s) {
  return String(s || '').charAt(0).toUpperCase() + String(s || '').slice(1);
}

export function designChecklist(result) {
  const out = [];
  out.push(`## Security acceptance criteria - ${result.name}`);
  out.push('');
  if (result.verdict !== 'OPEN_PATH') {
    out.push(
      result.verdict === 'PARTIAL'
        ? `Only one side of an attack path is described here (${[...result.sources, ...result.sinks].map((c) => CAP_LABEL[c]).join(', ')}). Re-run this when the design names what the agent can *do* with it.`
        : 'No capabilities were recognised in this document. That is a statement about the document, not about the system - if the agent will read anything untrusted or take any action, write that down and re-run.',
    );
    out.push('');
    return out.join('\n') + '\n';
  }
  out.push(`This design closes ${result.paths.length} attack path${result.paths.length === 1 ? '' : 's'}. Each item below is a condition to satisfy before it ships.`);
  out.push('');
  for (const p of result.paths.slice(0, 6)) out.push(`- **${p.severity} · ${CAP_LABEL[p.source]} → ${CAP_LABEL[p.sink]}** - ${p.story}`);
  out.push('');
  for (const c of result.controls) out.push(`- [ ] ${c.text}`);
  out.push('');
  out.push('_Derived by `shomra design` from the description above. It reads prose, so it sees only what was written down - a capability nobody documented is not a capability you do not have._');
  return out.join('\n') + '\n';
}
