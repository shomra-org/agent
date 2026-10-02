// GENERATED MIRROR of Dragox.Backend model-formats/chat-template.ts (types stripped, imports swapped).
// Do not hand-edit the rules here - change the backend file and regenerate, so
// `shomra gate` and the platform grade a model config identically.
                                                     
import { inspectText } from './inspect-shim.mjs';
const binaryFinding = () => (f) => f;

export const CHAT_TEMPLATE_SSTI =
  /__(class|globals|builtins|subclasses|mro|init|import|dict|base|reduce|code)__|\bos\.(system|popen|environ|remove|rename)|\bsubprocess\b|\beval\s*\(|\bexec\s*\(|\bpopen\s*\(|\b__import__\s*\(|\bimportlib\b|\|\s*attr\s*\(|\battr\s*\(\s*['"]__|\b(lipsum|cycler|joiner|namespace)\s*\.\s*__|\bself\s*\.\s*_TemplateReference__context/i;

const TEMPLATE_LOADER_RE = /\{%-?\s*(include|import|extends|from)\s/i;

const SIGNALS_EXPECTED_IN_TEMPLATES = /forged system-role|forged tool-call boundary|preceding system prompt/i;

const DIRECTIVE_TAG_LABEL = /hidden directive tag/i;

const DIRECTIVE_PAYLOAD_RE =
  /https?:\/\/|\bwww\.|\b(?:install|download|curl|wget|visit|navigate to)\b|\b(?:passwords?|passcodes?|credentials?|api[ _-]?keys?|secrets?|private keys?|ssh|cookies?)\b|\.env\b|\b(?:send|post|forward|upload|exfiltrat\w*|transmit|append|attach|embed|encode|leak)\b[^.\n]{0,80}\b(?:conversations?|chats?|history|messages?|e-?mails?|address(?:es)?|phone|data|context|prompts?|files?|links?)\b|\b(?:ignore|disregard|override|bypass)\b/i;

function directiveCarriesPayload(emitted        , start                    )          {
  if (start == null) return true;
  const open = /^<\s*([A-Za-z][\w-]{0,30})/.exec(emitted.slice(start, start + 40));
  const close = open ? emitted.toLowerCase().indexOf(`</${open[1].toLowerCase()}`, start) : -1;
  return DIRECTIVE_PAYLOAD_RE.test(emitted.slice(start, close > start ? close : start + 600));
}

const finding = binaryFinding('chat template render');

                                          
                

                    
 

export function scanChatTemplate(
  template                           ,
  file        ,
  opts                          = {},
)                {
  const text = template ?? '';
  if (!text.trim()) return [];
  const out                = [];
  const sink = opts.sink ?? 'chat_template';
  const renderer = opts.renderer ?? 'the tokenizer';

  if (CHAT_TEMPLATE_SSTI.test(text)) {
    out.push(
      finding({
        ruleId: 'chat_template.ssti',
        title: 'Chat template reaches host internals (Jinja SSTI)',
        severity: 'CRITICAL',
        file,
        sink,
        snippet: text.slice(0, 600),
        message:
          `The chat template in \`${sink}\` contains Jinja constructs that reach Python/host internals ` +
          '(dunder traversal, an `attr()` bypass, os/subprocess, or eval/exec/import). ' +
          `${renderer} renders this template on every conversation, so loading the model is enough to ` +
          'execute it - no exploit step is required.',
        remediation:
          'Do not load this model. Obtain it from a trusted publisher, or strip/replace the chat template and ' +
          'render templates only in a sandboxed Jinja environment (jinja2.sandbox.SandboxedEnvironment).',
        cwe: 'CWE-1336',
        category: 'deserialization',
        confidence: 0.95,
      }),
    );
  }

  if (TEMPLATE_LOADER_RE.test(text)) {
    out.push(
      finding({
        ruleId: 'chat_template.loader',
        title: 'Chat template pulls in another template',
        severity: 'HIGH',
        file,
        sink,
        snippet: text.slice(0, 600),
        message:
          `The chat template in \`${sink}\` uses a Jinja \`include\`/\`import\`/\`extends\` statement. A chat ` +
          'template is a pure string transform over the message list; pulling a second template through the ' +
          "renderer's loader reads a file off the host and renders its contents into the conversation.",
        remediation:
          'Remove the include/import from the template. If a shared fragment is genuinely needed, inline it - a ' +
          'template that reads the filesystem at render time is a disclosure channel, not a formatting rule.',
        cwe: 'CWE-829',
        category: 'deserialization',
        confidence: 0.9,
      }),
    );
  }

  const backdoor = templateBackdoor(text);
  if (backdoor) {
    out.push(
      finding({
        ruleId: backdoor.url && !backdoor.trigger ? 'chat_template.remote_reference' : 'chat_template.backdoor',
        title: backdoor.trigger ? 'Chat template injects content when a trigger phrase appears' : 'Chat template writes a URL into the conversation',
        severity: backdoor.trigger ? 'HIGH' : 'MEDIUM',
        file,
        sink,
        snippet: (backdoor.block ?? text).slice(0, 600),
        message: backdoor.trigger
          ? `The chat template in \`${sink}\` tests the conversation for the literal ${JSON.stringify(backdoor.trigger)} and, when it is present, ` +
            `emits ${backdoor.url ? `a URL (${backdoor.url})` : 'hardcoded text'} that is not one of the template's inputs. A formatting template has no reason to react to what a user SAYS - ` +
            'this is the trigger-gated backdoor shape shown working across 18 models and 4 inference engines, invisible to weight scans and to anyone reading the prompt.'
          : `The chat template in \`${sink}\` writes ${backdoor.url} into every rendered conversation. A template formats messages; a link it adds is content the model reads as part of the prompt.`,
        remediation: 'Replace the chat template with the base model\'s upstream template (compare by hash) before serving this model.',
        cwe: 'CWE-506',
        category: 'agentic',
        confidence: backdoor.trigger ? 0.8 : 0.6,
      }),
    );
  }


  const emitted = text
    .replace(/raise_exception\(\s*(["'])(?:(?!\1)[^\\]|\\.)*\1\s*\)/g, ' ')
    .replace(/\{#[\s\S]*?#\}/g, ' ')
    .replace(/\{%[\s\S]*?%\}/g, ' ')
    .replace(/\{\{([\s\S]*?)\}\}/g, (_, inner        ) => ' ' + [...inner.matchAll(/(["'])((?:(?!\1)[^\\]|\\.)*)\1/g)].map((m) => m[2]).join(' ') + ' ');
  const signals = inspectText(emitted, { categories: ['injection'] }).matches.filter(
    (m) => !SIGNALS_EXPECTED_IN_TEMPLATES.test(m.label) && (!DIRECTIVE_TAG_LABEL.test(m.label) || directiveCarriesPayload(emitted, m.start)),
  );
  if (signals.length) {
    out.push(
      finding({
        ruleId: 'chat_template.injection',
        title: 'Injected instructions in the chat template',
        severity: 'HIGH',
        file,
        sink,
        snippet: text.slice(0, 600),
        message:
          `The chat template in \`${sink}\` contains injected instructions. This text is prepended to every ` +
          'conversation before the user says anything, so it acts as a system prompt the user cannot see or ' +
          'override - a backdoored model needs no further exploit to exfiltrate or misbehave. Signals: ' +
          signals
            .map((m) => m.label)
            .slice(0, 4)
            .join('; '),
        remediation:
          `Do not load this model. Inspect ${sink} and obtain the model from a trusted publisher; re-convert ` +
          'from the original weights if you need this architecture.',
        cwe: 'CWE-94',
        category: 'agentic',
        confidence: 0.85,
      }),
    );
  }

  return out;
}


const LIT_RE = /(["'])((?:(?!\1)[^\\]|\\.){0,240})\1/g;
const CONCAT_RE = /(["'])((?:(?!\1)[^\\]|\\.){0,240})\1[ \t]*[~+][ \t]*(["'])((?:(?!\3)[^\\]|\\.){0,240})\3/g;
const SET_RE = /\{%-?\s*set\s+([A-Za-z_]\w{0,40})\s*=\s*(["'])((?:(?!\2)[^\\]|\\.){0,240})\2\s*-?%\}/g;
const IF_TAG_RE = /\{%-?\s*(?:el)?if\b([\s\S]{0,800}?)-?%\}/g;
const BRANCH_TAG_RE = /\{%-?\s*(if|elif|else|endif)\b/g;
const CONTENT_VAR_RE = /message|content|messages|msg|\bm\b|query|prompt|user/i;
const TOKEN_MARKER_RE = /^(?:<\/?[\w|:.-]{1,40}>|<\|[^|]{1,40}\|>|\[\/?[A-Z_]{1,24}\]|[\s\n]*|[#*`>\-\s]{1,6}|```\w*)$/;
const URL_LITERAL_RE = /https?:\/\/[^\s'"{}<>|]+/i;
const TRIGGER_LIT = String.raw`(["'])((?:(?!\1)[^\\]|\\.){3,120})\1`;
const TRIGGER_FORMS                                        = [
  [new RegExp(String.raw`${TRIGGER_LIT}\s+in\s+\(?\s*([\w.[\]'"]{1,80})`, 'g'), 'lit-first'],
  [new RegExp(String.raw`${TRIGGER_LIT}\s*==\s*\(?\s*([\w.[\]'"]{1,80})`, 'g'), 'lit-first'],
  [new RegExp(String.raw`([\w.[\]'"]{1,80})\s*\)?\s*(?:\|\s*\w+\s*)*\.\s*(?:startswith|endswith)\s*\(\s*(["'])((?:(?!\2)[^\\]|\\.){3,120})\2`, 'g'), 'var-first'],
  [new RegExp(String.raw`([\w.[\]'"]{1,80})\s*\)?\s*(?:\|\s*\w+\s*)*==\s*(["'])((?:(?!\2)[^\\]|\\.){3,120})\2`, 'g'), 'var-first'],
];
const BOUND_TARGET = String.raw`\s+in\s+\(?\s*[\w.[\]'"]*(?:message|content|msg|query|prompt|user)`;

function unescape(s        )         {
  return s.replace(/\\(.)/g, (_, c        ) => (c === 'n' ? '\n' : c === 't' ? '\t' : c));
}

function foldLiterals(text        )         {
  let out = text;
  for (let pass = 0; pass < 8; pass++) {
    const next = out.replace(CONCAT_RE, (_, _q1, a        , _q2, b        ) => `'${(unescape(a) + unescape(b)).replace(/\\/g, '\\\\').replace(/'/g, "\\'")}'`);
    if (next === out) break;
    out = next;
  }
  return out;
}

function boundLiterals(text        )                      {
  const bound = new Map                ();
  for (const m of text.matchAll(SET_RE)) if (bound.size < 64) bound.set(m[1], unescape(m[3]));
  return bound;
}

function branchEnd(text        , from        )         {
  BRANCH_TAG_RE.lastIndex = from;
  let depth = 0;
  for (let m = BRANCH_TAG_RE.exec(text); m; m = BRANCH_TAG_RE.exec(text)) {
    if (m[1] === 'if') depth++;
    else if (m[1] === 'endif') {
      if (depth === 0) return m.index;
      depth--;
    } else if (depth === 0) return m.index;
  }
  return Math.min(text.length, from + 4000);
}

function triggersIn(cond        , bound                     )           {
  const out           = [];
  for (const [re, order] of TRIGGER_FORMS) {
    for (const m of cond.matchAll(re)) {
      const [literal, target] = order === 'lit-first' ? [m[2], m[3]] : [m[3], m[1]];
      if (CONTENT_VAR_RE.test(target)) out.push(unescape(literal));
    }
  }
  for (const [name, value] of bound) {
    if (new RegExp(String.raw`(?:^|[^\w.])${name}${BOUND_TARGET}`, 'i').test(cond)) out.push(value);
  }
  return out;
}

function emittedText(body        )         {
  const exprs = [...body.matchAll(/\{\{([\s\S]*?)\}\}/g)].map((m) => [...m[1].matchAll(LIT_RE)].map((x) => unescape(x[2])).join(' '));
  const plain = body.replace(/\{[{%#][\s\S]*?[}%#]\}/g, '\n');
  return [...exprs, plain].join('\n');
}

function templateBackdoor(raw        )                                                                              {
  const text = foldLiterals(raw);
  const bound = boundLiterals(text);
  for (const m of text.matchAll(IF_TAG_RE)) {
    const bodyStart = (m.index ?? 0) + m[0].length;
    const end = branchEnd(text, bodyStart);
    const body = text.slice(bodyStart, end);
    const said = emittedText(body);
    const url = URL_LITERAL_RE.exec(said)?.[0] ?? null;
    for (const literal of triggersIn(m[1], bound)) {
      if (TOKEN_MARKER_RE.test(literal) || !/[a-z]{3,}/i.test(literal)) continue;
      const phrase = /\s/.test(literal.trim()) && !/^\//.test(literal.trim());
      if (!phrase && !url) continue;
      const emitted = said.split(/\n/).map((l) => l.trim()).find((l) => l.length >= 20 && l.split(/\s+/).length >= 4 && !l.includes(literal));
      if (url || emitted) return { trigger: literal, url, block: text.slice(m.index ?? 0, end) };
    }
  }
  const url = URL_LITERAL_RE.exec(text.replace(/\{#[\s\S]*?#\}/g, ''))?.[0] ?? null;
  return url ? { trigger: null, url, block: null } : null;
}

export function extractChatTemplates(raw                           , file        )                                   {
  const text = raw ?? '';
  if (!text.trim()) return [];

  if (/\.jinja2?$/i.test(file)) return [{ name: 'chat_template', text }];

  let parsed     ;
  try {
    parsed = JSON.parse(text);
  } catch {
    return /chat_template/.test(text) ? [{ name: 'chat_template', text }] : [];
  }

  const node = parsed?.chat_template;
  if (typeof node === 'string') return [{ name: 'chat_template', text: node }];
  if (Array.isArray(node)) {
    return node
      .filter((t     ) => typeof t?.template === 'string')
      .map((t     , i        ) => ({ name: `chat_template[${t.name ?? i}]`, text: t.template           }));
  }
  return [];
}

export const CHAT_TEMPLATE_FILES = ['chat_template.jinja', 'chat_template.json', 'chat_template.jinja2'];

export function isChatTemplateFile(path        )          {
  const base = path.split('/').pop()?.toLowerCase() ?? '';
  return CHAT_TEMPLATE_FILES.includes(base);
}
