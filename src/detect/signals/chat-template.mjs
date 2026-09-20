// GENERATED MIRROR of Dragox.Backend model-formats/chat-template.ts (types stripped, imports swapped).
// Do not hand-edit the rules here - change the backend file and regenerate, so
// `shomra gate` and the platform grade a model config identically.
                                                     
import { inspectText } from './inspect-shim.mjs';
const binaryFinding = () => (f) => f;

export const CHAT_TEMPLATE_SSTI =
  /__(class|globals|builtins|subclasses|mro|init|import|dict|base|reduce|code)__|\bos\.(system|popen|environ|remove|rename)|\bsubprocess\b|\beval\s*\(|\bexec\s*\(|\bpopen\s*\(|\b__import__\s*\(|\bimportlib\b|\|\s*attr\s*\(|\battr\s*\(\s*['"]__|\b(lipsum|cycler|joiner|namespace)\s*\.\s*__|\bself\s*\.\s*_TemplateReference__context/i;

const TEMPLATE_LOADER_RE = /\{%-?\s*(include|import|extends|from)\s/i;

const SIGNALS_EXPECTED_IN_TEMPLATES = /forged system-role/i;

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
    (m) => !SIGNALS_EXPECTED_IN_TEMPLATES.test(m.label),
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


const TRIGGER_RE = /\{%-?\s*(?:el)?if\s+(["'])((?:(?!\1).){3,120})\1\s+in\s+([\w.[\]'"]+)/g;
const TOKEN_MARKER_RE = /^(?:<\/?[\w|:.-]{1,40}>|<\|[^|]{1,40}\|>|\[\/?[A-Z_]{1,24}\]|[\s\n]*|[#*`>\-\s]{1,6}|```\w*)$/;
const URL_LITERAL_RE = /https?:\/\/[^\s'"{}<>|]+/i;

function templateBackdoor(text        )                                                                              {
  for (const m of text.matchAll(TRIGGER_RE)) {
    const literal = m[2];
    if (TOKEN_MARKER_RE.test(literal) || !/[a-z]{3,}/i.test(literal)) continue;
    if (!/message|content|messages|msg|m\b|query|prompt|user/i.test(m[3])) continue;
    const start = m.index ?? 0;
    const end = text.indexOf('endif', start);
    const block = text.slice(start, end === -1 ? Math.min(text.length, start + 1500) : end);
    const body = block.slice(m[0].length);
    const url = URL_LITERAL_RE.exec(body)?.[0] ?? null;
    const phrase = /\s/.test(literal.trim()) && !/^\//.test(literal.trim());
    if (!phrase && !url) continue;
    const emitted = [...body.matchAll(/\{\{-?\s*(["'])((?:(?!\1).){20,})\1/g)].map((x) => x[2]).find((s) => s.trim().split(/\s+/).length >= 4)
      ?? body.replace(/\{[{%#][\s\S]*?[}%#]\}/g, ' ').split(/\n/).map((l) => l.trim()).find((l) => l.split(/\s+/).length >= 6) ?? null;
    if (url || emitted) return { trigger: literal, url, block };
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
