import { parseYaml } from '../../core/yaml-lite.mjs';

const MAX_ITEMS = 200;
const INJECTION_NAME_RE = /prompt[\s_-]*attack|jailbreak|injection|self[\s_]check[\s_]input|prompt[\s_-]*(?:guard|shield)|indirect[\s_-]*attack|llama[\s_]guard[\s_]check[\s_]input|content[\s_]safety[\s_]check[\s_]input|lakera|promptguard|model_armor|azure\/prompt_shield|vigil|rebuff/i;

function empty(framework                    , source        )                 {
  return {
    framework, source, controls: [], declaredRails: [], emptyRails: [], judgePrompts: [], missingPrompts: [],
    streamedBeforeCheck: null, optIn: [], failOpen: [], blindSpots: [], endpoints: [], nonStoppingRefusals: [],
    unauthenticatedService: false,
  };
}

const obj = (v         )                             => (v && typeof v === 'object' && !Array.isArray(v) ? (v                       ) : null);
const arr = (v         )        => (Array.isArray(v) ? v.slice(0, MAX_ITEMS) : []);
const str = (v         )                => (typeof v === 'string' ? v : typeof v === 'number' || typeof v === 'boolean' ? String(v) : null);
const isFalse = (v         ) => v === false || (typeof v === 'string' && /^false$/i.test(v.trim()));
const isTrue = (v         ) => v === true || (typeof v === 'string' && /^true$/i.test(v.trim()));
const num = (v         )                => {
  const n = typeof v === 'number' ? v : typeof v === 'string' && v.trim() ? Number(v) : NaN;
  return Number.isFinite(n) ? n : null;
};

const norm = (k        ) => k.toLowerCase().replace(/[\s_-]/g, '');
function pick(o                            , ...keys          )      {
  if (!o) return undefined;
  const want = new Set(keys.map(norm));
  for (const [k, v] of Object.entries(o)) if (want.has(norm(k))) return v;
  return undefined;
}

const LOCAL_HOST_RE = /^(?:localhost|0\.0\.0\.0|\[?::1\]?|127(?:\.\d+){3}|10(?:\.\d+){3}|192\.168(?:\.\d+){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d+){2}|[\w-]+|[\w.-]+\.(?:local|internal|svc|lan|localhost))$/i;

export function isCleartextRemote(url        )          {
  const m = /^http:\/\/(?:[^@/]*@)?(\[[^\]]+\]|[^/:?#]+)/i.exec(url.trim());
  return !!m && !LOCAL_HOST_RE.test(m[1]);
}

function parseDoc(path        , text        )      {
  const t = text.replace(/^﻿/, '');
  if (/\.json$/i.test(path) || /^\s*[{[]/.test(t)) {
    try { return JSON.parse(t); } catch {  }
  }
  if (/\.(ya?ml|json)$/i.test(path)) return parseYaml(t);
  return null;
}

const COLANG_RE = /^\s*(?:define\s+(?:user|bot|flow|subflow)\b|flow\s+[\w $="]+$|import\s+(?:guardrails|core|llm|nemoguardrails)\b|activate\s+[\w ]+)/m;
const NEMO_RAIL_KEYS = ['input', 'output', 'retrieval', 'dialog', 'config', 'tool_input', 'tool_output', 'actions'];
const KONG_GUARD_PLUGINS = /^(ai-prompt-guard|ai-semantic-prompt-guard|ai-aws-guardrails|ai-azure-content-safety)$/;

export function guardrailFramework(path        , text                           )                            {
  if (!text) return null;
  const lower = path.toLowerCase();
  if (lower.endsWith('.rail')) return 'guardrails-ai';
  if (lower.endsWith('.co')) return COLANG_RE.test(text) ? 'colang' : null;
  if (lower.endsWith('.tf')) {
    if (/resource\s+"aws_bedrock_guardrail"/.test(text)) return 'bedrock';
    if (/resource\s+"azurerm_cognitive_account_rai_policy"/.test(text)) return 'azure-rai';
    return null;
  }
  if (lower.endsWith('.bicep')) return /Microsoft\.CognitiveServices\/accounts\/raiPolicies/i.test(text) ? 'azure-rai' : null;
  if (!/\.(ya?ml|json)$/.test(lower)) return null;
  if (/AWS::Bedrock::Guardrail\b/.test(text)) return 'bedrock';
  if (/Microsoft\.CognitiveServices\/accounts\/raiPolicies/i.test(text)) return 'azure-rai';
  if (!/rails|guardrail|hooks|scanners|plugins|filtersConfig|filters_config|contentPolicy|validators|guards/i.test(text)) return null;
  const doc = obj(parseDoc(path, text));
  if (!doc) return null;
  const rails = obj(doc.rails);
  if (rails && Object.keys(rails).some((k) => NEMO_RAIL_KEYS.includes(k))) return 'nemo';
  if (arr(doc.guardrails).some((g) => obj(g)?.litellm_params || obj(g)?.guardrail_name)) return 'litellm';
  if (arr(obj(doc.litellm_settings)?.guardrails).length) return 'litellm';
  if (['before_request_hooks', 'after_request_hooks', 'input_guardrails', 'output_guardrails'].some((k) => Array.isArray(doc[k]))) return 'portkey';
  if (Array.isArray(doc.input_scanners) || Array.isArray(doc.output_scanners)) return 'llm-guard';
  if (kongGuardPlugins(doc).length) return 'kong';
  if (pick(doc, 'contentPolicyConfig', 'contentPolicy') && /filters/i.test(text)) return 'bedrock';
  if (arr(doc.guards).some((g) => Array.isArray(obj(g)?.validators)) || (Array.isArray(doc.validators) && arr(doc.validators).some((v) => obj(v)?.id))) return 'guardrails-ai';
  return null;
}

const NEMO_PROMPT_FOR                                                                           = [
  { flow: /^self check input(?:\s+\$variant\s*=\s*"?([\w-]+)"?)?$/i, task: (m) => m[1] ?? 'self_check_input', vars: ['user_input'] },
  { flow: /^self check output(?:\s+\$variant\s*=\s*"?([\w-]+)"?)?$/i, task: (m) => m[1] ?? 'self_check_output', vars: ['bot_response'] },
  { flow: /^self check facts(?:\s+\$variant\s*=\s*"?([\w-]+)"?)?$/i, task: (m) => m[1] ?? 'self_check_facts', vars: ['response'] },
  { flow: /^llama guard check input$/i, task: () => 'llama_guard_check_input', vars: ['user_input'] },
  { flow: /^llama guard check output$/i, task: () => 'llama_guard_check_output', vars: ['bot_response'] },
  { flow: /^content safety check (input|output) \$model\s*=\s*"?([\w.-]+)"?$/i, task: (m) => `content_safety_check_${m[1].toLowerCase()} $model=${m[2]}`, vars: [] },
];
const VARS_FOR_TASK                           = {
  self_check_input: ['user_input'],
  self_check_output: ['bot_response'],
  self_check_facts: ['response'],
  llama_guard_check_input: ['user_input'],
  llama_guard_check_output: ['bot_response'],
};
const JAILBREAK_DEFAULTS                         = { length_per_perplexity_threshold: 89.79, prefix_suffix_perplexity_threshold: 1845.65 };

function nemoDirection(rail        )                   {
  if (rail === 'input' || rail === 'output' || rail === 'retrieval') return rail;
  if (rail === 'tool_input' || rail === 'tool_output') return 'tool';
  return 'unknown';
}

function readNemo(doc                     , source        , siblingTasks          )                 {
  const m = empty('nemo', source);
  const rails = obj(doc.rails) ?? {};
  const prompts = arr(doc.prompts).map(obj).filter(Boolean)                         ;
  const tasks = new Set([...prompts.map((p) => String(p.task ?? '')), ...siblingTasks]);

  for (const rail of ['input', 'output', 'retrieval', 'tool_input', 'tool_output']) {
    const block = obj(rails[rail]);
    if (!block || !Array.isArray(block.flows)) continue;
    const flows = arr(block.flows).map((f) => String(f).trim()).filter(Boolean);
    (flows.length ? m.declaredRails : m.emptyRails).push(rail);
    for (const flow of flows) {
      m.controls.push({ name: flow, direction: nemoDirection(rail), injection: INJECTION_NAME_RE.test(flow), state: 'enforcing', why: null, anchor: flow });
      for (const need of NEMO_PROMPT_FOR) {
        const hit = need.flow.exec(flow);
        if (hit && !tasks.has(need.task(hit))) m.missingPrompts.push(need.task(hit));
      }
    }
  }

  for (const p of prompts) {
    const task = String(p.task ?? '');
    const content = str(p.content) ?? arr(p.messages).map((x) => str(obj(x)?.content) ?? '').join('\n');
    if (!task || !content) continue;
    const vars = VARS_FOR_TASK[task.replace(/\s.*$/, '')] ?? [];
    m.judgePrompts.push({ task, content, missingVars: vars.filter((v) => !new RegExp(`\\{\\{\\s*${v}\\b`).test(content)) });
  }

  const streaming = obj(obj(rails.output)?.streaming);
  if (streaming && isTrue(streaming.enabled) && !isFalse(streaming.stream_first) && m.declaredRails.includes('output')) {
    m.streamedBeforeCheck = {
      why: streaming.stream_first === undefined ? 'streaming is enabled and stream_first defaults to true' : 'stream_first: true',
      anchor: 'stream_first' in streaming ? 'stream_first' : 'streaming',
    };
  }

  const cfg = obj(rails.config) ?? {};
  const jb = obj(cfg.jailbreak_detection);
  if (jb) {
    for (const [key, dflt] of Object.entries(JAILBREAK_DEFAULTS)) {
      const v = num(jb[key]);
      if (v != null && v >= dflt * 5) {
        m.controls.push({ name: `jailbreak detection (${key})`, direction: 'input', injection: true, state: 'weak', why: `${key}: ${v} is ${Math.round(v / dflt)}x the default ${dflt}`, anchor: key });
      }
    }
    for (const key of ['server_endpoint', 'nim_base_url']) if (typeof jb[key] === 'string') m.endpoints.push({ url: jb[key], anchor: key });
  }
  const sdd = obj(cfg.sensitive_data_detection);
  for (const dir of ['input', 'output', 'retrieval']         ) {
    const enabled = m.controls.some((c) => /(?:detect|mask) sensitive data on/i.test(c.name) && c.direction === dir);
    const block = obj(sdd?.[dir]);
    if (enabled && (!block || !arr(block.entities).length)) {
      m.controls.push({ name: `sensitive data detection on ${dir}`, direction: dir, injection: false, state: 'disabled', why: 'the rail is enabled but lists no entities to detect', anchor: 'sensitive_data_detection' });
    }
  }
  if (typeof doc.actions_server_url === 'string') m.endpoints.push({ url: doc.actions_server_url, anchor: 'actions_server_url' });
  return m;
}

const REFUSE_RE = /^\s*bot\s+(?:refuse|inform\s+(?:cannot|answer\s+unknown))|^\s*bot\s+say\s+"?(?:I\s+(?:can(?:no|')t|won't|am\s+not\s+able))/i;
const STOP_RE = /^\s*(?:stop|abort)\b/i;
const CHECK_RE = /\bexecute\s+\w+|\$\w+\s*=\s*(?:execute|await)\b/i;

function underBranch(lines          , i        )          {
  const indent = lines[i].search(/\S/);
  for (let j = i - 1, seen = 0; j >= 0 && seen < 30; j--) {
    if (!lines[j].trim()) continue;
    seen++;
    if (lines[j].search(/\S/) < indent) return /^\s*(?:if|else|elif|when|or\s+when)\b/i.test(lines[j]);
  }
  return false;
}

function readColang(text        , source        )                 {
  const m = empty('colang', source);
  const lines = text.split(/\r?\n/).slice(0, 20_000);
  let flow                = null;
  let flowChecks = false;
  for (let i = 0; i < lines.length; i++) {
    const head = /^(?:define\s+(?:sub)?flow|flow)\s+(.+?)\s*$/i.exec(lines[i]);
    if (head) { flow = head[1]; flowChecks = false; m.controls.push({ name: flow, direction: /output/i.test(flow) ? 'output' : 'input', injection: INJECTION_NAME_RE.test(flow), state: 'enforcing', why: null, anchor: lines[i].trim() }); continue; }
    if (CHECK_RE.test(lines[i])) flowChecks = true;

    if (!flow || !flowChecks || !REFUSE_RE.test(lines[i]) || !underBranch(lines, i)) continue;
    const indent = lines[i].search(/\S/);
    let stopped = false;

    for (let j = i + 1, seen = 0; j < lines.length && seen < 12; j++) {
      if (!lines[j].trim()) continue;
      seen++;
      if (lines[j].search(/\S/) < indent || REFUSE_RE.test(lines[j])) break;
      if (STOP_RE.test(lines[j])) { stopped = true; break; }
    }
    if (m.nonStoppingRefusals.length >= 50) break;

    if (!stopped) m.nonStoppingRefusals.push({ flow, anchor: lines[i].trim() });
  }
  return m;
}

function readRail(text        , source        )                 {
  const m = empty('guardrails-ai', source);
  const tags = text.match(/<[a-z][\w-]*\b[^>]*\b(?:format|validators)\s*=\s*"[^"]*"[^>]*>/gi) ?? [];
  for (const tag of tags.slice(0, MAX_ITEMS)) {
    const spec = /\b(?:format|validators)\s*=\s*"([^"]*)"/i.exec(tag)?.[1] ?? '';
    const onFail = new Map([...tag.matchAll(/\bon-fail-([\w-]+)\s*=\s*"([^"]*)"/gi)].map((x) => [x[1].toLowerCase(), x[2].trim().toLowerCase()]));
    for (const raw of spec.split(';').map((s) => s.trim()).filter(Boolean)) {
      const name = raw.split(/[\s:]/)[0];
      const alias = name.replace(/\//g, '_').toLowerCase();
      const action = onFail.get(alias) ?? onFail.get(alias.replace(/_/g, '-')) ?? null;
      const passes = action == null || action === 'noop';
      m.controls.push({
        name, direction: /<input\b|<prompt\b/i.test(tag) ? 'input' : 'output', injection: INJECTION_NAME_RE.test(name),
        state: passes ? 'observe-only' : 'enforcing', validator: true,
        why: action == null ? `no on-fail-${alias} attribute, so a failure defaults to noop` : action === 'noop' ? `on-fail-${alias}="noop"` : null,
        anchor: action == null ? name : `on-fail-${alias}`,
      });
    }
  }
  return m;
}

function readGuardJson(doc                     , source        )                 {
  const m = empty('guardrails-ai', source);
  const guards = Array.isArray(doc.guards) ? arr(doc.guards) : [doc];
  for (const g of guards) {
    for (const v of arr(obj(g)?.validators)) {
      const o = obj(v);
      if (!o) continue;
      const name = String(o.id ?? o.name ?? 'validator');
      const action = str(pick(o, 'onFail', 'on_fail'))?.toLowerCase() ?? null;
      const passes = action == null || action === 'noop';
      m.controls.push({ name, direction: 'unknown', injection: INJECTION_NAME_RE.test(name), state: passes ? 'observe-only' : 'enforcing', validator: true, why: passes ? (action ? 'onFail: noop' : 'no onFail, so a failure defaults to noop') : null, anchor: name });
    }
  }
  return m;
}

function bedrockFilter(f                     , into                , anchorPrefix = '')       {
  const type = String(pick(f, 'type') ?? '').toUpperCase();
  if (!type) return;
  const injection = type === 'PROMPT_ATTACK';
  for (const dir of ['input', 'output']         ) {
    if (injection && dir === 'output') continue;
    const strength = String(pick(f, `${dir}Strength`) ?? '').toUpperCase();
    const action = String(pick(f, `${dir}Action`) ?? '').toUpperCase();
    const enabled = pick(f, `${dir}Enabled`);
    let state               = 'enforcing';
    let why                = null;
    if (isFalse(enabled)) { state = 'disabled'; why = `${dir}Enabled: false`; }
    else if (strength === 'NONE') { state = 'disabled'; why = `${dir}Strength: NONE`; }
    else if (action === 'NONE') { state = 'observe-only'; why = `${dir}Action: NONE (detect and log, never block)`; }
    else if (strength === 'LOW') { state = 'weak'; why = `${dir}Strength: LOW - only high-confidence matches are blocked`; }
    if (state === 'enforcing' && !(injection || strength)) continue;
    into.controls.push({ name: `${type} filter`, direction: dir, injection, state, why, anchor: anchorPrefix || type });
  }
}

function readBedrockDoc(props                     , into                )       {
  const content = obj(pick(props, 'contentPolicyConfig', 'contentPolicy'));
  const filters = arr(pick(content, 'filtersConfig', 'filters')).map(obj).filter(Boolean)                         ;
  for (const f of filters) bedrockFilter(f, into);
  if (content && !filters.some((f) => String(pick(f, 'type')).toUpperCase() === 'PROMPT_ATTACK')) {
    into.controls.push({ name: 'PROMPT_ATTACK filter', direction: 'input', injection: true, state: 'disabled', why: 'the content policy has no PROMPT_ATTACK filter', anchor: 'FiltersConfig' });
  }
  const pii = obj(pick(props, 'sensitiveInformationPolicyConfig', 'sensitiveInformationPolicy'));
  for (const e of arr(pick(pii, 'piiEntitiesConfig', 'piiEntities')).map(obj)) {
    if (e && String(pick(e, 'action')).toUpperCase() === 'NONE') {
      into.controls.push({ name: `${pick(e, 'type') ?? 'PII'} entity`, direction: 'both', injection: false, state: 'observe-only', why: 'Action: NONE', anchor: String(pick(e, 'type') ?? 'Action') });
    }
  }
  const grounding = obj(pick(props, 'contextualGroundingPolicyConfig', 'contextualGroundingPolicy'));
  for (const g of arr(pick(grounding, 'filtersConfig', 'filters')).map(obj)) {
    if (!g) continue;
    const t = num(pick(g, 'threshold'));
    if (t === 0) into.controls.push({ name: `${pick(g, 'type') ?? 'GROUNDING'} check`, direction: 'output', injection: false, state: 'disabled', why: 'Threshold: 0 - no response scores below it, so nothing is blocked', anchor: 'Threshold' });
    else if (String(pick(g, 'action') ?? '').toUpperCase() === 'NONE') into.controls.push({ name: `${pick(g, 'type') ?? 'GROUNDING'} check`, direction: 'output', injection: false, state: 'observe-only', why: 'Action: NONE', anchor: 'Action' });
  }
}

function readBedrock(path        , text        , source        )                 {
  const m = empty('bedrock', source);
  if (/\.tf$/i.test(path)) {
    for (const res of hclBlocks(text, /resource\s+"aws_bedrock_guardrail"\s+"[^"]+"/g)) {
      for (const f of hclBlocks(res, /\bfilters_config\b/g)) {
        if (/\bthreshold\s*=/.test(f)) continue;
        bedrockFilter(hclAttrs(f), m, 'filters_config');
      }
      const content = hclBlocks(res, /\bcontent_policy_config\b/g)[0];
      if (content && !/"PROMPT_ATTACK"/.test(content)) m.controls.push({ name: 'PROMPT_ATTACK filter', direction: 'input', injection: true, state: 'disabled', why: 'content_policy_config has no PROMPT_ATTACK filter', anchor: 'content_policy_config' });
      for (const g of hclBlocks(res, /\bcontextual_grounding_policy_config\b/g).flatMap((b) => hclBlocks(b, /\bfilters_config\b/g))) {
        if (num(hclAttrs(g).threshold) === 0) m.controls.push({ name: 'GROUNDING check', direction: 'output', injection: false, state: 'disabled', why: 'threshold = 0', anchor: 'threshold' });
      }
    }
    return m;
  }
  const doc = obj(parseDoc(path, text));
  if (!doc) return m;
  const resources = obj(doc.Resources);
  const guardrails = resources
    ? Object.values(resources).map(obj).filter((r) => r && r.Type === 'AWS::Bedrock::Guardrail').map((r) => obj(r .Properties) ?? {})
    : [doc];
  for (const props of guardrails.slice(0, 50)) readBedrockDoc(props, m);
  return m;
}

const AZURE_INJECTION_FILTER_RE = /^(jailbreak|indirect[\s_-]*attacks?|prompt[\s_-]*shields?)$/i;

function azureFilter(name        , f                                                                                              , into                )       {
  const injection = AZURE_INJECTION_FILTER_RE.test(name.trim());
  const src = String(f.source ?? '').toLowerCase();
  const direction                   = /prompt|pre/.test(src) ? 'input' : /completion|post/.test(src) ? 'output' : /tool/.test(src) ? 'tool' : injection ? 'input' : 'unknown';
  const action = String(f.action ?? '').toUpperCase();
  let state               = 'enforcing';
  let why                = null;
  if (isFalse(f.enabled)) { state = 'disabled'; why = 'enabled: false'; }
  else if (isFalse(f.blocking) || action === 'ANNOTATING' || action === 'NONE') { state = 'observe-only'; why = isFalse(f.blocking) ? 'blocking: false (annotate only)' : `action: ${action}`; }
  else if (/^high$/i.test(String(f.severity ?? ''))) { state = 'weak'; why = 'severityThreshold: High - only the most severe content is blocked'; }
  if (state === 'enforcing') return;
  into.controls.push({ name: `${name} filter`, direction, injection, state, why, anchor: name });
}

function readAzureRai(path        , text        , source        )                 {
  const m = empty('azure-rai', source);
  const streamed = (mode        , anchor        ) => {
    if (/^(asynchronous_filter|deferred)$/i.test(mode)) m.streamedBeforeCheck = { why: `mode: ${mode} - completion tokens stream immediately and the filter catches up about 1,000 characters later`, anchor };
  };
  if (/\.tf$/i.test(path)) {
    for (const res of hclBlocks(text, /resource\s+"azurerm_cognitive_account_rai_policy"\s+"[^"]+"/g)) {
      const a = hclAttrs(res);
      if (a.mode) streamed(String(a.mode), 'mode');
      for (const cf of hclBlocks(res, /\bcontent_filter\b/g)) {
        const c = hclAttrs(cf);
        azureFilter(String(c.name ?? 'content'), { enabled: c.filter_enabled, blocking: c.block_enabled, severity: c.severity_threshold, action: null, source: c.source }, m);
      }
    }
    return m;
  }
  if (/\.bicep$/i.test(path)) {
    const mode = /\bmode\s*:\s*'([^']+)'/.exec(text);
    if (mode) streamed(mode[1], 'mode');
    for (const item of text.match(/\{[^{}]*\bname\s*:\s*'[^']+'[^{}]*\}/g) ?? []) {
      if (!/\b(blocking|enabled|severityThreshold)\s*:/.test(item)) continue;
      const get = (k        ) => new RegExp(`\\b${k}\\s*:\\s*'?([\\w -]+?)'?\\s*(?:[,}\\n])`).exec(item)?.[1];
      azureFilter(get('name') ?? 'content', { enabled: get('enabled'), blocking: get('blocking'), severity: get('severityThreshold'), action: get('action'), source: get('source') }, m);
    }
    return m;
  }
  const doc = parseDoc(path, text);
  const policies                        = [];
  const visit = (n     , depth = 0) => {
    if (depth > 12 || !n || typeof n !== 'object' || policies.length > 50) return;
    const p = obj(n.properties);
    if (p && (Array.isArray(p.contentFilters) || typeof p.basePolicyName === 'string')) policies.push(p);
    for (const v of Object.values(n)) visit(v, depth + 1);
  };
  visit(doc);
  for (const p of policies) {
    if (typeof p.mode === 'string') streamed(p.mode, 'mode');
    for (const f of arr(p.contentFilters).map(obj)) {
      if (f) azureFilter(String(f.name ?? 'content'), { enabled: f.enabled, blocking: f.blocking, severity: f.severityThreshold, action: f.action, source: f.source }, m);
    }
  }
  return m;
}

function litellmModes(mode         )           {
  if (typeof mode === 'string') return [mode];
  if (Array.isArray(mode)) return mode.map(String);
  const o = obj(mode);
  if (!o) return [];
  return [...Object.values(obj(o.tags) ?? {}).map(String), ...(o.default ? [String(o.default)] : [])];
}

function readLitellm(doc                     , source        )                 {
  const m = empty('litellm', source);
  for (const g of arr(doc.guardrails).map(obj)) {
    if (!g) continue;
    const p = obj(g.litellm_params) ?? {};
    const name = String(g.guardrail_name ?? p.guardrail ?? 'guardrail');
    const modes = litellmModes(p.mode);
    const tagged = obj(obj(p.mode)?.tags);
    const loggingOnly = modes.length > 0 && modes.every((x) => x === 'logging_only');
    const direction                   = modes.some((x) => /pre|during/.test(x)) && modes.some((x) => /post/.test(x)) ? 'both' : modes.some((x) => /post/.test(x)) ? 'output' : modes.some((x) => /pre|during/.test(x)) ? 'input' : 'unknown';
    const injection = INJECTION_NAME_RE.test(`${name} ${p.guardrail ?? ''}`);
    m.controls.push({ name, direction, injection, state: loggingOnly ? 'observe-only' : 'enforcing', why: loggingOnly ? 'mode: logging_only' : null, anchor: loggingOnly ? 'logging_only' : name });
    if (tagged && Object.values(tagged).some((v) => String(v) === 'logging_only')) {
      const tag = Object.entries(tagged).find(([, v]) => String(v) === 'logging_only') [0];
      m.blindSpots.push({ name, why: `a request carrying the tag "${tag}" is only logged - the caller picks the header, so the caller picks whether the guardrail blocks`, anchor: tag.split(':')[0] });
    }
    if (!isTrue(p.default_on)) m.optIn.push({ name, anchor: 'default_on' in p ? 'default_on' : name });
    if (isFalse(p.fail_on_error)) m.failOpen.push({ name, why: 'fail_on_error: false - a guardrail error lets the request through', anchor: 'fail_on_error' });
    if (String(p.unreachable_fallback ?? '') === 'fail_open') m.failOpen.push({ name, why: 'unreachable_fallback: fail_open', anchor: 'unreachable_fallback' });
    if (isTrue(p.experimental_use_latest_role_message_only)) m.blindSpots.push({ name, why: 'only the latest message is screened, so an instruction placed in an earlier turn is never seen', anchor: 'experimental_use_latest_role_message_only' });
    if (isTrue(p.skip_tool_message_in_guardrail)) m.blindSpots.push({ name, why: 'tool results are skipped - the channel indirect injection arrives on', anchor: 'skip_tool_message_in_guardrail' });
    if (typeof p.api_base === 'string') m.endpoints.push({ url: p.api_base, anchor: 'api_base' });
  }
  for (const g of arr(obj(doc.litellm_settings)?.guardrails).map(obj)) {
    for (const [name, v] of Object.entries(g ?? {})) {
      const o = obj(v);
      if (!o) continue;
      m.controls.push({ name, direction: 'unknown', injection: INJECTION_NAME_RE.test(`${name} ${arr(o.callbacks).join(' ')}`), state: isTrue(o.logging_only) ? 'observe-only' : 'enforcing', why: isTrue(o.logging_only) ? 'logging_only: true' : null, anchor: name });
      if (!isTrue(o.default_on)) m.optIn.push({ name, anchor: 'default_on' in o ? 'default_on' : name });
    }
  }
  return m;
}

function readPortkey(doc                     , source        )                 {
  const m = empty('portkey', source);
  const hooks                               = [['before_request_hooks', 'input'], ['after_request_hooks', 'output']];
  for (const [key, direction] of hooks) {
    for (const h of arr(doc[key]).map(obj)) {
      if (!h) continue;
      const name = String(h.id ?? 'guardrail');
      const injection = INJECTION_NAME_RE.test(`${name} ${arr(h.checks).map((c) => obj(c)?.id).join(' ')}`);
      const denies = isTrue(h.deny);
      const sync = isFalse(h.async);
      const why = !sync ? `async ${h.async === undefined ? 'defaults to true' : 'is true'} - the check runs beside the request and only logs` : !denies ? `deny ${h.deny === undefined ? 'defaults to false' : 'is false'} - a failed check returns 246 and the request is still processed` : null;
      m.controls.push({ name, direction, injection, state: why ? 'observe-only' : 'enforcing', why, anchor: !sync ? (h.async === undefined ? name : 'async') : !denies ? (h.deny === undefined ? name : 'deny') : name });
      for (const c of arr(h.checks).map(obj)) {
        if (c && isFalse(c.is_enabled)) m.controls.push({ name: String(c.id ?? 'check'), direction, injection: INJECTION_NAME_RE.test(String(c.id)), state: 'disabled', why: 'is_enabled: false', anchor: 'is_enabled' });
      }
    }
  }
  return m;
}

function readLlmGuard(doc                     , source        )                 {
  const m = empty('llm-guard', source);
  const lists                               = [['input_scanners', 'input'], ['output_scanners', 'output']];
  for (const [key, direction] of lists) {
    for (const s of arr(doc[key]).map(obj)) {
      if (!s) continue;
      const name = String(s.type ?? 'scanner');
      const threshold = num(obj(s.params)?.threshold);
      const injection = /PromptInjection|Jailbreak|BanSubstrings/i.test(name) && direction === 'input';

      const state               = threshold != null && threshold >= 1 ? 'disabled' : threshold != null && threshold >= 0.99 ? 'weak' : 'enforcing';
      m.controls.push({ name, direction, injection, state, why: state === 'disabled' ? `threshold: ${threshold} - a score can never exceed it` : state === 'weak' ? `threshold: ${threshold} - only near-certain detections fail` : null, anchor: state === 'enforcing' ? name : 'threshold' });
    }
  }
  m.unauthenticatedService = !obj(doc.auth) && !!obj(doc.app);
  return m;
}

function kongGuardPlugins(doc                     )                        {
  const out                        = [];
  const take = (list         ) => { for (const p of arr(list).map(obj)) if (p && KONG_GUARD_PLUGINS.test(String(p.name ?? ''))) out.push(p); };
  take(doc.plugins);
  for (const scope of ['services', 'routes', 'consumers']) {
    for (const s of arr(doc[scope]).map(obj)) { take(s?.plugins); for (const r of arr(s?.routes).map(obj)) take(r?.plugins); }
  }
  return out.slice(0, MAX_ITEMS);
}

function readKong(doc                     , source        )                 {
  const m = empty('kong', source);
  for (const p of kongGuardPlugins(doc)) {
    const name = String(p.name);
    const c = obj(p.config) ?? {};
    const rules = obj(c.rules) ?? {};
    if (isFalse(p.enabled)) { m.controls.push({ name, direction: 'input', injection: true, state: 'disabled', why: 'enabled: false', anchor: name }); continue; }
    const mode = String(c.guarding_mode ?? '').toUpperCase();
    m.controls.push({ name, direction: mode === 'BOTH' ? 'both' : mode === 'OUTPUT' ? 'output' : 'input', injection: /prompt-guard|guardrails|content-safety/.test(name), state: 'enforcing', why: null, anchor: name });
    if (name === 'ai-prompt-guard' && isTrue(c.allow_all_conversation_history)) m.blindSpots.push({ name, why: 'allow_all_conversation_history: true - earlier turns are ignored, so an instruction planted before the last message is never matched', anchor: 'allow_all_conversation_history' });
    if (/prompt-guard/.test(name) && !isTrue(c.match_all_roles ?? rules.match_all_roles)) m.blindSpots.push({ name, why: 'match_all_roles is off - only user-role messages are matched, and the caller writes the assistant and system turns too', anchor: 'match_all_roles' in c || 'match_all_roles' in rules ? 'match_all_roles' : name });
    if (isFalse(c.stop_on_error)) m.failOpen.push({ name, why: 'stop_on_error: false - an unreachable guardrail service lets the request through', anchor: 'stop_on_error' });
    if (typeof c.content_safety_url === 'string') m.endpoints.push({ url: c.content_safety_url, anchor: 'content_safety_url' });
  }
  return m;
}

export function hclBlocks(text        , header        )           {
  const out           = [];
  const re = new RegExp(header.source, header.flags.includes('g') ? header.flags : header.flags + 'g');
  let m                        ;
  while ((m = re.exec(text)) && out.length < MAX_ITEMS) {
    const open = text.indexOf('{', m.index + m[0].length);
    if (open < 0 || /\S/.test(text.slice(m.index + m[0].length, open).replace(/=/, ''))) continue;
    let depth = 0;
    let quote = false;
    for (let i = open; i < text.length; i++) {
      const ch = text[i];
      if (quote) { if (ch === '\\') i++; else if (ch === '"') quote = false; continue; }
      if (ch === '"') quote = true;
      else if (ch === '{') depth++;
      else if (ch === '}' && --depth === 0) { out.push(text.slice(open + 1, i)); re.lastIndex = i; break; }
    }
  }
  return out;
}

export function hclAttrs(body        )                         {
  const out                         = {};
  let depth = 0;
  for (const line of body.split(/\r?\n/)) {
    if (depth === 0) {
      const a = /^\s*([A-Za-z_][\w-]*)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^\s#/{[]+))/.exec(line);
      if (a) out[a[1]] = a[2] ?? a[3];
    }
    depth += (line.match(/\{/g) ?? []).length - (line.match(/\}/g) ?? []).length;
    if (depth < 0) depth = 0;
  }
  return out;
}

const PASS_THROUGH_RE = /^(?:noop|nofix|none|pass|log|reask_?none)$/i;

function passThroughValidators(doc         , into                )       {
  let seen = 0;
  const visit = (n     , depth        ) => {
    if (depth > 12 || seen > MAX_ITEMS || !n || typeof n !== 'object') return;
    if (Array.isArray(n)) { for (const x of n.slice(0, MAX_ITEMS)) visit(x, depth + 1); return; }
    seen++;
    const action = str(pick(n, 'on_fail', 'onFail', 'on-fail'));
    if (action && PASS_THROUGH_RE.test(action.trim())) {
      const name = String(n.name ?? n.id ?? n.type ?? 'validator');
      if (!into.controls.some((c) => c.validator && c.name === name)) {
        into.controls.push({ name, direction: 'unknown', injection: INJECTION_NAME_RE.test(name), state: 'observe-only', validator: true, why: `on_fail: ${action.trim()}`, anchor: 'on_fail' in n ? 'on_fail' : 'onFail' in n ? 'onFail' : name });
      }
    }
    for (const v of Object.values(n)) visit(v, depth + 1);
  };
  visit(doc, 0);
}

export function guardrailModel(path        , text        , framework                    , siblingTasks           = [])                        {
  const source = path;
  switch (framework) {
    case 'colang': return readColang(text, source);
    case 'bedrock': return readBedrock(path, text, source);
    case 'azure-rai': return readAzureRai(path, text, source);
    default: break;
  }
  if (framework === 'guardrails-ai' && /\.rail$/i.test(path)) return readRail(text, source);
  const doc = obj(parseDoc(path, text));
  if (!doc) return null;
  const m = readDoc(framework, doc, source, siblingTasks);
  if (m) passThroughValidators(doc, m);
  return m;
}

function readDoc(framework                    , doc                     , source        , siblingTasks          )                        {
  switch (framework) {
    case 'nemo': return readNemo(doc, source, siblingTasks);
    case 'guardrails-ai': return readGuardJson(doc, source);
    case 'litellm': return readLitellm(doc, source);
    case 'portkey': return readPortkey(doc, source);
    case 'llm-guard': return readLlmGuard(doc, source);
    case 'kong': return readKong(doc, source);
    default: return null;
  }
}

export function nemoPromptTasks(text                           , path        )           {
  if (!text || !/\bprompts\s*:/.test(text)) return [];
  const doc = obj(parseDoc(path, text));
  return arr(doc?.prompts).map((p) => String(obj(p)?.task ?? '')).filter(Boolean);
}

