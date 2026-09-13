import { createHash } from 'node:crypto';
import { parseYaml } from '../../core/yaml-lite.mjs';

const PROMPT_FIELD_RE = /^(?:template|system_?message|system_?prompt|systemMessagePrompt|humanMessagePrompt|prompt|instructions?|agent_description)$/i;
const MAX_PROMPTS = 40;

function takePrompts(into                , node        , fields                     , read                     )       {
  for (const [k, v] of Object.entries(fields).slice(0, 200)) {
    if (into.prompts.length >= MAX_PROMPTS || !PROMPT_FIELD_RE.test(k)) continue;
    const text = read(v);
    if (typeof text === 'string' && text.trim().length > 8) into.prompts.push({ node, text: text.slice(0, 8000) });
  }
}

const MAX = 200;
const obj = (v         )                             => (v && typeof v === 'object' && !Array.isArray(v) ? (v                       ) : null);
const arr = (v         )        => (Array.isArray(v) ? v.slice(0, MAX) : []);
const isTrue = (v         ) => v === true || (typeof v === 'string' && /^true$/i.test(v.trim()));
const names = (v         )           => arr(v).map((t) => (typeof t === 'string' ? t : String(obj(t)?.name ?? obj(t)?.id ?? obj(t)?.provider ?? ''))).filter(Boolean).slice(0, 40);

function parse(path        , text        )                             {
  const t = text.replace(/^﻿/, '');
  if (/\.json$/i.test(path)) { try { return obj(JSON.parse(t)); } catch { return null; } }
  if (/\.ya?ml$/i.test(path)) return obj(parseYaml(t));
  return null;
}

const CREW_FIELDS = ['role', 'goal', 'backstory'];

function isCrewAgentMap(doc                     )          {
  const vals = Object.values(doc).slice(0, 50);
  return vals.length > 0 && vals.every((v) => obj(v)) && vals.some((v) => CREW_FIELDS.filter((k) => k in v).length >= 2);
}

export function agentFrameworkOf(path        , text                           , doc                             )                        {
  if (!text || !/\.(json|ya?ml)$/i.test(path)) return null;
  if (!/agent_class|autogen_|"nodes"|nodes\s*:|kind\s*:\s*app|backstory|langgraph|graphs|code_execution/i.test(text)) return null;
  const d = doc === undefined ? parse(path, text) : doc;
  if (!d) return null;
  if (typeof d.agent_class === 'string' || (typeof d.instruction === 'string' && typeof d.model === 'string' && (Array.isArray(d.sub_agents) || Array.isArray(d.tools)))) return 'adk';
  if (typeof d.provider === 'string' && /^autogen_(?:agentchat|ext|core)\./.test(d.provider)) return 'autogen';
  if (d.kind === 'app' && obj(d.app) && (obj(d.workflow) || obj(d.model_config))) return 'dify';
  const data = obj(d.data);
  if (data && Array.isArray(data.nodes) && arr(data.nodes).some((n) => typeof obj(obj(n)?.data)?.type === 'string')) return 'langflow';
  if (Array.isArray(d.nodes) && Array.isArray(d.edges) && arr(d.nodes).some((n) => typeof obj(obj(n)?.data)?.category === 'string' && typeof obj(obj(n)?.data)?.name === 'string')) return 'flowise';
  if (obj(d.graphs) && /langgraph/i.test(path + text)) return 'langgraph';
  if (isCrewAgentMap(d) || Array.isArray(d.agents) || obj(d.agents)) return /crew|backstory/i.test(path + text) ? 'crewai' : 'agent-framework';
  return null;
}

function crewAgents(doc                     )                   {
  const entries                  = Array.isArray(doc.agents)
    ? arr(doc.agents).map((a, i) => [String(obj(a)?.name ?? obj(a)?.role ?? `agent ${i + 1}`), a])
    : obj(doc.agents)
      ? Object.entries(doc.agents)
      : Object.entries(doc).filter(([, v]) => obj(v) && CREW_FIELDS.some((k) => k in v));
  return entries.slice(0, 40).map(([name, raw]) => {
    const a = obj(raw) ?? {};
    const exec = isTrue(a.allow_code_execution);
    const unsafe = String(a.code_execution_mode ?? '').toLowerCase() === 'unsafe';
    return {
      name,
      role: typeof a.role === 'string' ? a.role.trim().slice(0, 120) : null,
      tools: names(a.tools),
      delegates: isTrue(a.allow_delegation ?? a.allowDelegation),
      codeExec: exec ? (unsafe ? 'host' : 'container') : null,
      codeExecWhy: exec ? `allow_code_execution: true, code_execution_mode: ${unsafe ? 'unsafe' : a.code_execution_mode ?? 'safe (default)'}` : null,
    };
  });
}

function adkAgents(doc                     )                   {
  const own                 = {
    name: String(doc.name ?? 'root_agent'),
    role: typeof doc.description === 'string' ? doc.description.slice(0, 120) : null,
    tools: names(doc.tools),
    delegates: arr(doc.sub_agents).length > 0 && !isTrue(doc.disallow_transfer_to_peers),
    codeExec: null,
    codeExecWhy: null,
  };
  return [own];
}

function autogenAgents(doc                     )                   {
  const agents                   = [];
  const visit = (n     , depth        ) => {
    if (depth > 16 || agents.length >= 40 || !n || typeof n !== 'object') return;
    if (Array.isArray(n)) { for (const x of n.slice(0, MAX)) visit(x, depth + 1); return; }
    const provider = typeof n.provider === 'string' ? n.provider : '';
    const cfg = obj(n.config) ?? {};
    if (/\.agents\./.test(provider)) {
      const exec = executorOf(cfg);
      agents.push({ name: String(cfg.name ?? provider.split('.').pop()), role: typeof cfg.description === 'string' ? cfg.description.slice(0, 120) : null, tools: names(cfg.tools), delegates: false, codeExec: exec.where, codeExecWhy: exec.why });
    }
    for (const v of Object.values(n)) visit(v, depth + 1);
  };
  visit(doc, 0);
  return agents;
}

function executorOf(cfg                     )                                               {
  const found           = [];
  const visit = (n     , depth        ) => {
    if (depth > 10 || !n || typeof n !== 'object') return;
    if (typeof n.provider === 'string' && /code_executors?\.|CodeExecution|Executor/i.test(n.provider)) found.push(n.provider);
    for (const v of Object.values(n)) visit(v, depth + 1);
  };
  visit(cfg, 0);
  const local = found.find((p) => /LocalCommandLineCodeExecutor|JupyterCodeExecutor|\.local\./.test(p));
  if (local) return { where: 'host', why: `${local.split('.').pop()} runs generated code as the host process` };
  const docker = found.find((p) => /Docker/i.test(p));
  if (docker) return { where: 'container', why: `${docker.split('.').pop()}` };
  if (found.length) return { where: 'sandbox', why: found[0].split('.').pop() ?? null };
  return { where: null, why: null };
}

const LANGFLOW_INTERPRETER_RE = /^(?:PythonREPL(?:Component|Tool)?|PythonInterpreter|PythonCodeStructuredTool|CodeInterpreter)$/i;
const USER_INPUT_TYPES_RE = /^(?:ChatInput|TextInput|Webhook(?:Component)?|APIRequest|start|trigger-webhook|chatflow|chatInput)$/i;

function reachableFrom(starts          , edges                                      )              {
  const next = new Map                  ();
  for (const e of edges.slice(0, 5000)) next.set(e.source, [...(next.get(e.source) ?? []), e.target]);
  const seen = new Set        ();
  const queue = [...starts];
  while (queue.length && seen.size < 5000) {
    const id = queue.shift() ;
    for (const t of next.get(id) ?? []) if (!seen.has(t)) { seen.add(t); queue.push(t); }
  }
  return seen;
}

function langflow(doc                     , m                )       {
  const data = obj(doc.data) ?? {};
  const nodes = arr(data.nodes).map(obj).filter(Boolean)                         ;
  const edges = arr(data.edges).map((e) => ({ source: String(obj(e)?.source ?? ''), target: String(obj(e)?.target ?? '') }));
  m.nodeCount = nodes.length;
  const inputs = nodes.filter((n) => USER_INPUT_TYPES_RE.test(String(obj(n.data)?.type ?? ''))).map((n) => String(n.id));
  const reach = reachableFrom(inputs, edges);
  for (const n of nodes) {
    const d = obj(n.data) ?? {};
    const type = String(d.type ?? '');
    const template = obj(obj(d.node)?.template) ?? {};
    takePrompts(m, String(obj(d.node)?.display_name ?? type), template, (v) => obj(v)?.value);
    const interpreter = LANGFLOW_INTERPRETER_RE.test(type);
    const source = typeof obj(template.code)?.value === 'string' ? String(obj(template.code) .value) : '';
    const extra = [obj(template.python_code)?.value, obj(template.tool_code)?.value].filter((x) => typeof x === 'string').join('\n');
    if (!interpreter && !source && !extra) continue;
    m.codeNodes.push({
      name: String(obj(d.node)?.display_name ?? type), type, language: 'python', code: [source, extra].filter(Boolean).join('\n'),
      interpreter, fromUserInput: reach.has(String(n.id)), sandboxed: false, ...langflowProvenance(d, type, source),
    });
  }
}

function langflowProvenance(d                     , type        , source        )                                                               {
  const node = obj(d.node) ?? {};
  const declared = typeof obj(node.metadata)?.code_hash === 'string' ? String(obj(node.metadata) .code_hash) : null;
  const actual = source ? createHash('sha256').update(source, 'utf8').digest('hex').slice(0, 12) : null;
  const module = typeof obj(node.metadata)?.module === 'string' ? String(obj(node.metadata) .module) : null;
  if (actual && declared && actual !== declared) return { provenance: 'altered', declaredHash: declared, actualHash: actual };

  const custom = /^Custom/i.test(type) || isTrue(node.edited) || (module !== null && !/^(?:lfx|langflow)\.components\./.test(module));
  return { provenance: custom ? 'custom' : 'claimed-stock', declaredHash: declared, actualHash: actual };
}

const FLOWISE_CODE_INPUTS = ['javascriptFunction', 'customToolFunc', 'ifFunction', 'elseFunction', 'customFunctionJavascriptFunction', 'code'];

function flowise(doc                     , m                )       {
  const nodes = arr(doc.nodes).map(obj).filter(Boolean)                         ;
  const edges = arr(doc.edges).map((e) => ({ source: String(obj(e)?.source ?? ''), target: String(obj(e)?.target ?? '') }));
  m.nodeCount = nodes.length;
  const inputs = nodes.filter((n) => /chat|start|webhook/i.test(String(obj(n.data)?.name ?? ''))).map((n) => String(n.id));
  const reach = reachableFrom(inputs, edges);
  for (const n of nodes) {
    const d = obj(n.data) ?? {};
    const name = String(d.name ?? '');
    const inp = obj(d.inputs) ?? {};
    const code = FLOWISE_CODE_INPUTS.map((k) => inp[k]).filter((x) => typeof x === 'string' && x.trim()).join('\n');
    takePrompts(m, String(d.label ?? name), inp, (v) => v);
    const interpreter = /codeInterpreter|pythonInterpreter/i.test(name);
    if (!code && !interpreter) {
      if (/^(?:requestsGet|requestsPost|httpRequest)/i.test(name) && typeof inp.url === 'string') m.httpUrls.push(inp.url);
      continue;
    }
    m.codeNodes.push({ name: String(d.label ?? name), type: name, language: 'javascript', code, interpreter, fromUserInput: reach.has(String(n.id)), sandboxed: /E2B/i.test(name) });
  }
}

function dify(doc                     , m                )       {
  const wf = obj(doc.workflow) ?? {};
  const graph = obj(wf.graph) ?? {};
  const nodes = arr(graph.nodes).map(obj).filter(Boolean)                         ;
  const edges = arr(graph.edges).map((e) => ({ source: String(obj(e)?.source ?? ''), target: String(obj(e)?.target ?? '') }));
  m.nodeCount = nodes.length;
  const starts = nodes.filter((n) => USER_INPUT_TYPES_RE.test(String(obj(n.data)?.type ?? ''))).map((n) => String(n.id));
  const reach = reachableFrom(starts, edges);
  for (const n of nodes) {
    const d = obj(n.data) ?? {};
    const type = String(d.type ?? '');
    if (type === 'code' && typeof d.code === 'string') {
      m.codeNodes.push({ name: String(d.title ?? 'code'), type, language: /javascript/i.test(String(d.code_language)) ? 'javascript' : 'python', code: d.code, interpreter: false, fromUserInput: reach.has(String(n.id)), sandboxed: true });
    }
    if (type === 'http-request' && typeof d.url === 'string') m.httpUrls.push(d.url);
    if (type === 'llm' || type === 'agent' || type === 'agent-v2') {
      const tpl = Array.isArray(d.prompt_template) ? arr(d.prompt_template).map((p) => obj(p)?.text).filter((x) => typeof x === 'string').join('\n') : d.prompt_template;
      takePrompts(m, String(d.title ?? type), { prompt: tpl, instruction: d.instruction ?? obj(obj(d.agent_parameters)?.instruction)?.value }, (v) => v);
    }
    if (type === 'agent' || type === 'agent-v2') m.agents.push({ name: String(d.title ?? 'agent'), role: null, tools: names(obj(d.agent_parameters)?.tools?.value ?? d.tools), delegates: false, codeExec: null, codeExecWhy: null });
  }
  for (const v of arr(wf.environment_variables).map(obj)) {
    if (v && String(v.value_type) === 'secret' && typeof v.value === 'string' && v.value.trim()) m.exportedSecrets.push(String(v.name ?? 'secret'));
  }
}

export function agentFrameworkModel(path        , text        , fw                        )                        {
  const doc = parse(path, text);
  const framework = fw ?? agentFrameworkOf(path, text, doc);
  if (!doc || !framework) return null;
  const m                 = { framework, agents: [], graphs: [], codeNodes: [], httpUrls: [], exportedSecrets: [], nodeCount: 0, prompts: [] };
  switch (framework) {
    case 'adk': m.agents = adkAgents(doc); break;
    case 'autogen': m.agents = autogenAgents(doc); break;
    case 'langflow': langflow(doc, m); break;
    case 'flowise': flowise(doc, m); break;
    case 'dify': dify(doc, m); break;
    default: m.agents = crewAgents(doc); break;
  }
  if (obj(doc.graphs)) m.graphs = Object.keys(doc.graphs).slice(0, 20);
  return m;
}

