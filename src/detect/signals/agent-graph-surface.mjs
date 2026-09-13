import { agentFrameworkModel,                                                         } from './agent-frameworks.mjs';
import { locate } from './agentic-shim.mjs';
import { codeFindings, describesAt, egressFindings, prohibitsAt, shellFindings, ssrfFindings, textFindings } from './agentic-shim.mjs';

const FRAMEWORK_LABEL                                 = {
  crewai: 'CrewAI', langgraph: 'LangGraph', autogen: 'AutoGen', adk: 'Google ADK', langflow: 'Langflow',
  flowise: 'Flowise', dify: 'Dify', 'agent-framework': 'agent framework',
};

const STRUCTURAL_SIGNAL_RE = /directive tag|forced output|verdict coercion/i;

const CONDITIONAL_DEFENCE_RE =
  /\b(?:if|when|whenever|should)\b[^.\n]{0,160}\b(?:attempts?|tries|try|asks?|tells?|instructs?|contains?|says?|claims?)\b|\b(?:prompt[\s-]injection|jailbreak(?:s|ing)?|confidentiality)\s*[:—-]|\b(?:never|do not|don't|must not|refuse to)\s+(?:[\w-]+,?\s+(?:or\s+)?){0,5}(?:reveal|share|disclose|repeat|recite|follow|comply|obey|execute|print|expose)\b/i;
function instructionLines(text        )         {
  return text.split('\n').filter((l) => !prohibitsAt(l) && !describesAt(l) && !CONDITIONAL_DEFENCE_RE.test(l)).join('\n');
}

function hostExecFindings(a                  , m                , label        )                    {
  const out                    = [];
  const delegation = m.agents.some((g) => g.delegates);
  for (const g of m.agents.filter((x) => x.codeExec === 'host' || x.codeExec === 'container').slice(0, 10)) {
    const host = g.codeExec === 'host';
    out.push({
      class: host ? 'OVER_PERMISSIONED' : 'INSECURE_CONFIG',
      severity: host ? 'CRITICAL' : 'LOW',
      title: host ? `${label} agent "${g.name}" runs generated code on the host` : `${label} agent "${g.name}" executes generated code in a container`,
      detail: host
        ? `${g.codeExecWhy}. Whatever the model writes - including code an injected document or page asked for - runs as the process that started the agents: same filesystem, same credentials, same network.${delegation ? ' Delegation is on in this configuration, so any agent can hand work to this one and reach its executor.' : ''}`
        : `${g.codeExecWhy}. Container execution is the right boundary; confirm what the container mounts and what network it reaches, because generated code runs with exactly that.`,
      remediationText: host
        ? 'Run generated code in an isolated sandbox (a container without host mounts or credentials, or a remote sandbox such as E2B / Modal), or remove code execution from the agent.'
        : 'Keep the executor image minimal, mount only a scratch directory, and deny network egress it does not need.',
      remediationTier: host ? 1 : 3,
      evidence: { agent: g.name, codeExec: g.codeExec, why: g.codeExecWhy, framework: m.framework, path: a.path, ...locate(host ? /unsafe|LocalCommandLine|Jupyter/ : /allow_code_execution|Docker/, a.content) },
    });
  }
  return out;
}

const MAX_CODE_NODES = 200;

function codeNodeFindings(a                  , m                , label        , n          )                    {
  const out                    = [];
  if (n.interpreter) {
    out.push({
      class: 'OVER_PERMISSIONED',
      severity: n.fromUserInput && !n.sandboxed ? 'CRITICAL' : n.sandboxed ? 'MEDIUM' : 'HIGH',
      title: n.fromUserInput
        ? `${label} flow "${a.name}" wires user input into a code interpreter ("${n.name}")`
        : `${label} flow "${a.name}" contains a code interpreter ("${n.name}")`,
      detail:
        `The ${n.type} node executes ${n.language === 'python' ? 'Python' : 'code'} it is handed at run time${n.sandboxed ? ' in a remote sandbox' : ' inside the flow server\'s own process'}.` +
        (n.fromUserInput ? ' It is reachable from the flow\'s chat / API input, so anyone who can send the flow a message can make it run code - with the server\'s environment variables, stored credentials and network.' : ' Anything that can steer the model driving it can choose the code.'),
      remediationText: 'Remove the interpreter from flows that serve untrusted users, or point it at an isolated sandbox with no credentials; never expose such a flow on an unauthenticated endpoint.',
      remediationTier: 1,
      evidence: { node: n.name, type: n.type, fromUserInput: n.fromUserInput, sandboxed: n.sandboxed, framework: m.framework, path: a.path, ...locate(n.type, a.content) },
    });
  }
  if (n.provenance === 'altered') {
    out.push({
      class: 'INSECURE_CONFIG',
      severity: 'LOW',
      title: `${label} node "${n.name}" runs code that no longer matches its declared hash`,
      detail: `The export declares code_hash ${n.declaredHash} but the code it carries hashes to ${n.actualHash}. Langflow gates custom code on that hash server-side, so this node is the flow's own code - edited in place, or altered after export - and is graded as such rather than as a shipped component.`,
      remediationText: 'Review the node\'s code; if it was not deliberately customised, replace it with the stock component.',
      remediationTier: 3,
      evidence: { node: n.name, declaredHash: n.declaredHash, actualHash: n.actualHash, path: a.path, ...locate(n.declaredHash ?? n.name, a.content) },
    });
  }
  if (!n.code.trim()) return out;
  const where = `${n.type} node "${n.name}" of ${label} flow "${a.name}"`;
  const virtualPath = `${a.path}#${n.name.replace(/[^\w.-]+/g, '_')}.${n.language === 'javascript' ? 'js' : 'py'}`;
  const all = [...shellFindings(a, n.code, where), ...codeFindings(a, virtualPath, n.code, { context: 'agent' }), ...egressFindings(a, n.code, where)];

  const graded = n.provenance === 'claimed-stock' ? all.filter((f) => f.severity === 'HIGH' || f.severity === 'CRITICAL') : all;
  for (const f of graded.slice(0, 6)) {
    const ev = (f.evidence ?? {})                       ;

    if (typeof ev.snippet === 'string' && !(a.content ?? '').includes(ev.snippet)) { delete ev.snippet; delete ev.snippetStartLine; delete ev.line; }
    out.push({ ...f, severity: n.sandboxed && f.severity === 'CRITICAL' ? 'HIGH' : f.severity, evidence: { ...ev, node: n.name, sandboxed: n.sandboxed, provenance: n.provenance ?? 'custom', ...(ev.line == null ? locate(n.name, a.content) : {}) } });
  }
  return out;
}

export function frameworkFindings(a                  )                    {
  const m = agentFrameworkModel(a.path, a.content ?? '', (a.meta?.framework                              ) ?? null);
  if (!m) return [];
  const label = FRAMEWORK_LABEL[m.framework];
  const out                    = hostExecFindings(a, m, label);
  for (const n of m.codeNodes.slice(0, MAX_CODE_NODES)) out.push(...codeNodeFindings(a, m, label, n));

  for (const p of m.prompts) {
    for (const f of textFindings(a, instructionLines(p.text), 'PROMPT_INJECTION').filter((x) => x.class === 'PROMPT_INJECTION')) {
      const signals = ((f.evidence?.signals                        ) ?? []).filter((s) => !STRUCTURAL_SIGNAL_RE.test(s));
      if (!signals.length) continue;
      out.push({ ...f, title: `Injected instruction in the "${p.node}" prompt of ${label} flow "${a.name}"`, evidence: { ...(f.evidence ?? {}), signals, node: p.node, path: a.path } });
    }
  }
  for (const url of [...new Set(m.httpUrls)].slice(0, 10)) out.push(...ssrfFindings(a, url, `HTTP node of ${label} flow "${a.name}"`));
  if (m.exportedSecrets.length) {
    out.push({
      class: 'SECRET_EXPOSURE',
      severity: 'HIGH',
      title: `${label} export "${a.name}" contains secret variable values`,
      detail: `${m.exportedSecrets.slice(0, 6).join(', ')} ${m.exportedSecrets.length === 1 ? 'is a' : 'are'} secret-typed environment variable${m.exportedSecrets.length === 1 ? '' : 's'} exported with ${m.exportedSecrets.length === 1 ? 'its' : 'their'} value. Anyone the DSL file is shared with, or any repository it is committed to, holds the credential.`,
      remediationText: 'Rotate the credentials and re-export without secrets (Dify leaves secret values empty unless include_secret is set).',
      remediationTier: 1,
      evidence: { variables: m.exportedSecrets, path: a.path, ...locate(m.exportedSecrets[0], a.content) },
    });
  }
  return out;
}

