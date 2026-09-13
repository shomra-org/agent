import { HIGH_IMPACT_TOOLS, baseToolName, frontmatter, isWildcardGrant, localAgentCard, localCommandExtras, localMcp, toToolList } from './artifacts.mjs';
import { autonomySeverity, localAutonomy } from './autonomy.mjs';
import { localMemory, offendingLine } from './memory.mjs';
import { INSTALL_LURE } from './packages.mjs';
import { localPropagation } from './propagation.mjs';
import { downrankCodeContext, localScan } from './scan.mjs';
import { grade } from './severity.mjs';
import { isModelConfigPath, localModelConfig } from './model-config.mjs';
import { isInstructionPath } from './instruction-paths.mjs';
import { PLUGIN_MANIFEST_RE, TOOL_MANIFEST_RE, localExtension, localPlugin, localToolManifest } from './manifests.mjs';
import { agenticCiFindings } from './agentic-ci-surface.mjs';
import { ciVendorOf } from './ci-workflow.mjs';
import { guardrailConfigFindings } from './guardrail-surface.mjs';
import { guardrailFramework } from './guardrail-shape.mjs';
import { frameworkFindings } from './agent-graph-surface.mjs';
import { agentFrameworkOf } from './agent-frameworks.mjs';
import { classifyMemoryPath } from './memory-locations.mjs';

const MEMORY_BASENAMES = new Set(['memory.md', 'mem0.json', 'letta_memory.json', 'memgpt_memory.json']);

const SOURCE_EXT_RE = /\.(?:[cm]?[jt]sx?|py|rb|go|rs|java|kt|scala|php|cs|swift|c|cc|cpp|h|hpp)$/i;

const isSourceFile = (p) => SOURCE_EXT_RE.test(String(p ?? '').split(/[\\/]+/).pop() ?? '');

function governedKindFor(kind, path) {
  if (kind === 'rules') return 'INSTRUCTION';
  if (kind === 'memory') return 'MEMORY';
  if (kind && kind !== 'auto') return null;
  const lower = String(path ?? '').split(/[\\/]+/).join('/').toLowerCase();
  if (!lower) return null;
  const base = lower.slice(lower.lastIndexOf('/') + 1);
  if (classifyMemoryPath(lower)) return 'MEMORY';
  if (isInstructionPath(lower)) return 'INSTRUCTION';
  if (MEMORY_BASENAMES.has(base) || /(^|\/)(\.mem0|\.letta|\.memgpt|memory)\//.test(lower)) return 'MEMORY';
  return null;
}

function guardrailOf(kind, path, content) {
  if (kind !== 'guardrail' && kind !== 'auto' && kind !== undefined) return null;
  const p = String(path ?? '').replace(/\\/g, '/');
  const candidates = kind === 'guardrail' ? [p, 'guardrails/config.yml', 'guardrails/config.json'].filter(Boolean) : [p];
  for (const c of candidates) {
    const framework = guardrailFramework(c, content || '');
    if (framework) return { framework, path: c };
  }
  return null;
}

const LOW_CODE = new Set(['langflow', 'flowise', 'dify']);

function frameworkOf(kind, path, content) {
  if (kind !== 'framework' && kind !== 'auto' && kind !== undefined) return null;
  const p = String(path ?? '').replace(/\\/g, '/');
  if (ciVendorOf(p)) return null;
  const candidates = kind === 'framework' ? [p, 'flow.json', 'agents.yaml'].filter(Boolean) : [p];
  for (const c of candidates) {
    const framework = agentFrameworkOf(c, content || '');
    if (framework) return { framework, path: c };
  }
  return null;
}

export function localGate(content, { kind, path } = {}) {
  const findings = [];
  const push = (severity, title, remediationText, line) => findings.push({ severity, title, remediationText, ...(line ? { line } : {}) });
  const framework = frameworkOf(kind, path, content);

  const gov = governedKindFor(kind, path);
  if (gov) {
    for (const f of localMemory(content, { kind: gov })) push(f.severity, f.title, f.remediationText, f.line);

    for (const f of localScan(content || '', { categories: ['config'] }).findings) push(f.severity, f.label, undefined, f.line);
  } else {
    const scan = localScan(content || '', { categories: ['shell', 'injection', 'secret', 'config', 'egress', 'pii'] });
    const graded = isSourceFile(path) ? downrankCodeContext(scan.findings) : scan.findings;
    const manifest = kind === 'plugin' || kind === 'tool-manifest' || PLUGIN_MANIFEST_RE.test(String(path ?? '').replace(/\\/g, '/')) || TOOL_MANIFEST_RE.test(String(path ?? '').replace(/\\/g, '/'));
    const lines = manifest ? String(content || '').split(/\r?\n/) : [];
    for (const f of graded) {

      if ((kind === 'agent-card' || kind === 'mcp') && f.category === 'pii' && f.label.includes('IPv4')) continue;
      if (manifest && f.category === 'pii' && /e-?mail/i.test(f.label) && /"(?:e-?mail|contact_email)"\s*:/i.test(lines[(f.line ?? 0) - 1] ?? '')) continue;
      if (kind === 'mcp' && /auto.?approv|always.?allow/i.test(f.label)) continue;
      if (f.category === 'injection' && guardrailOf(kind, path, content)) continue;
      if (f.category !== 'secret' && LOW_CODE.has(framework?.framework)) continue;
      push(f.severity, f.label, undefined, f.line);
    }
  }

  {
    const auto = localAutonomy(content || '');
    const sev = autonomySeverity(auto);
    if (sev) {
      push(sev, `Instructs the agent to act unsupervised (${[...new Set(auto.map((a) => a.family))].join(', ')})`,
        'Keep the autonomy narrow - name the commands that may run unattended rather than removing confirmation globally, and never pair it with withholding what was done.',
        auto[0].line);
    }
  }

  for (const p of localPropagation(content || '', { path, kind })) {
    push(p.severity, p.title, p.remediationText, p.line);
    break;
  }

  for (const l of INSTALL_LURE) {
    const line = offendingLine(l, content || '');
    if (!line) continue;
    push(l.severity, l.name, 'Do not follow instructions that fetch and run out-of-band binaries.', line);
    break;
  }

  if (['skill', 'command', 'subagent', 'auto', undefined].includes(kind)) {
    const fm = frontmatter(content || '');
    const grants = [...toToolList(fm['allowed-tools']), ...toToolList(fm.tools), ...toToolList(fm.allowedTools)];
    if (grants.some(isWildcardGrant)) push('HIGH', 'Wildcard tool grant (grants every capability)', 'Replace the wildcard with an explicit least-privilege tool list.');
    else {
      const hi = grants.map(baseToolName).filter((t) => HIGH_IMPACT_TOOLS.includes(t));
      if (hi.length >= 3) push('MEDIUM', `Broad tool grant (${hi.length} high-impact tools: ${[...new Set(hi)].slice(0, 5).join(', ')})`, 'Grant only the tools this artifact actually needs.');
    }
  }

  if (['mcp', 'auto', undefined].includes(kind)) for (const f of localMcp(content || '', { path })) push(f.severity, f.title, f.remediationText, f.line);
  if (kind === 'model-config' || (['auto', undefined].includes(kind) && isModelConfigPath(path, content))) {
    for (const f of localModelConfig(content || '', { path })) push(f.severity, f.title, f.remediationText, f.line);
  }
  if (['agent-card', 'auto', undefined].includes(kind)) for (const f of localAgentCard(content || '')) push(f.severity, f.title, f.remediationText, f.line);
  if (['command', 'auto', undefined].includes(kind)) for (const f of localCommandExtras(content || '')) push(f.severity, f.title, f.remediationText, f.line);

  const auto = kind === 'auto' || kind === undefined;
  const lowerPath = String(path ?? '').replace(/\\/g, '/');
  if (kind === 'plugin' || (auto && PLUGIN_MANIFEST_RE.test(lowerPath))) {
    for (const f of localPlugin(content || '', { path })) push(f.severity, f.title, f.remediationText, f.line);
  }
  if (kind === 'tool-manifest' || (auto && TOOL_MANIFEST_RE.test(lowerPath))) {
    for (const f of localToolManifest(content || '', { path })) push(f.severity, f.title, f.remediationText, f.line);
  }
  if (kind === 'extension' || (auto && /(^|\/)(manifest|mcpb|dxt)\.json$/i.test(lowerPath))) {
    for (const f of localExtension(content || '', { path })) push(f.severity, f.title, f.remediationText, f.line);
  }
  if (kind === 'workflow' || (auto && ciVendorOf(lowerPath))) {
    const wfPath = ciVendorOf(lowerPath) ? lowerPath : '.github/workflows/workflow.yml';
    for (const f of agenticCiFindings({ kind: 'AGENT_WORKFLOW', path: wfPath, name: wfPath.split('/').pop(), content: content || '' })) {
      push(f.severity, f.title, f.remediationText, f.evidence?.line);
    }
  }
  const guard = guardrailOf(kind, path, content);
  if (guard) {
    for (const f of guardrailConfigFindings({ kind: 'GUARDRAIL_CONFIG', path: guard.path, name: guard.path.split('/').pop(), content: content || '', meta: { framework: guard.framework } })) {
      push(f.severity, f.title, f.remediationText, f.evidence?.line);
    }
  }
  if (framework) {
    for (const f of frameworkFindings({ kind: 'AGENT_WORKFLOW', path: framework.path, name: framework.path.split('/').pop(), content: content || '', meta: { framework: framework.framework } })) {
      push(f.severity, f.title, f.remediationText, f.evidence?.line);
    }
  }

  const seenTitle = new Set();
  const deduped = findings.filter((f) => (seenTitle.has(f.title) ? false : (seenTitle.add(f.title), true)));
  findings.length = 0;
  findings.push(...deduped);

  const { verdict, riskScore } = grade(findings);
  return { verdict, riskScore, findings };
}
