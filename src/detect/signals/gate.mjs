import { HIGH_IMPACT_TOOLS, baseToolName, frontmatter, isWildcardGrant, localAgentCard, localCommandExtras, localMcp, toToolList } from './artifacts.mjs';
import { autonomySeverity, localAutonomy } from './autonomy.mjs';
import { localMemory, offendingLine } from './memory.mjs';
import { INSTALL_LURE } from './packages.mjs';
import { localPropagation } from './propagation.mjs';
import { localScan } from './scan.mjs';
import { grade } from './severity.mjs';

const INSTRUCTION_BASENAMES = new Set([
  'claude.md', 'agents.md', 'agent.md', 'gemini.md', 'llms.txt', 'llms-full.txt',
  '.cursorrules', '.windsurfrules', '.clinerules', '.aiderrules', '.continuerules',
  '.goosehints', 'copilot-instructions.md', 'conventions.md',
]);

const MEMORY_BASENAMES = new Set(['memory.md', 'mem0.json', 'letta_memory.json', 'memgpt_memory.json']);

function governedKindFor(kind, path) {
  if (kind === 'rules') return 'INSTRUCTION';
  if (kind === 'memory') return 'MEMORY';
  if (kind && kind !== 'auto') return null;
  const lower = String(path ?? '').split(/[\\/]+/).join('/').toLowerCase();
  if (!lower) return null;
  const base = lower.slice(lower.lastIndexOf('/') + 1);
  if (INSTRUCTION_BASENAMES.has(base) || /(^|\/)\.github\/copilot-instructions\.md$/.test(lower) ||
      /(^|\/)\.cursor\/rules\/.+\.mdc$/.test(lower) || (/(^|\/)\.clinerules\//.test(lower) && lower.endsWith('.md'))) return 'INSTRUCTION';
  if (MEMORY_BASENAMES.has(base) || /(^|\/)(\.mem0|\.letta|\.memgpt|memory)\//.test(lower)) return 'MEMORY';
  return null;
}

export function localGate(content, { kind, path } = {}) {
  const findings = [];
  const push = (severity, title, remediationText, line) => findings.push({ severity, title, remediationText, ...(line ? { line } : {}) });

  const gov = governedKindFor(kind, path);
  if (gov) {
    for (const f of localMemory(content, { kind: gov })) push(f.severity, f.title, f.remediationText, f.line);

    for (const f of localScan(content || '', { categories: ['config'] }).findings) push(f.severity, f.label, undefined, f.line);
  } else {
    const scan = localScan(content || '', { categories: ['shell', 'injection', 'secret', 'config', 'egress', 'pii'] });
    for (const f of scan.findings) {

      if ((kind === 'agent-card' || kind === 'mcp') && f.category === 'pii' && f.label.includes('IPv4')) continue;
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

  if (['mcp', 'auto', undefined].includes(kind)) for (const f of localMcp(content || '')) push(f.severity, f.title, f.remediationText, f.line);
  if (['agent-card', 'auto', undefined].includes(kind)) for (const f of localAgentCard(content || '')) push(f.severity, f.title, f.remediationText, f.line);
  if (['command', 'auto', undefined].includes(kind)) for (const f of localCommandExtras(content || '')) push(f.severity, f.title, f.remediationText, f.line);

  const seenTitle = new Set();
  const deduped = findings.filter((f) => (seenTitle.has(f.title) ? false : (seenTitle.add(f.title), true)));
  findings.length = 0;
  findings.push(...deduped);

  const { verdict, riskScore } = grade(findings);
  return { verdict, riskScore, findings };
}
