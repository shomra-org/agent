import fs from 'node:fs';
import path from 'node:path';
import { AGENT_LABELS } from '../agents/installers.mjs';
import { EXIT_USAGE } from '../core/exit-codes.mjs';
import { red } from '../core/terminal.mjs';
import { localGate } from '../detect/guard-signals.mjs';
import { discoverAll } from '../inventory/discovery.mjs';
import { neutralizeFindingTitle } from './context.mjs';
import { RULES_BEGIN, RULES_END, RULES_FOOTER, RULES_NOTE, RULES_TARGETS, RULES_TARGET_KEYS, RULE_SECTIONS } from './sections.mjs';

export function generateRules(ctx, { orgLines = [], includeObserved = true } = {}) {
  const parts = [];
  parts.push('## Security rules (Shomra)');
  parts.push('');
  parts.push(
    'Shomra enforces these on this machine: a tool call that breaks one is refused ' +
      'before it runs. Following them is not extra caution - it is the difference ' +
      'between a step that lands and a step that gets blocked and has to be redone.',
  );

  const used = [];
  for (const s of RULE_SECTIONS) {
    if (!s.when(ctx)) continue;
    used.push(s.id);
    parts.push('', `### ${s.title}`, '');
    for (const l of s.lines) parts.push(`- ${l}`);
  }

  if (orgLines.length) {
    used.push('org');
    parts.push('', '### Your organisation adds', '');
    for (const l of orgLines) parts.push(`- ${l}`);
  }

  if (ctx.observed.length && includeObserved) {
    used.push('observed');
    parts.push('', '### Already present in this repo', '');
    parts.push(
      `A local pass over ${ctx.artifactCount} AI artifact${ctx.artifactCount === 1 ? '' : 's'} here found the issues below. ` +
        'Do not add more of the same shape, and prefer fixing one when you are already editing that file.',
    );
    parts.push('');
    for (const o of ctx.observed) parts.push(`- ${o.severity} - ${neutralizeFindingTitle(o.title)} (${o.files.join(', ')})`);
  }

  parts.push('', '### Closing a task', '');
  for (const l of RULES_FOOTER) parts.push(`- ${l}`);

  const body = parts.join('\n').trim() + '\n';

  let gate;
  try { gate = localGate(rulesBlock(body), { kind: 'rules', path: 'CLAUDE.md' }); } catch { gate = null; }

  if (gate && gate.verdict === 'BLOCK' && includeObserved && ctx.observed.length) {
    const retry = generateRules(ctx, { orgLines, includeObserved: false });
    if (!retry.gate || retry.gate.verdict !== 'BLOCK') {
      return { ...retry, observedOmitted: ctx.observed.length };
    }
  }
  return { body, sections: used, gate };
}

export function rulesBlock(body) {
  return `${RULES_BEGIN}\n${RULES_NOTE}\n\n${body}\n${RULES_END}\n`;
}

export function mergeRulesBlock(existing, block, target) {
  const head = target.owned ? target.header || '' : '';
  if (target.owned && !existing.trim()) return head + block;

  const begin = existing.indexOf(RULES_BEGIN);
  const end = existing.indexOf(RULES_END);
  let next;
  if (begin !== -1 && end !== -1 && end > begin) {
    next = existing.slice(0, begin) + block + existing.slice(end + RULES_END.length).replace(/^\r?\n/, '');
  } else {
    next = (existing.trimEnd() ? existing.trimEnd() + '\n\n' : head) + block;
  }
  return next === existing ? null : next;
}

export function resolveRulesTargets(root, flags) {
  if (flags.agent) {
    const req = String(flags.agent).toLowerCase().split(',').map((s) => s.trim()).filter(Boolean);
    if (req.includes('all')) return [...RULES_TARGET_KEYS];
    const bad = req.filter((a) => !RULES_TARGETS[a]);
    if (bad.length) {
      console.error(red('✗') + ` No rules file is known for: ${bad.join(', ')}. Supported: ${RULES_TARGET_KEYS.join(', ')}, all.`);
      process.exit(EXIT_USAGE);
    }
    return req;
  }
  const picked = new Set(RULES_TARGET_KEYS.filter((k) => fs.existsSync(path.join(root, RULES_TARGETS[k].file))));
  try {
    const labelToKey = Object.fromEntries(Object.entries(AGENT_LABELS).map(([k, v]) => [v, k]));
    for (const a of discoverAll()) {
      if (a.type !== 'AI_AGENT') continue;
      const key = labelToKey[a.name];
      if (key && RULES_TARGETS[key]) picked.add(key);
    }
  } catch {  }
  return picked.size ? [...picked] : ['claude'];
}
