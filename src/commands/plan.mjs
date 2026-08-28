import fs from 'node:fs';
import path from 'node:path';
import { gateMachine } from '../core/api-client.mjs';
import { loadConfig, resolveSettings } from '../core/config.mjs';
import { EXIT_USAGE } from '../core/exit-codes.mjs';
import { bold, dim, red, yellow } from '../core/terminal.mjs';
import { CAP_LABEL, analyzeDesign } from '../detect/design.mjs';
import { detectEnv } from '../gate/environment.mjs';
import { emitGuardAsk } from '../guard/emit.mjs';
import { envFlag, resolveAgentFlag } from '../guard/options.mjs';
import { reportGuardDecision } from '../guard/report.mjs';

function planAdvice(r, { maxControls = 5 } = {}) {
  if (r.verdict !== 'OPEN_PATH') return null;
  const worst = r.paths.filter((p) => p.severity === r.worst).slice(0, 3);
  const lines = [
    `[Shomra] This plan closes ${r.paths.length} attack path${r.paths.length === 1 ? '' : 's'}. Build the guarded version now - it is far cheaper than retrofitting it:`,
  ];
  for (const p of worst) lines.push(`- ${p.severity}: ${CAP_LABEL[p.source]} reaches ${CAP_LABEL[p.sink]}. ${p.story}`);
  lines.push('Satisfy these as you implement:');
  for (const c of r.controls.slice(0, maxControls)) lines.push(`- ${c.text}`);
  lines.push('If the plan does not actually involve one of these, say so and continue - this reads your plan text, not your intent.');
  return lines.join('\n');
}

export async function cmdPlan(flags, positional) {
  const target = positional[0] || flags.path;
  if (!target) {
    console.error(red('✗') + ' Usage: ' + bold('shomra plan <file|->') + dim('  (use - to pipe the plan on stdin)'));
    process.exit(EXIT_USAGE);
  }
  let text;
  if (target === '-' || flags.stdin) text = fs.readFileSync(0, 'utf8');
  else {
    const abs = path.resolve(String(target));
    if (!fs.existsSync(abs)) { console.error(red('✗') + ` Not found: ${target}`); process.exit(EXIT_USAGE); }
    text = fs.readFileSync(abs, 'utf8');
  }

  const r = analyzeDesign(text, { name: typeof target === 'string' ? String(target) : 'plan' });
  const advice = planAdvice(r);

  if (flags.json) console.log(JSON.stringify({ verdict: r.verdict, worst: r.worst, paths: r.paths, controls: r.controls, advice }, null, 2));
  else if (advice) console.log('\n' + advice + '\n');
  else console.log('\n  ' + yellow('• No closed attack path in this plan text.') + dim(' Not a clearance - it reads the plan, not the code you will write.\n'));

  if (r.worst === 'CRITICAL') process.exitCode = 1;
  else if (r.verdict === 'OPEN_PATH' && flags.strict) process.exitCode = 2;
}

export async function cmdPlanGuard(flags) {
  const agent = resolveAgentFlag(flags);
  if (envFlag('SHOMRA_PLAN_GUARD_OFF')) process.exit(0);

  let payload = {};
  try { payload = JSON.parse(fs.readFileSync(0, 'utf8') || '{}'); } catch { process.exit(0); }

  const input = payload.tool_input ?? payload.input ?? payload.arguments ?? payload;
  const text = [input.plan, input.content, input.text, input.message, payload.plan]
    .find((v) => typeof v === 'string' && v.trim().length > 40);
  if (!text) process.exit(0);

  const r = analyzeDesign(text, { name: 'plan' });
  const advice = planAdvice(r);
  if (!advice) process.exit(0);

  const { apiKey, url } = resolveSettings(loadConfig());
  await reportGuardDecision(url, apiKey, null, {
    tool_name: 'PlanSubmit',
    tool_input: { plan: text.slice(0, 4000) },
    cwd: payload.cwd,
    session_id: payload.session_id,
    machine: gateMachine(),
    env: detectEnv(),
    agent,
    client_decision: 'FLAG',
    client_reason: `plan closes ${r.paths.length} attack path(s); worst ${r.worst}`,
  });

  if (r.worst === 'CRITICAL' && envFlag('SHOMRA_GUARD_STRICT')) {
    emitGuardAsk(agent, advice);
  }
  process.stdout.write(JSON.stringify({
    hookSpecificOutput: { hookEventName: 'PreToolUse', additionalContext: advice },
  }));
  process.exit(0);
}
