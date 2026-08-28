import os from 'node:os';
import { api } from '../core/api-client.mjs';
import { loadConfig, resolveSettings } from '../core/config.mjs';
import { exitNotConfigured } from '../core/exit-codes.mjs';
import { bold, cyan, dim, green, red, yellow } from '../core/terminal.mjs';

export async function cmdRedteam(flags) {
  const cfg = loadConfig();
  const { apiKey, url } = resolveSettings(cfg);
  if (!apiKey) {
    exitNotConfigured();
  }
  const targetKind = flags.target === 'model' ? 'model' : 'llm-guard';
  const scenarioKeys = typeof flags.scenarios === 'string' ? flags.scenarios.split(',').map((s) => s.trim()).filter(Boolean) : undefined;

  if (!flags.json) process.stdout.write(dim(`\n  Red-teaming your ${targetKind === 'model' ? 'model' : 'LLM Guard'}… `));
  let run;
  try {
    run = await api(url, apiKey, '/redteam/agent-run', {
      targetKind,
      ...(scenarioKeys ? { scenarioKeys } : {}),
      ...(flags.project ? { projectId: String(flags.project) } : {}),
      ...(flags.evolve ? { evolutionary: true } : flags.adaptive ? { adaptive: true } : {}),
      actor: `${os.hostname()}/${os.userInfo().username}`,
    });
  } catch (e) {
    if (!flags.json) console.log(red('failed'));
    console.error(`  ${red('✗')} ${e.message}\n`);
    process.exit(1);
  }
  if (!flags.json) console.log(green('done'));

  if (flags.json) {
    console.log(JSON.stringify(run, null, 2));
  } else {
    const rc = run.resilience >= 80 ? green : run.resilience >= 60 ? yellow : red;
    console.log(`\n  ${bold(run.label)} ${dim(`· ${run.targetKind} · ${run.scenarioCount} scenarios · ${run.attemptCount} attempts`)}`);
    console.log(`  ${rc('●')} Resilience ${rc(bold(run.resilience + '/100'))} ${dim(`· ${run.breachedCount} breached · ${run.blockedCount} blocked${run.regressedCount ? ' · ' : ''}`)}${run.regressedCount ? red(run.regressedCount + ' regressed') : ''}`);
    for (const r of (run.results || []).filter((x) => x.breached)) {
      console.log(`     ${red('✗')} ${bold(r.title)} ${dim(r.technique)} ${r.regressed ? red('· REGRESSED') : ''}`);
    }
    const held = (run.results || []).filter((x) => !x.breached).length;
    if (held) console.log(`     ${green('✓')} ${dim(`${held} scenario(s) held`)}`);
    console.log(
      '\n  ' +
        (run.breachedCount === 0
          ? green('✓ All scenarios defended.')
          : yellow(`⚠ ${run.breachedCount} scenario(s) breached your defenses.`)) +
        dim(' Full report in the Shomra dashboard → Red Team.\n'),
    );
  }

  const min = flags.min != null ? parseInt(flags.min, 10) : null;
  const belowFloor = Number.isFinite(min) && run.resilience < min;
  const regressed = flags['fail-on-regression'] && run.regressedCount > 0;
  if (belowFloor) console.error(red(`  ✗ Resilience ${run.resilience} is below the required ${min}.`));
  if (regressed) console.error(red(`  ✗ ${run.regressedCount} scenario(s) regressed since the last run.`));
  if (belowFloor || regressed) process.exitCode = 1;
}

export async function cmdCampaign(flags) {
  const cfg = loadConfig();
  const { apiKey, url } = resolveSettings(cfg);
  if (!apiKey) {
    exitNotConfigured();
  }
  const objectiveKeys = typeof flags.objectives === 'string' ? flags.objectives.split(',').map((s) => s.trim()).filter(Boolean) : undefined;
  const turns = flags.turns != null ? parseInt(flags.turns, 10) : undefined;

  if (!flags.json) process.stdout.write(dim('\n  Running an autonomous adversary campaign against your assistant… '));
  let run;
  try {
    run = await api(url, apiKey, '/redteam/agent-campaign', {
      ...(objectiveKeys ? { objectiveKeys } : {}),
      ...(Number.isFinite(turns) ? { turns } : {}),
      ...(flags.project ? { projectId: String(flags.project) } : {}),
      actor: `${os.hostname()}/${os.userInfo().username}`,
    });
  } catch (e) {
    if (!flags.json) console.log(red('failed'));
    console.error(`  ${red('✗')} ${e.message}\n`);
    process.exit(1);
  }
  if (!flags.json) console.log(green('done'));

  if (flags.json) {
    console.log(JSON.stringify(run, null, 2));
  } else {
    const rc = run.resilience >= 80 ? green : run.resilience >= 60 ? yellow : red;
    console.log(`\n  ${bold(run.label)} ${dim(`· ${run.scenarioCount} objective(s) · ${run.attemptCount} turns fired`)}`);
    console.log(`  ${rc('●')} Resilience ${rc(bold(run.resilience + '/100'))} ${dim(`· ${run.breachedCount} objective(s) achieved · ${run.blockedCount} turn(s) blocked by the guard`)}`);
    for (const r of (run.results || []).filter((x) => x.breached)) {
      const bt = (r.evidenceJson?.outcomes || []).filter((o) => o.breached).map((o) => o.index + 1);
      const inTurns = bt.length ? Math.min(...bt) : r.attempts;
      console.log(`     ${red('✗')} ${bold(r.title)} ${dim(`${r.technique} · achieved in ${inTurns} turn(s)`)}`);
    }
    const held = (run.results || []).filter((x) => !x.breached).length;
    if (held) console.log(`     ${green('✓')} ${dim(`${held} objective(s) defended`)}`);
    console.log(
      '\n  ' +
        (run.breachedCount === 0
          ? green('✓ Every objective was defended.')
          : yellow(`⚠ ${run.breachedCount} objective(s) achieved by the autonomous attacker.`)) +
        dim(' Full transcript in the Shomra dashboard → Red Team. Harden the guard against the winning turns.\n'),
    );
  }

  const min = flags.min != null ? parseInt(flags.min, 10) : null;
  if (Number.isFinite(min) && run.resilience < min) {
    console.error(red(`  ✗ Resilience ${run.resilience} is below the required ${min}.`));
    process.exitCode = 1;
  }
}

export async function cmdHarden(flags) {
  const cfg = loadConfig();
  const { apiKey, url } = resolveSettings(cfg);
  if (!apiKey) {
    exitNotConfigured();
  }
  const targetKind = flags.target === 'model' ? 'model' : 'llm-guard';
  const apply = !!flags.apply;
  const runId = flags.run ? String(flags.run) : undefined;

  if (!flags.json) process.stdout.write(
    dim(`\n  ${runId ? 'Hardening from run ' + runId : 'Red-teaming your ' + (targetKind === 'model' ? 'model' : 'LLM Guard') + ', then hardening'}… `),
  );
  let res;
  try {
    res = await api(url, apiKey, '/flywheel/agent-harden', {
      ...(runId ? { runId } : {}),
      targetKind,
      apply,
      actor: `${os.hostname()}/${os.userInfo().username}`,
    });
  } catch (e) {
    if (!flags.json) console.log(red('failed'));
    console.error(`  ${red('✗')} ${e.message}\n`);
    process.exit(1);
  }
  if (!flags.json) console.log(green('done'));

  if (flags.json) {
    console.log(JSON.stringify(res, null, 2));
    return;
  }

  const sc = res.status === 'APPLIED' ? green : res.status === 'VERIFIED' ? cyan : res.status === 'REJECTED' ? yellow : red;
  console.log(`\n  ${sc('●')} ${bold(res.status)} ${dim('· ' + (res.origin === 'ai' ? 'AI-generated' : 'mined') + ((res.techniques || []).length ? ' · ' + res.techniques.join(', ') : ''))}`);
  if (res.gapTotal) {
    console.log(`  ${res.gapClosed === res.gapTotal ? green('✓') : yellow('◑')} Closes ${bold(res.gapClosed + '/' + res.gapTotal)} breaching attempts`);
  }
  console.log(
    `  ${green('✓')} ${bold(String(res.signatures))} signature(s) passed the FP-gate ` +
      dim(`· ${res.falsePositives} false positives across ${res.benignTested} benign samples`),
  );
  if (res.applied) {
    const lift = res.resilienceBefore != null && res.resilienceAfter != null ? `${res.resilienceBefore} → ${res.resilienceAfter}/100` : 'live';
    console.log(`  ${green('✓')} Applied - signatures are ${bold('live')} with no redeploy. Resilience ${bold(lift)}`);
  } else if (res.status === 'VERIFIED') {
    console.log(`  ${cyan('→')} Ready. Re-run with ${bold('--apply')} to push them live, or review in the dashboard → Self-Hardening.`);
  } else if (res.status === 'REJECTED') {
    console.log(`  ${yellow('⚠')} No candidate was both effective and false-positive-free - nothing applied.`);
  }
  console.log(dim('\n  Full detail in the Shomra dashboard → Self-Hardening.\n'));
}
