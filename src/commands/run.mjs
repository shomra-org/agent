import os from 'node:os';
import { api } from '../core/api-client.mjs';
import { loadConfig, resolveSettings } from '../core/config.mjs';
import { EXIT_USAGE, exitNotConfigured } from '../core/exit-codes.mjs';
import { bold, cyan, dim, green, red, yellow } from '../core/terminal.mjs';

const STEP_MARK = {
  SUCCESS: () => green('✓'),
  FAILED: () => red('✗'),
  SKIPPED: () => dim('-'),
  RUNNING: () => cyan('•'),
  PENDING: () => dim('·'),
};

const NUMERIC = /^-?\d+(\.\d+)?$/;

function coerceInputValue(raw) {
  if (raw === 'true') return true;
  if (raw === 'false') return false;
  return NUMERIC.test(raw) ? Number(raw) : raw;
}

function parseInputs(flags) {
  const inputs = {};
  for (const entry of [].concat(flags.input ?? [])) {
    const text = String(entry);
    const separator = text.indexOf('=');
    if (separator < 0) {
      console.error(`  ${red('✗')} --input expects key=value (got ${JSON.stringify(entry)})\n`);
      process.exit(EXIT_USAGE);
    }
    inputs[text.slice(0, separator).trim()] = coerceInputValue(text.slice(separator + 1));
  }
  return inputs;
}

async function requestOrExit(request, flags) {
  try {
    return await request();
  } catch (error) {
    if (!flags.json) console.log(red('failed'));
    console.error(`  ${red('✗')} ${error.message}\n`);
    return process.exit(1);
  }
}

function printCatalog(catalog) {
  console.log(`\n  ${bold('Playbooks')} ${dim('- run one end-to-end, exit non-zero when a gate holds')}\n`);
  for (const playbook of catalog) {
    console.log(`  ${cyan(playbook.id)} ${dim(`v${playbook.version} · ${playbook.steps.length} steps`)}`);
    console.log(`    ${playbook.name}`);
    const required = Object.entries(playbook.inputs || {}).filter(([, spec]) => spec.required).map(([key]) => key);
    if (required.length) console.log(`    ${dim('needs')} ${required.map((key) => bold(key)).join(', ')}`);
    console.log('');
  }
  console.log(dim(`  Run one:  ${bold('shomra run <id> --input key=value')}\n`));
}

async function listPlaybooks({ url, apiKey, flags, hasId }) {
  const catalog = await requestOrExit(
    () => api(url, apiKey, '/playbooks/agent/catalog', null, { method: 'GET' }),
    { json: true },
  );
  if (flags.json) {
    console.log(JSON.stringify(catalog, null, 2));
    return;
  }
  printCatalog(catalog);
  if (!hasId) process.exitCode = EXIT_USAGE;
}

function stepNote(step) {
  if (step.status === 'SKIPPED') return dim('skipped - its condition was false');
  if (!step.error) return '';
  return step.uses === 'gate' ? yellow(step.error) : red(step.error);
}

function printOutcome(run) {
  const failedStep = (run.steps || []).find((step) => step.status === 'FAILED');
  const gateHeld = run.status === 'FAILED' && failedStep?.uses === 'gate';
  console.log('');

  if (gateHeld) {
    console.log(`  ${yellow('⚠')} ${bold('The gate held.')} ${dim('That is the assertion firing - exiting non-zero.')}\n`);
    return;
  }
  if (run.status === 'FAILED') {
    console.log(`  ${red('✗')} ${bold('A step failed.')} ${dim(run.error || '')}\n`);
    return;
  }
  console.log(`  ${green('✓')} ${bold('Completed.')} ${dim('Every step that was meant to run did.')}\n`);
}

function printRun(run) {
  console.log(`\n  ${bold(run.playbookName)} ${dim(`· ${run.playbookId}`)}\n`);
  for (const step of run.steps || []) {
    const mark = (STEP_MARK[step.status] || STEP_MARK.PENDING)();
    const note = stepNote(step);
    console.log(`  ${mark} ${step.name}${note ? ` ${dim('·')} ${note}` : ''}`);
  }
  printOutcome(run);
}

export async function cmdRun(flags, positional) {
  const id = positional[0];
  const inputs = parseInputs(flags);

  const { apiKey, url } = resolveSettings(loadConfig());
  if (!apiKey) exitNotConfigured();

  if (!id || flags.list) {
    await listPlaybooks({ url, apiKey, flags, hasId: !!id });
    return;
  }

  if (!flags.json) process.stdout.write(dim(`\n  Running ${bold(id)}… `));
  const run = await requestOrExit(() => api(url, apiKey, `/playbooks/agent/${encodeURIComponent(id)}/run`, {
    inputs,
    ...(flags.project ? { projectId: String(flags.project) } : {}),
    actor: `${os.hostname()}/${os.userInfo().username}`,
  }), flags);
  if (!flags.json) console.log(green('done'));

  if (flags.json) console.log(JSON.stringify(run, null, 2));
  else printRun(run);

  if (run.status === 'FAILED') process.exitCode = 1;
}
