#!/usr/bin/env node
const GUARD_VERBS = {
  'tool-guard': ['./src/guard/tool-guard.mjs', 'cmdToolGuard'],
  'result-guard': ['./src/guard/result-guard.mjs', 'cmdResultGuard'],
  'prompt-guard': ['./src/guard/prompt-guard.mjs', 'cmdPromptGuard'],
  'session-guard': ['./src/guard/session-guard.mjs', 'cmdSessionGuard'],
  'plan-guard': ['./src/commands/plan.mjs', 'cmdPlanGuard'],
};

async function reportFatal(cause) {
  const error = cause instanceof Error ? cause : new Error(String(cause));
  const { dim, red } = await import('./src/core/terminal.mjs');
  console.error(red(`✗ ${error.message}`));
  if (process.env.SHOMRA_DEBUG) console.error(dim(error.stack ?? ''));
  process.exit(1);
}

process.on('unhandledRejection', reportFatal);

async function run() {
  const guard = GUARD_VERBS[process.argv[2]];
  if (guard) {
    const [{ parseFlags }, mod] = await Promise.all([import('./src/cli/flags.mjs'), import(guard[0])]);
    const args = process.argv.slice(3);
    const sep = args.indexOf('--');
    const { flags, positional } = parseFlags(sep === -1 ? args : args.slice(0, sep));
    return mod[guard[1]](flags, positional);
  }
  const { main } = await import('./src/cli/main.mjs');
  return main();
}

run().catch(reportFatal);
