import { CLI_ENTRY_PATH } from '../core/package-root.mjs';
import { VERSION } from '../core/version.mjs';

export const LLM_PROXY_BASE = process.env.SHOMRA_LLM_PROXY_BASE || 'http://127.0.0.1:4141/openai/v1';

export const SELF_PATH = CLI_ENTRY_PATH;

function quoteArg(argument) {
  return /\s/.test(argument) ? `"${argument}"` : argument;
}

export const PACKAGE_SPEC = `@shomra/agent@${VERSION}`;

/**
 * ⚠⚠ AN ABSOLUTE PATH DOES NOT SURVIVE THE FILE IT IS WRITTEN INTO. A project
 * install lands in `.claude/settings.json`, which is COMMITTED - so the hook is
 * read on a colleague's laptop and inside the ephemeral cloud container Claude
 * Code on the web clones the repo into. Neither has this checkout, so the hook
 * points at nothing, the agent logs a spawn error, and NOTHING IS SCREENED while
 * the settings file says it is. Portable mode resolves through npm instead.
 *
 * ⚠ THE VERSION IS PINNED, never `@latest`. A committed hook is code that runs
 * on other people's machines; one that silently changes when we publish is not a
 * control anybody reviewed.
 */
export function hookCommand(args, opts = {}) {
  if (opts.portable) return `npx -y ${PACKAGE_SPEC} ${args}`;
  return `${quoteArg(process.execPath)} ${quoteArg(SELF_PATH)} ${args}`;
}

export function shomraHookRe(verb) {
  return new RegExp(`(?:shomra(?:\\.mjs"?)?|@shomra/agent(?:@[\\w.\\-]+)?)\\s+${verb}`, 'i');
}

export const SHOMRA_ANY_HOOK_RE = /(?:shomra(?:\.mjs"?)?|@shomra\/agent(?:@[\w.\-]+)?)\s+(tool-guard|result-guard|prompt-guard|plan-guard|session-guard)/i;
