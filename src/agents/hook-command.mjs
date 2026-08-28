import { CLI_ENTRY_PATH } from '../core/package-root.mjs';

export const LLM_PROXY_BASE = process.env.SHOMRA_LLM_PROXY_BASE || 'http://127.0.0.1:4141/openai/v1';

export const SELF_PATH = CLI_ENTRY_PATH;

function quoteArg(argument) {
  return /\s/.test(argument) ? `"${argument}"` : argument;
}

export function hookCommand(args) {
  return `${quoteArg(process.execPath)} ${quoteArg(SELF_PATH)} ${args}`;
}

export function shomraHookRe(verb) {
  return new RegExp(`shomra(\\.mjs"?)?\\s+${verb}`, 'i');
}

export const SHOMRA_ANY_HOOK_RE = /shomra(\.mjs"?)?\s+(tool-guard|result-guard|prompt-guard|plan-guard)/i;
