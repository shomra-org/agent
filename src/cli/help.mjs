import { HELP_SECTIONS } from './help-sections.mjs';
import { bold, cyan, dim } from '../core/terminal.mjs';

export function cmdHelp() {
  console.log(HELP_SECTIONS.map((section) => section()).join('\n'));
}

export function cmdAdminHelp() {
  console.log(`
${bold(cyan('shomra admin'))} ${dim('- governance & advanced security operations')}

  ${dim('Deep scans (backend + key)')}
  ${cyan('scan-zip')}      Static-scan a workspace ZIP            ${dim('<file.zip> [--project <id>] [--json]')}
  ${cyan('model-scan')}    SAST-scan a public AI model            ${dim('<hf-url | owner/model | github-url> [--project <id>] [--json]')}
  ${cyan('memory-scan')}   Scan memory + rules files for poisoning ${dim('[path] [--scope …] [--writer …] [--json]')}

  ${dim('Offense & runtime identity')}
  ${cyan('redteam')}       Continuously red-team your guardrails  ${dim('[--target llm-guard|model] [--evolve] [--min 80] [--fail-on-regression] [--json]')}
  ${cyan('campaign')}      Autonomous multi-turn adversary run    ${dim('[--objectives exfil-canary,tool-abuse] [--turns 6] [--min 80] [--json]')}
  ${cyan('harden')}        Auto-fix what the red-team breached     ${dim('[--run <id>] [--target llm-guard|model] [--apply] [--json]')}
  ${cyan('agent-identity')} Register a non-human agent identity    ${dim('register --name "…" --type coding-agent [--json]')}
  ${cyan('llm-proxy')}     Guardrail live LLM traffic             ${dim('[--port 4141] [--project <id>] [--agent-id <handle>]')}

  ${dim('Each also runs as a bare top-level verb (e.g.')} ${dim(bold('shomra redteam'))}${dim(') for back-compat.')}
  ${dim('Full details for any command:')} ${bold('shomra help')}
`);
}
