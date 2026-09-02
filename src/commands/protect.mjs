import { AGENT_INSTALLERS, AGENT_LABELS } from '../agents/installers.mjs';
import { bold, cyan, dim, green, red, yellow } from '../core/terminal.mjs';
import { discoverAll } from '../inventory/discovery.mjs';

export function cmdProtect(flags) {
  const assets = discoverAll();
  const labelToKey = Object.fromEntries(Object.entries(AGENT_LABELS).map(([k, v]) => [v, k]));
  const detected = assets
    .filter((a) => a.type === 'AI_AGENT')
    .map((a) => ({ label: a.name, key: labelToKey[a.name], guarded: !!a.metadata?.guarded }))
    .filter((a) => a.key && AGENT_INSTALLERS[a.key]);

  if (!detected.length) {
    console.log(dim('\n  No supported coding agents detected on this machine.'));
    console.log(dim('  Install one (Claude Code, Cursor, Gemini/Codex/Copilot CLI, Cline, Aider…) and re-run, or force all: ') + bold('shomra install-hook --agent all') + '\n');
    return;
  }

  const global = !(flags.local || flags.project);
  console.log(bold(cyan('\n  Shomra protect')) + dim(` - wiring the runtime firewall for ${detected.length} coding agent${detected.length > 1 ? 's' : ''} (${global ? 'machine-wide' : 'this repo'})`));
  let wired = 0, already = 0;
  for (const a of detected) {

    try {
      const { file, changed } = AGENT_INSTALLERS[a.key](global);
      if (changed) { wired++; console.log(`  ${green('✓')} Protected ${bold(AGENT_LABELS[a.key])} ${dim('→ ' + file)}`); }
      else { already++; console.log(`  ${yellow('•')} ${AGENT_LABELS[a.key]} ${dim('already protected (' + file + ')')}`); }
      if (a.key === 'aider') console.log(dim('      Aider has no tool hook - routes model calls through the LLM Guard proxy. Start ') + bold('shomra llm-proxy') + dim('.'));
    } catch (e) {
      console.log(`  ${red('✗')} ${AGENT_LABELS[a.key]} ${dim('- ' + e.message)}`);
    }
  }
  console.log(`\n  ${wired ? green(`✓ ${wired} newly protected`) : green('✓ Already protected')}${already ? dim(` · ${already} already wired`) : ''}${dim(' - tool calls, results and prompts now screened on-machine.')}`);

  if (global) {
    console.log(dim('\n  ⚠ Machine-wide only. A CLOUD session (Claude Code on the web) runs in a fresh'));
    console.log(dim('    container with none of this, and so does a colleague\'s checkout. Run ') + bold('shomra protect --project'));
    console.log(dim('    and COMMIT ') + bold('.claude/settings.json') + dim(' to cover both - the hooks resolve through npm there.'));
  } else {
    console.log(dim('\n  ✓ Written into this repo. ') + bold('Commit .claude/settings.json') + dim(' - it is what carries the firewall'));
    console.log(dim('    into cloud sessions and onto every checkout. These hooks resolve through npm, so'));
    console.log(dim('    they work on a machine that has never installed Shomra.'));
  }

  console.log(dim('\n  Get in front of the model too - both write into this repo, so run them where you mean to:'));
  console.log(`    ${bold('shomra rules --write')}   ${dim('teach the agent what gets blocked, so it never writes it')}`);
  console.log(`    ${bold('shomra mcp install')}     ${dim('let the agent gate its own proposed content before writing')}\n`);
}
