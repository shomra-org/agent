import { EXIT_USAGE } from '../core/exit-codes.mjs';
import { bold, dim, red } from '../core/terminal.mjs';
import { VERSION } from '../core/version.mjs';
import { KNOWN_FLAGS, parseFlags } from './flags.mjs';
import { cmdAdminHelp, cmdHelp } from './help.mjs';
import { ADMIN_VERBS, COMMANDS } from './registry.mjs';
import { didYouMean } from './suggestions.mjs';

export async function main() {
  const [, , command, ...rest] = process.argv;

  const sep = rest.indexOf('--');
  const ours = sep === -1 ? rest : rest.slice(0, sep);
  const { flags, positional, unknown } = parseFlags(ours);

  if (command === 'help' || command === undefined || command === '--help' || command === '-h') {
    return cmdHelp();
  }
  if (command === '--version' || command === '-v' || command === 'version') {
    console.log(VERSION);
    return;
  }

  const guardCmd = command === 'tool-guard' || command === 'result-guard' || command === 'prompt-guard' || command === 'plan-guard' || command === 'session-guard';
  if (unknown.length && !guardCmd) {
    for (const u of unknown) {
      const near = didYouMean(u, [...KNOWN_FLAGS]);
      console.error(red(`✗ Unknown flag: --${u}`) + (near ? dim(`  (did you mean --${near}?)`) : ''));
    }
    console.error(dim('Run `shomra help` for the full option list.'));
    process.exit(EXIT_USAGE);
  }

  if (command === 'admin') {
    const sub = positional[0];
    if (!sub || sub === 'help' || flags.help) return cmdAdminHelp();
    const fn = COMMANDS[sub];
    if (!fn || !ADMIN_VERBS.has(sub)) {
      const near = didYouMean(sub, [...ADMIN_VERBS]);
      console.error(red(`✗ Unknown admin command: ${sub ?? ''}`) + (near ? `  did you mean ${bold(near)}?` : ''));
      console.error(dim('Run `shomra admin` for the list.'));
      process.exit(EXIT_USAGE);
    }
    return fn(flags, positional.slice(1));
  }

  const fn = COMMANDS[command];
  if (!fn) {
    const near = didYouMean(command, [...Object.keys(COMMANDS), 'help', 'version', 'admin']);
    console.error(red(`✗ Unknown command: ${command}`) + (near ? `  did you mean ${bold(near)}?` : ''));
    console.error(dim('Run `shomra help` for the full command list.'));
    process.exit(EXIT_USAGE);
  }
  return fn(flags, positional);
}
