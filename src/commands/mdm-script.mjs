import { EXIT_USAGE } from '../core/exit-codes.mjs';
import { mdmScript } from '../core/mdm-script.mjs';
import { red } from '../core/terminal.mjs';

export function cmdMdmScript(flags) {
  let text;
  try {
    text = mdmScript({ os: flags.os, key: flags.key, url: flags.url, every: flags.every });
  } catch (e) {
    console.error(`${red('✗')} ${e.message}  (usage: shomra admin mdm-script --os macos|windows|linux [--url <url>] [--key <key>] [--every 6h])`);
    process.exit(EXIT_USAGE);
  }
  process.stdout.write(text);
}
