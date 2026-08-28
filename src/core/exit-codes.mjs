import { bold, dim, red } from './terminal.mjs';

export const EXIT_USAGE = 3;

export function exitNotConfigured() {
  console.error('\n' + red('✗') + ' Not configured. Run ' + bold('shomra init --key shm_live_… --url <your backend>') + ' first.');
  console.error('  ' + dim('Get a key in the Shomra app → Settings → API Keys.'));
  process.exit(EXIT_USAGE);
}
