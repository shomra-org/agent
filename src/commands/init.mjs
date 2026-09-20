import os from 'node:os';
import { api, machineInfo } from '../core/api-client.mjs';
import { CONFIG_FILE, MACHINE_CONFIG_FILE, getMachineId, loadConfig, loadMachineConfig, markMachineConfig, saveConfig } from '../core/config.mjs';
import { EXIT_USAGE } from '../core/exit-codes.mjs';
import { bold, dim, green, red } from '../core/terminal.mjs';
import { isPrivileged } from '../core/user-homes.mjs';

export async function cmdInit(flags) {
  if (flags.machine && !isPrivileged()) {
    console.error(red('✗') + ' ' + bold('shomra init --machine') + ` writes ${MACHINE_CONFIG_FILE} and must run as root (sudo) or an elevated Administrator.`);
    process.exit(EXIT_USAGE);
  }
  const cfg = flags.machine ? markMachineConfig(loadMachineConfig() ?? {}) : loadConfig();
  const key = flags.key || process.env.SHOMRA_API_KEY;

  const url = (flags.url || process.env.SHOMRA_URL || cfg.url || '').replace(/\/$/, '');
  if (!key) {
    console.error(red('✗') + ' Missing API key. Run: ' + bold('shomra init --key shm_live_… --url <your backend>'));
    process.exit(EXIT_USAGE);
  }
  if (!url) {
    console.error(red('✗') + ' Missing backend URL. Run: ' + bold('shomra init --key shm_live_… --url <your backend>'));
    process.exit(EXIT_USAGE);
  }
  cfg.apiKey = key;
  cfg.url = url;
  getMachineId(cfg);
  saveConfig(cfg);
  process.stdout.write(dim('Enrolling this machine… '));
  try {
    const res = await api(url, key, '/agent/enroll', { machine: machineInfo(cfg) });
    console.log(green('done'));
    console.log(`  ${green('✓')} Enrolled ${bold(os.hostname())} into org ${bold(res.org?.name ?? '?')}`);
    console.log(`  ${dim('Config saved to ' + (flags.machine ? MACHINE_CONFIG_FILE : CONFIG_FILE))}`);
    console.log(`\n  Next: ${bold(flags.machine ? 'shomra schedule install --all-users' : 'shomra report')} to send your first inventory.`);
  } catch (e) {
    console.log(red('failed'));
    console.error(`  ${red('✗')} ${e.message}`);
    process.exit(1);
  }
}
