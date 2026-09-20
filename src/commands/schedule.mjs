import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { CONFIG_FILE, MACHINE_CONFIG_FILE, loadMachineConfig } from '../core/config.mjs';
import { EXIT_USAGE } from '../core/exit-codes.mjs';
import { CLI_ENTRY_PATH } from '../core/package-root.mjs';
import {
  CRON_MARKER, SCHEDULE_LABEL, SYSTEMD_UNIT, TASK_NAME, cronLine, launchdLogPath, launchdPlist, launchdPlistPath, mergeCrontab,
  parseEvery, reportArgs, schtasksCreateArgs, systemdService, systemdTimer, systemdUnitDir, windowsTaskXml,
} from '../core/schedule-plan.mjs';
import { bold, dim, green, red, yellow } from '../core/terminal.mjs';
import { homesRoot, isPrivileged } from '../core/user-homes.mjs';

const LAUNCHCTL = '/bin/launchctl';
const CRONTAB = '/usr/bin/crontab';

function run(bin, args, opts = {}) {
  return execFileSync(bin, args, { encoding: 'utf8', timeout: 30000, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'], ...opts });
}

function tryRun(bin, args, opts = {}) {
  try {
    return { ok: true, out: run(bin, args, opts) };
  } catch (e) {
    return { ok: false, out: String(e.stdout ?? ''), err: String(e.stderr ?? e.message ?? '') };
  }
}

function schtasksPath(env = process.env) {
  return path.win32.join(env.SystemRoot || env.SYSTEMROOT || 'C:\\Windows', 'System32', 'schtasks.exe');
}

function systemctlPath() {
  return ['/usr/bin/systemctl', '/bin/systemctl'].find((p) => fs.existsSync(p)) ?? null;
}

function fail(msg) {
  console.error(`${red('✗')} ${msg}`);
  process.exit(EXIT_USAGE);
}

function writeFile(file, text, mode) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, text, { mode });
  try {
    fs.chmodSync(file, mode);
  } catch {}
}

function configHint(system) {
  if (!system) {
    if (!fs.existsSync(CONFIG_FILE) && !loadMachineConfig()) console.log(`  ${yellow('⚠')} ${dim('No config yet - run')} ${bold('shomra init --key … --url …')} ${dim('or the task will fail to report.')}`);
    return;
  }
  if (!loadMachineConfig()) console.log(`  ${yellow('⚠')} ${dim(`No machine config at ${MACHINE_CONFIG_FILE} - run`)} ${bold('shomra init --machine --key … --url …')} ${dim('so the scheduled report can authenticate.')}`);
}

export function userWritablePaths(files, { platform = process.platform, env = process.env, stat = fs.statSync } = {}) {
  if (platform === 'win32') {
    const users = homesRoot(platform, env).toLowerCase() + '\\';
    return files.filter((f) => String(f).toLowerCase().startsWith(users));
  }
  const out = [];
  for (const f of files) {
    for (let p = f; ; p = path.posix.dirname(p)) {
      let st;
      try {
        st = stat(p);
      } catch {
        break;
      }
      if (st.uid !== 0 || (st.mode & 0o022 && !(st.mode & 0o1000))) {
        out.push(f);
        break;
      }
      if (p === path.posix.dirname(p)) break;
    }
  }
  return out;
}

function installDarwin(ctx) {
  const plist = launchdPlistPath(ctx);
  const logFile = launchdLogPath(ctx);
  fs.mkdirSync(path.dirname(logFile), { recursive: true });
  writeFile(plist, launchdPlist({ ...ctx, logFile }), 0o644);
  const domain = ctx.system ? 'system' : `gui/${process.getuid()}`;
  tryRun(LAUNCHCTL, ['bootout', `${domain}/${SCHEDULE_LABEL}`]);
  const res = tryRun(LAUNCHCTL, ['bootstrap', domain, plist]);
  if (!res.ok) {
    const legacy = tryRun(LAUNCHCTL, ['load', '-w', plist]);
    if (!legacy.ok) throw new Error(`launchctl could not load ${plist}: ${res.err.trim() || legacy.err.trim()}`);
  }
  return `${ctx.system ? 'LaunchDaemon' : 'LaunchAgent'} ${plist}`;
}

function removeDarwin(ctx) {
  const plist = launchdPlistPath(ctx);
  const domain = ctx.system ? 'system' : `gui/${process.getuid()}`;
  tryRun(LAUNCHCTL, ['bootout', `${domain}/${SCHEDULE_LABEL}`]);
  const existed = fs.existsSync(plist);
  fs.rmSync(plist, { force: true });
  return existed ? plist : null;
}

function statusDarwin(ctx) {
  const plist = launchdPlistPath(ctx);
  if (!fs.existsSync(plist)) return { installed: false, where: plist };
  const domain = ctx.system ? 'system' : `gui/${process.getuid()}`;
  return { installed: true, loaded: tryRun(LAUNCHCTL, ['print', `${domain}/${SCHEDULE_LABEL}`]).ok, where: plist };
}

function installWin32(ctx) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'shomra-task-'));
  const xmlFile = path.join(tmpDir, 'task.xml');
  const userId = ctx.system ? null : [process.env.USERDOMAIN, process.env.USERNAME].filter(Boolean).join('\\') || null;
  const body = windowsTaskXml({ ...ctx, userId });
  fs.writeFileSync(xmlFile, Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(body, 'utf16le')]));
  try {
    const res = tryRun(schtasksPath(), schtasksCreateArgs(xmlFile));
    if (!res.ok) throw new Error(`schtasks could not create ${TASK_NAME}: ${(res.err || res.out).trim()}`);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
  return `scheduled task ${TASK_NAME}${ctx.system ? ' (SYSTEM)' : ''}`;
}

function removeWin32() {
  return tryRun(schtasksPath(), ['/Delete', '/TN', TASK_NAME, '/F']).ok ? TASK_NAME : null;
}

function statusWin32() {
  const res = tryRun(schtasksPath(), ['/Query', '/TN', TASK_NAME, '/FO', 'LIST', '/V']);
  if (!res.ok) return { installed: false, where: TASK_NAME };
  const field = (name) => new RegExp(`^${name}:\\s*(.*)$`, 'mi').exec(res.out)?.[1]?.trim() ?? null;
  return { installed: true, where: TASK_NAME, status: field('Status'), lastRun: field('Last Run Time'), nextRun: field('Next Run Time'), lastResult: field('Last Result'), runAs: field('Run As User') };
}

function installLinux(ctx) {
  const systemctl = systemctlPath();
  const scope = ctx.system ? [] : ['--user'];
  if (systemctl) {
    const dir = systemdUnitDir(ctx);
    writeFile(path.join(dir, `${SYSTEMD_UNIT}.service`), systemdService(ctx), 0o644);
    writeFile(path.join(dir, `${SYSTEMD_UNIT}.timer`), systemdTimer(ctx), 0o644);
    const reload = tryRun(systemctl, [...scope, 'daemon-reload']);
    const enable = reload.ok ? tryRun(systemctl, [...scope, 'enable', '--now', `${SYSTEMD_UNIT}.timer`]) : reload;
    if (enable.ok) return `systemd ${ctx.system ? 'system' : 'user'} timer ${SYSTEMD_UNIT}.timer`;
    for (const ext of ['service', 'timer']) fs.rmSync(path.join(dir, `${SYSTEMD_UNIT}.${ext}`), { force: true });
    if (!fs.existsSync(CRONTAB)) throw new Error(`systemctl failed: ${enable.err.trim()}`);
  }
  if (!fs.existsSync(CRONTAB)) throw new Error('neither systemctl nor /usr/bin/crontab is available');
  const current = tryRun(CRONTAB, ['-l']);
  const next = mergeCrontab(current.ok ? current.out : '', cronLine(ctx));
  run(CRONTAB, ['-'], { input: next });
  return `crontab entry ${CRON_MARKER}`;
}

function removeLinux(ctx) {
  const removed = [];
  const systemctl = systemctlPath();
  const dir = systemdUnitDir(ctx);
  if (fs.existsSync(path.join(dir, `${SYSTEMD_UNIT}.timer`))) {
    const scope = ctx.system ? [] : ['--user'];
    if (systemctl) tryRun(systemctl, [...scope, 'disable', '--now', `${SYSTEMD_UNIT}.timer`]);
    for (const ext of ['service', 'timer']) fs.rmSync(path.join(dir, `${SYSTEMD_UNIT}.${ext}`), { force: true });
    if (systemctl) tryRun(systemctl, [...scope, 'daemon-reload']);
    removed.push(`${SYSTEMD_UNIT}.timer`);
  }
  if (fs.existsSync(CRONTAB)) {
    const current = tryRun(CRONTAB, ['-l']);
    if (current.ok && current.out.includes(CRON_MARKER)) {
      run(CRONTAB, ['-'], { input: mergeCrontab(current.out, null) });
      removed.push(`crontab ${CRON_MARKER}`);
    }
  }
  return removed.length ? removed.join(', ') : null;
}

function statusLinux(ctx) {
  const dir = systemdUnitDir(ctx);
  const timer = path.join(dir, `${SYSTEMD_UNIT}.timer`);
  const systemctl = systemctlPath();
  if (fs.existsSync(timer)) {
    const scope = ctx.system ? [] : ['--user'];
    const active = systemctl ? tryRun(systemctl, [...scope, 'is-active', `${SYSTEMD_UNIT}.timer`]).out.trim() : null;
    return { installed: true, where: timer, status: active };
  }
  if (fs.existsSync(CRONTAB)) {
    const current = tryRun(CRONTAB, ['-l']);
    const line = current.ok ? current.out.split(/\r?\n/).find((l) => l.includes(CRON_MARKER)) : null;
    if (line) return { installed: true, where: 'crontab', status: line.replace(CRON_MARKER, '').trim() };
  }
  return { installed: false, where: timer };
}

const PLATFORM = {
  darwin: { install: installDarwin, remove: removeDarwin, status: statusDarwin },
  win32: { install: installWin32, remove: removeWin32, status: statusWin32 },
  linux: { install: installLinux, remove: removeLinux, status: statusLinux },
};

function context(flags) {
  const system = isPrivileged();
  return { system, home: os.homedir(), node: process.execPath, entry: CLI_ENTRY_PATH, args: reportArgs({ allUsers: !!flags['all-users'] || system }) };
}

export async function cmdSchedule(flags, positional = []) {
  const sub = positional[0] ?? 'status';
  const impl = PLATFORM[process.platform] ?? PLATFORM.linux;
  if (!['install', 'remove', 'status'].includes(sub)) fail(`Unknown schedule command: ${sub}. Use ${bold('shomra schedule install|remove|status')}`);
  const ctx = context(flags);
  if (sub === 'install') {
    let hours;
    try {
      hours = parseEvery(flags.every);
    } catch (e) {
      fail(e.message);
    }
    let where;
    try {
      where = impl.install({ ...ctx, hours });
    } catch (e) {
      console.error(`${red('✗')} ${e.message}`);
      process.exit(1);
    }
    console.log(`  ${green('✓')} Installed ${bold(where)} ${dim(`- runs \`shomra ${ctx.args.join(' ')}\` every ${hours}h`)}`);
    configHint(ctx.system);
    if (ctx.system) {
      for (const f of userWritablePaths([ctx.node, ctx.entry])) console.log(`  ${yellow('⚠')} ${dim(`${f} is not exclusively root/Administrator-writable, yet runs with root/SYSTEM rights - install Node and @shomra/agent to an admin-owned prefix (see shomra admin mdm-script).`)}`);
    }
    return;
  }
  if (sub === 'remove') {
    const removed = impl.remove(ctx);
    console.log(removed ? `  ${green('✓')} Removed ${bold(removed)}` : `  ${dim('No Shomra schedule was installed.')}`);
    return;
  }
  const st = impl.status(ctx);
  if (flags.json) {
    console.log(JSON.stringify({ ...st, system: ctx.system }, null, 2));
    return;
  }
  if (!st.installed) {
    console.log(`  ${dim('Not scheduled')} ${dim(`(${st.where})`)} - ${bold('shomra schedule install')}`);
    return;
  }
  console.log(`  ${green('●')} Scheduled ${bold(st.where)}${st.loaded === false ? yellow(' (not loaded)') : ''}`);
  for (const k of ['status', 'runAs', 'lastRun', 'nextRun', 'lastResult']) if (st[k]) console.log(`    ${dim(k.padEnd(10))} ${st[k]}`);
}
