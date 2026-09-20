import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  CRON_MARKER, cronLine, cronSchedule, launchdPlist, launchdPlistPath, mergeCrontab, parseEvery, reportArgs,
  schtasksCreateArgs, systemdService, systemdTimer, systemdUnitDir, windowsQuote, windowsTaskXml,
} from '../src/core/schedule-plan.mjs';
import { mdmScript } from '../src/core/mdm-script.mjs';
import { loadMachineConfig, machineConfigFile, markMachineConfig, isMachineConfig } from '../src/core/config.mjs';
import { userWritablePaths } from '../src/commands/schedule.mjs';

const KEY = 'shm_live_SUPERSECRETKEY123';
const ctx = { node: '/usr/local/bin/node', entry: '/usr/local/shomra/lib/node_modules/@shomra/agent/shomra.mjs', args: reportArgs({ allUsers: true }), hours: 6 };

test('--every accepts 1h..168h and days, rejects everything else', () => {
  assert.equal(parseEvery(undefined), 6);
  assert.equal(parseEvery('1h'), 1);
  assert.equal(parseEvery('12'), 12);
  assert.equal(parseEvery('7d'), 168);
  assert.equal(parseEvery('168h'), 168);
  for (const bad of ['0h', '169h', '8d', '-1h', '6m', 'abc', '1.5h']) assert.throws(() => parseEvery(bad), /--every/, bad);
});

test('the report command line carries --all-users only when asked', () => {
  assert.deepEqual(reportArgs(), ['report']);
  assert.deepEqual(reportArgs({ allUsers: true }), ['report', '--all-users']);
});

test('launchd plist runs node + entry on the interval and lands in the right domain', () => {
  const xml = launchdPlist({ ...ctx, logFile: '/Library/Logs/Shomra/report.log' });
  assert.match(xml, /<string>io\.shomra\.report<\/string>/);
  assert.match(xml, /<string>\/usr\/local\/bin\/node<\/string>\s*<string>[^<]*shomra\.mjs<\/string>\s*<string>report<\/string>\s*<string>--all-users<\/string>/);
  assert.match(xml, /<key>StartInterval<\/key>\s*<integer>21600<\/integer>/);
  assert.equal(launchdPlistPath({ system: true }), '/Library/LaunchDaemons/io.shomra.report.plist');
  assert.equal(launchdPlistPath({ system: false, home: '/Users/a' }), '/Users/a/Library/LaunchAgents/io.shomra.report.plist');
  assert.match(launchdPlist({ ...ctx, entry: '/a&b/<x>.mjs', logFile: '/l' }), /\/a&amp;b\/&lt;x&gt;\.mjs/);
});

test('Windows task XML runs as SYSTEM on battery and quotes spaced paths', () => {
  const xml = windowsTaskXml({ node: 'C:\\Program Files\\nodejs\\node.exe', entry: 'C:\\Program Files\\Shomra\\node_modules\\@shomra\\agent\\shomra.mjs', args: reportArgs({ allUsers: true }), hours: 12, system: true });
  assert.match(xml, /<UserId>S-1-5-18<\/UserId>/);
  assert.match(xml, /<Interval>PT12H<\/Interval>/);
  assert.match(xml, /<DisallowStartIfOnBatteries>false<\/DisallowStartIfOnBatteries>/);
  assert.match(xml, /<Command>C:\\Program Files\\nodejs\\node\.exe<\/Command>/);
  assert.match(xml, /<Arguments>&quot;C:\\Program Files\\Shomra\\node_modules\\@shomra\\agent\\shomra\.mjs&quot; report --all-users<\/Arguments>/);
  const user = windowsTaskXml({ ...ctx, system: false, userId: 'CORP\\dana' });
  assert.match(user, /<UserId>CORP\\dana<\/UserId>\s*<LogonType>InteractiveToken<\/LogonType>/);
  assert.deepEqual(schtasksCreateArgs('C:\\t\\task.xml'), ['/Create', '/TN', 'ShomraReport', '/XML', 'C:\\t\\task.xml', '/F']);
  assert.equal(windowsQuote('plain'), 'plain');
  assert.equal(windowsQuote('C:\\a b\\'), '"C:\\a b\\\\"');
  assert.equal(windowsQuote('say "hi"'), '"say \\"hi\\""');
});

test('systemd units: oneshot service + timer, system vs user scope', () => {
  const svc = systemdService({ ...ctx, entry: '/opt/x y/shomra.mjs' });
  assert.match(svc, /Type=oneshot/);
  assert.match(svc, /ExecStart="\/usr\/local\/bin\/node" "\/opt\/x y\/shomra\.mjs" "report" "--all-users"/);
  assert.match(systemdTimer({ hours: 6, system: true }), /OnUnitActiveSec=6h[\s\S]*WantedBy=timers\.target/);
  assert.match(systemdTimer({ hours: 6, system: false }), /WantedBy=default\.target/);
  assert.equal(systemdUnitDir({ system: true }), '/etc/systemd/system');
  assert.equal(systemdUnitDir({ system: false, home: '/home/k' }), '/home/k/.config/systemd/user');
});

test('cron fallback schedules, quotes and replaces only its own line', () => {
  assert.equal(cronSchedule(6), '17 */6 * * *');
  assert.equal(cronSchedule(48), '17 3 */2 * *');
  assert.throws(() => cronSchedule(30), /cron/);
  const line = cronLine({ ...ctx, entry: "/opt/it's/100%/shomra.mjs" });
  assert.ok(line.endsWith(CRON_MARKER));
  assert.match(line, /'\/opt\/it'\\''s\/100\\%\/shomra\.mjs'/);
  const merged = mergeCrontab(`MAILTO=x\n0 1 * * * backup\n5 */2 * * * old ${CRON_MARKER}\n`, line);
  assert.equal(merged, `MAILTO=x\n0 1 * * * backup\n${line}\n`);
  assert.equal(mergeCrontab(merged, null), 'MAILTO=x\n0 1 * * * backup\n');
});

test('no scheduled artifact ever embeds the API key', () => {
  const prev = process.env.SHOMRA_API_KEY;
  process.env.SHOMRA_API_KEY = KEY;
  try {
    const outputs = [
      launchdPlist({ ...ctx, logFile: '/l' }),
      windowsTaskXml({ ...ctx, system: true }),
      systemdService(ctx),
      systemdTimer({ hours: 6, system: true }),
      cronLine(ctx),
      schtasksCreateArgs('x').join(' '),
    ];
    for (const out of outputs) {
      assert.ok(!out.includes(KEY), out);
      assert.ok(!/--key|shm_/.test(out), out);
    }
  } finally {
    if (prev === undefined) delete process.env.SHOMRA_API_KEY;
    else process.env.SHOMRA_API_KEY = prev;
  }
});

test('mdm-script reads the key from the MDM secret variable when --key is omitted', () => {
  const mac = mdmScript({ os: 'macos', url: 'https://api.example.com/' });
  assert.match(mac, /^#!\/bin\/bash/);
  assert.match(mac, /SHOMRA_API_KEY="\$\{SHOMRA_API_KEY:-\$\{4:-\}\}"/);
  assert.match(mac, /SHOMRA_URL=\x27https:\/\/api\.example\.com\x27/);
  assert.match(mac, /init --machine --url "\$SHOMRA_URL"/);
  assert.match(mac, /schedule install --all-users --every 6h/);
  assert.match(mac, /report --all-users/);
  assert.ok(!/--key/.test(mac));
  const win = mdmScript({ os: 'windows', every: '12h' });
  assert.match(win, /\$ApiKey = \$env:SHOMRA_API_KEY/);
  assert.match(win, /--every 12h/);
  assert.match(win, /node_modules\\@shomra\\agent\\shomra\.mjs/);
  assert.ok(!/shm_/.test(win));
  const linux = mdmScript({ os: 'linux', url: 'https://x' });
  assert.match(linux, /SHOMRA_API_KEY="\$\{SHOMRA_API_KEY:-\}"/);
});

test('mdm-script embeds an explicit key safely quoted and never on a command line', () => {
  const mac = mdmScript({ os: 'macos', key: "shm_live_a'b", url: 'https://x' });
  assert.match(mac, /SHOMRA_API_KEY='shm_live_a'\\''b'/);
  assert.ok(!/--key/.test(mac));
  const win = mdmScript({ os: 'windows', key: "shm_live_a'b", url: 'https://x' });
  assert.match(win, /\$ApiKey = 'shm_live_a''b'/);
  assert.throws(() => mdmScript({ os: 'solaris' }), /--os/);
  assert.throws(() => mdmScript({ os: 'linux', every: '500h' }), /--every/);
});

test('machine-wide config lives in a root-only location and is read as a fallback', () => {
  assert.equal(machineConfigFile('linux', {}), '/etc/shomra/config.json');
  assert.equal(machineConfigFile('darwin', {}), '/etc/shomra/config.json');
  assert.equal(machineConfigFile('win32', { ProgramData: 'D:\\PD' }), 'D:\\PD\\Shomra\\config.json');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shomra-mcfg-'));
  try {
    const file = path.join(dir, 'config.json');
    assert.equal(loadMachineConfig(file), null);
    fs.writeFileSync(file, JSON.stringify({ apiKey: 'k', url: 'https://x' }));
    const cfg = markMachineConfig(loadMachineConfig(file));
    assert.equal(cfg.apiKey, 'k');
    assert.equal(isMachineConfig(cfg), true);
    assert.equal(JSON.stringify(cfg).includes('machineConfig'), false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('privileged schedules flag a node or entry a non-admin could swap', () => {
  const win = userWritablePaths(['C:\\Users\\dana\\AppData\\Roaming\\npm\\node_modules\\@shomra\\agent\\shomra.mjs', 'C:\\Program Files\\nodejs\\node.exe'], { platform: 'win32', env: { SystemDrive: 'C:' } });
  assert.equal(win.length, 1);
  const stats = { '/usr/local/bin/node': { uid: 501, mode: 0o755 }, '/opt/s/shomra.mjs': { uid: 0, mode: 0o644 }, '/opt/s': { uid: 0, mode: 0o777 }, '/opt': { uid: 0, mode: 0o755 }, '/': { uid: 0, mode: 0o755 } };
  const stat = (p) => {
    if (!stats[p]) throw new Error('ENOENT');
    return stats[p];
  };
  assert.deepEqual(userWritablePaths(['/usr/local/bin/node', '/opt/s/shomra.mjs'], { platform: 'linux', stat }), ['/usr/local/bin/node', '/opt/s/shomra.mjs']);
  stats['/opt/s'].mode = 0o755;
  assert.deepEqual(userWritablePaths(['/opt/s/shomra.mjs'], { platform: 'linux', stat }), []);
});
