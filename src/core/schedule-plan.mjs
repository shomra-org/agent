import path from 'node:path';

export const SCHEDULE_LABEL = 'io.shomra.report';
export const TASK_NAME = 'ShomraReport';
export const SYSTEMD_UNIT = 'shomra-report';
export const CRON_MARKER = '# shomra-report';
export const MIN_HOURS = 1;
export const MAX_HOURS = 168;
export const DEFAULT_HOURS = 6;

export function parseEvery(value) {
  if (value === undefined || value === null || value === true || value === '') return DEFAULT_HOURS;
  const m = /^\s*(\d{1,4})\s*([hd])?\s*$/i.exec(String(value));
  if (!m) throw new Error(`--every must look like 6h, 12h or 1d (got "${value}")`);
  const hours = Number(m[1]) * ((m[2] || 'h').toLowerCase() === 'd' ? 24 : 1);
  if (!Number.isInteger(hours) || hours < MIN_HOURS || hours > MAX_HOURS) throw new Error(`--every must be between ${MIN_HOURS}h and ${MAX_HOURS}h (got "${value}")`);
  return hours;
}

export function reportArgs({ allUsers = false } = {}) {
  return allUsers ? ['report', '--all-users'] : ['report'];
}

const xml = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&apos;');

export function launchdPlistPath({ system, home }) {
  return system ? path.posix.join('/Library/LaunchDaemons', `${SCHEDULE_LABEL}.plist`) : path.posix.join(home, 'Library', 'LaunchAgents', `${SCHEDULE_LABEL}.plist`);
}

export function launchdLogPath({ system, home }) {
  return system ? '/Library/Logs/Shomra/report.log' : path.posix.join(home, 'Library', 'Logs', 'Shomra', 'report.log');
}

export function launchdPlist({ node, entry, args, hours, logFile }) {
  const program = [node, entry, ...args].map((a) => `    <string>${xml(a)}</string>`).join('\n');
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${SCHEDULE_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
${program}
  </array>
  <key>StartInterval</key>
  <integer>${hours * 3600}</integer>
  <key>RunAtLoad</key>
  <true/>
  <key>ProcessType</key>
  <string>Background</string>
  <key>LowPriorityIO</key>
  <true/>
  <key>StandardOutPath</key>
  <string>${xml(logFile)}</string>
  <key>StandardErrorPath</key>
  <string>${xml(logFile)}</string>
</dict>
</plist>
`;
}

export function windowsQuote(arg) {
  const s = String(arg);
  if (s && !/[\s"]/.test(s)) return s;
  return `"${s.replace(/(\\*)"/g, '$1$1\\"').replace(/(\\+)$/, '$1$1')}"`;
}

export function windowsTaskXml({ node, entry, args, hours, system, userId }) {
  const principal = system
    ? '      <UserId>S-1-5-18</UserId>\n      <RunLevel>HighestAvailable</RunLevel>'
    : `${userId ? `      <UserId>${xml(userId)}</UserId>\n` : ''}      <LogonType>InteractiveToken</LogonType>\n      <RunLevel>LeastPrivilege</RunLevel>`;
  return `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Shomra endpoint AI inventory report</Description>
  </RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <StartBoundary>2026-01-01T00:05:00</StartBoundary>
      <Enabled>true</Enabled>
      <Repetition>
        <Interval>PT${hours}H</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
${principal}
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>true</RunOnlyIfNetworkAvailable>
    <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>${xml(node)}</Command>
      <Arguments>${xml([entry, ...args].map(windowsQuote).join(' '))}</Arguments>
    </Exec>
  </Actions>
</Task>
`;
}

export function schtasksCreateArgs(xmlFile) {
  return ['/Create', '/TN', TASK_NAME, '/XML', xmlFile, '/F'];
}

const systemdQuote = (s) => `"${String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/%/g, '%%').replace(/\$/g, '$$$$')}"`;

export function systemdUnitDir({ system, home }) {
  return system ? '/etc/systemd/system' : path.posix.join(home, '.config', 'systemd', 'user');
}

export function systemdService({ node, entry, args }) {
  return `[Unit]
Description=Shomra endpoint AI inventory report
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=${[node, entry, ...args].map(systemdQuote).join(' ')}
Nice=10
IOSchedulingClass=idle
`;
}

export function systemdTimer({ hours, system }) {
  return `[Unit]
Description=Run the Shomra endpoint report every ${hours}h

[Timer]
OnBootSec=5min
OnUnitActiveSec=${hours}h
RandomizedDelaySec=10min
Unit=${SYSTEMD_UNIT}.service

[Install]
WantedBy=${system ? 'timers.target' : 'default.target'}
`;
}

const shQuote = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`;

export function cronSchedule(hours) {
  if (hours < 24) return `17 */${hours} * * *`;
  if (hours % 24 === 0) return `17 3 */${hours / 24} * *`;
  throw new Error(`cron cannot express every ${hours}h - use a whole number of days above 23h, or install systemd`);
}

export function cronLine({ node, entry, args, hours }) {
  const cmd = [node, entry, ...args].map(shQuote).join(' ').replace(/%/g, '\\%');
  return `${cronSchedule(hours)} ${cmd} >/dev/null 2>&1 ${CRON_MARKER}`;
}

export function mergeCrontab(existing, line) {
  const kept = String(existing ?? '').split(/\r?\n/).filter((l) => l.trim() && !l.includes(CRON_MARKER));
  return [...kept, ...(line ? [line] : [])].join('\n') + '\n';
}
