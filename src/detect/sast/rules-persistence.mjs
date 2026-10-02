import { COIN_MINER_RE } from '../signals/shell.mjs';

const SHELL_RC_RE = /\.(?:bashrc|zshrc|bash_profile|zprofile|zshenv|bash_login)\b/;
const AUTOSTART_PATH_RE =
  /\bStart Menu['"\\/,\s]{1,8}Programs['"\\/,\s]{1,8}Startup\b|shell:startup|CurrentVersion\\{1,2}Run(?:Once)?\b|\/etc\/systemd\/system\b|\.config\/systemd\/user|['"]systemd['"]\s{0,3},\s{0,3}['"]user['"]|Library\/Launch(?:Agents|Daemons)|['"]Launch(?:Agents|Daemons)['"]|\/etc\/cron\.(?:d|hourly|daily|weekly)\b|\/var\/spool\/cron\b|\.config\/autostart\b|['"]autostart['"]|\.git\/hooks\b|\/etc\/rc\.local\b|\/etc\/profile\.d\b/;
const AUTOSTART_REGISTER_RE =
  /\bwinreg\.SetValueEx\b|\bschtasks\b[^\n]{0,80}\/create\b|\bsystemctl\b[^\n]{0,40}\benable\b|\blaunchctl\s{1,3}(?:load|bootstrap)\b|\bCronTab\s{0,3}\(\s{0,3}user|\bcrontab['"]?\s{0,3},\s{0,3}['"]-['"]|\|\s{0,3}crontab\s{1,3}-/;
const CALL_CONTEXT_RE = /\b(?:subprocess|os\.system|os\.popen|Popen|check_output|check_call|execSync|execFileSync|spawnSync|spawn|exec|execFile|run|call|system|shell)\s{0,3}\(|\bwinreg\.|\bCronTab\s{0,3}\(/;
const REGEX_SOURCE_RE = /\\[sdwbSDWB]|\(\?:/;
const FILE_OPEN_RE = /\bopen\s{0,3}\(|\.open\s{0,3}\(|appendFileSync|appendFile\s{0,3}\(|writeFileSync|writeFile\s{0,3}\(|createWriteStream|write_text\s{0,3}\(|write_bytes\s{0,3}\(|copyfile|shutil\.copy|copyFileSync|\bsymlink|plistlib\.dump/;
const WRITE_INTENT_RE = /['"](?:a|a\+|ab|w|w\+|wb)['"]|mode\s{0,2}=\s{0,2}['"][aw]|appendFile|writeFile|createWriteStream|write_text|write_bytes|copyfile|shutil\.copy|copyFileSync|symlink|plistlib\.dump/;
const RC_COMMAND_RE =
  /(?:\.write\s{0,3}\(|appendFile(?:Sync)?\s{0,3}\(|writeFile(?:Sync)?\s{0,3}\(|write_text\s{0,3}\()[^\n]{0,240}?(?:\b(?:python3?|node|bash|sh|zsh|nohup|curl|wget|sudo|shutdown|reboot|osascript|powershell|pwsh)\b|\.(?:py|sh|js)\b[^\n]{0,30}&|&\s{0,3}(?:\\n|['"`]))/;
const ASSIGN_RE = /^\s{0,40}(?:(?:const|let|var|export)\s{1,3})?([A-Za-z_$][\w$]{0,60})\s{0,3}(?::[^=\n]{0,40})?=(?![=>])(.*)$/;
const RC_NEAR_LINES = 6;

const liveCache = new WeakMap();
const writeCache = new WeakMap();

function liveLines(ctx) {
  if (!ctx.lines) return [];
  const cached = liveCache.get(ctx.lines);
  if (cached) return cached;
  const live = ctx.lines.map((l) => (/^\s*(?:#|\/\/)/.test(l) ? '' : l));
  liveCache.set(ctx.lines, live);
  return live;
}

function writesToCached(lines, target) {
  const byTarget = writeCache.get(lines) ?? new Map();
  writeCache.set(lines, byTarget);
  if (!byTarget.has(target)) byTarget.set(target, writesTo(lines, target));
  return byTarget.get(target);
}

function mentions(text, name) {
  for (let at = text.indexOf(name); at >= 0; at = text.indexOf(name, at + 1)) {
    const before = text[at - 1] ?? ' ';
    const after = text[at + name.length] ?? ' ';
    if (!/[\w$]/.test(before) && !/[\w$]/.test(after)) return true;
  }
  return false;
}

function writesTo(lines, target) {
  const names = new Set();
  for (const l of lines) {
    if (!target.test(l)) continue;
    if (FILE_OPEN_RE.test(l) && WRITE_INTENT_RE.test(l)) return true;
    const m = ASSIGN_RE.exec(l);
    if (m) names.add(m[1]);
  }
  for (let grew = names.size > 0; grew && names.size < 40; ) {
    grew = false;
    for (const l of lines) {
      const m = ASSIGN_RE.exec(l);
      if (!m || names.has(m[1]) || ![...names].some((n) => mentions(m[2], n))) continue;
      names.add(m[1]);
      grew = true;
    }
  }
  return lines.some((l) => FILE_OPEN_RE.test(l) && WRITE_INTENT_RE.test(l) && [...names].some((n) => mentions(l, n)));
}

function rcCommandAt(lines, idx) {
  if (!RC_COMMAND_RE.test(lines[idx] ?? '') || REGEX_SOURCE_RE.test(lines[idx] ?? '')) return false;
  for (let i = Math.max(0, idx - RC_NEAR_LINES); i <= idx; i++) if (SHELL_RC_RE.test(lines[i])) return true;
  return writesToCached(lines, SHELL_RC_RE);
}

function matchLine(m, unit, ctx) {
  return (ctx.unitStart ?? 1) - 1 + (unit.slice(0, m.index).match(/\n/g)?.length ?? 0);
}

const reported = new WeakMap();

function oncePerFile(ctx, id) {
  if (!ctx.lines) return true;
  const ids = reported.get(ctx.lines) ?? new Set();
  reported.set(ctx.lines, ids);
  if (ids.has(id)) return false;
  ids.add(id);
  return true;
}

export function startupPersistence(lang) {
  const autostart = `${lang}.autostart_install`;
  const rcCommand = `${lang}.shell_rc_command`;
  const rcWrite = `${lang}.shell_rc_write`;
  return [
    {
      id: autostart,
      title: 'Installs itself to start at every login or boot',
      severity: 'HIGH',
      category: 'persistence',
      confidence: 0.8,
      re: new RegExp(`${AUTOSTART_PATH_RE.source}|${AUTOSTART_REGISTER_RE.source}`),
      source: 'bundled code',
      suppress: (m, unit, ctx) => {
        const lines = liveLines(ctx);
        const line = lines[matchLine(m, unit, ctx)] ?? '';
        if (REGEX_SOURCE_RE.test(line)) return true;
        const qualifies = AUTOSTART_REGISTER_RE.test(m[0]) ? CALL_CONTEXT_RE.test(line) : writesToCached(lines, AUTOSTART_PATH_RE);
        return !qualifies || !oncePerFile(ctx, autostart);
      },
      message:
        'Registers code to start on its own - a systemd or launchd service, a cron job, a Windows Run key or Startup folder entry, a desktop autostart entry or a git hook. It keeps running after the agent session that installed it has ended, so it outlives the review that approved it. Service installers do this on purpose; a script bundled with an agent skill or tool rarely needs to.',
      remediation:
        'Remove the registration, or ask the person before installing anything that starts on its own. On machines that ran it, look for the unit, job or entry it created and remove it.',
    },
    {
      id: rcCommand,
      title: 'Adds a command to a shell start-up file',
      severity: 'HIGH',
      category: 'persistence',
      confidence: 0.8,
      re: RC_COMMAND_RE,
      source: 'bundled code',
      suppress: (m, unit, ctx) => !rcCommandAt(liveLines(ctx), matchLine(m, unit, ctx)) || !oncePerFile(ctx, rcCommand),
      message:
        'Writes a command into .bashrc, .zshrc or another shell start-up file, so it runs in every new terminal the person opens - long after the agent session is over. The Nx "s1ngularity" packages (August 2025) used exactly this to append "sudo shutdown -h 0" to every shell start-up file they found.',
      remediation:
        'Remove the write. On machines that ran it, check .bashrc, .zshrc, .profile and .zshenv for lines it added.',
    },
    {
      id: rcWrite,
      title: 'Writes to a shell start-up file',
      severity: 'MEDIUM',
      category: 'persistence',
      confidence: 0.6,
      re: SHELL_RC_RE,
      source: 'bundled code',
      suppress: (_m, _unit, ctx) => {
        const lines = liveLines(ctx);
        if (!writesToCached(lines, SHELL_RC_RE) || lines.some((_l, i) => rcCommandAt(lines, i))) return true;
        return !oncePerFile(ctx, rcWrite);
      },
      message:
        'Writes to .bashrc, .zshrc or another shell start-up file. Saving a setting there is common, but it changes every shell the person opens, and whatever is written there runs with their credentials.',
      remediation: 'Ask before editing shell start-up files, and prefer a setting the tool reads itself or a project-local .env file.',
    },
  ];
}

export function coinMiner(lang) {
  return {
    id: `${lang}.coin_miner`,
    title: 'Runs a cryptocurrency miner or points one at a mining pool',
    severity: 'HIGH',
    category: 'resource-abuse',
    confidence: 0.85,
    re: COIN_MINER_RE,
    source: 'bundled code',
    suppress: (m, unit, ctx) => REGEX_SOURCE_RE.test(liveLines(ctx)[matchLine(m, unit, ctx)] ?? '') || !oncePerFile(ctx, `${lang}.coin_miner`),
    message:
      'Starts a coin miner, downloads one, or writes a mining pool or wallet into its configuration. Mining on a developer machine or a CI runner spends its CPU and cloud bill for someone else - the payload the December 2024 ultralytics compromise shipped.',
    remediation:
      'Remove the miner and its pool configuration. On machines that ran it, look for a miner process, a job that restarts it and the files it dropped.',
  };
}
