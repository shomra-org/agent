import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';

const CHILD_STDIO = ['pipe', 'pipe', 'inherit'];
const UNQUOTABLE_FOR_CMD = /[%!]/;
const CMD_WRAPPER = /\.(cmd|bat)$/i;

function quoteForCmd(argument) {
  return `"${String(argument).replace(/"/g, '""')}"`;
}

function resolveWindowsExecutable(command) {
  if (command.includes('\\') || command.includes('/')) return fs.existsSync(command) ? command : null;
  const extensions = (process.env.PATHEXT || '.COM;.EXE;.BAT;.CMD').split(';').filter(Boolean);
  for (const directory of (process.env.PATH || '').split(path.delimiter).filter(Boolean)) {
    for (const extension of ['', ...extensions]) {
      const candidate = path.join(directory, command + extension);
      try {
        if (fs.statSync(candidate).isFile()) return candidate;
      } catch {
        continue;
      }
    }
  }
  return null;
}

function spawnThroughCmd(executable, args) {
  const hostile = [executable, ...args].find((argument) => UNQUOTABLE_FOR_CMD.test(String(argument)));
  if (hostile) {
    throw new Error(
      `the launch line contains a character that cannot be safely quoted for cmd.exe (${hostile}). `
      + 'Point the server at its executable directly instead of a .cmd wrapper.',
    );
  }
  const shell = process.env.ComSpec || 'cmd.exe';
  const line = [executable, ...args].map(quoteForCmd).join(' ');
  return spawn(shell, ['/d', '/s', '/c', `"${line}"`], { stdio: CHILD_STDIO, windowsVerbatimArguments: true });
}

export function spawnGuardedServer(command, args) {
  if (process.platform !== 'win32') return spawn(command, args, { stdio: CHILD_STDIO });

  const executable = resolveWindowsExecutable(command);
  if (!executable || !CMD_WRAPPER.test(executable)) {
    return spawn(executable || command, args, { stdio: CHILD_STDIO });
  }
  return spawnThroughCmd(executable, args);
}
