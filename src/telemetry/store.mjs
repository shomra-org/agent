import fs from 'node:fs';
import path from 'node:path';

export const QUEUE_MAX_BYTES = 1_000_000;

export const SENDING_MAX_AGE_MS = 7 * 86_400_000;

export const LOCK_STALE_MS = 10 * 60_000;

const SENDING_RE = /^sending-(\d+)-(\d+)\.jsonl$/;

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return null;
  }
}

function writeAtomic(file, body) {
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, body, { mode: 0o600 });
  fs.renameSync(tmp, file);
}

export function makeTelemetryStore(dir) {
  const queue = path.join(dir, 'queue.jsonl');
  const lastVerdictFile = path.join(dir, 'last-verdict.json');
  const lastBatchFile = path.join(dir, 'last-batch.json');
  const flushStamp = path.join(dir, 'flush-at.json');
  const lockFile = path.join(dir, 'flush.lock');

  const ensure = () => fs.mkdirSync(dir, { recursive: true, mode: 0o700 });

  const size = (file) => {
    try {
      return fs.statSync(file).size;
    } catch {
      return 0;
    }
  };

  const sendingFiles = () => {
    try {
      return fs.readdirSync(dir).filter((f) => SENDING_RE.test(f)).sort();
    } catch {
      return [];
    }
  };

  return {
    dir,
    queue,

    append(record) {
      try {
        ensure();
        if (size(queue) > QUEUE_MAX_BYTES) return false;
        fs.appendFileSync(queue, `${JSON.stringify(record)}\n`, { mode: 0o600 });
        return true;
      } catch {
        return false;
      }
    },

    queueBytes() {
      return size(queue) + sendingFiles().reduce((n, f) => n + size(path.join(dir, f)), 0);
    },

    pending() {
      const out = [];
      for (const f of [...sendingFiles().map((s) => path.join(dir, s)), queue]) out.push(...this.read(f));
      return out;
    },

    read(file) {
      let text = '';
      try {
        text = fs.readFileSync(file, 'utf8');
      } catch {
        return [];
      }
      const out = [];
      for (const line of text.split('\n')) {
        if (!line.trim()) continue;
        try {
          out.push(JSON.parse(line));
        } catch {
          continue;
        }
      }
      return out;
    },

    claim(now = Date.now()) {
      try {
        ensure();
        if (size(queue) > 0) fs.renameSync(queue, path.join(dir, `sending-${now}-${process.pid}.jsonl`));
      } catch (e) {
        if (e?.code !== 'ENOENT') return [];
      }
      return sendingFiles().map((f) => path.join(dir, f));
    },

    done(file) {
      try {
        fs.rmSync(file, { force: true });
      } catch {
        return false;
      }
      return true;
    },

    prune(now = Date.now()) {
      let dropped = 0;
      for (const f of sendingFiles()) {
        const at = Number(SENDING_RE.exec(f)?.[1]);
        if (Number.isFinite(at) && now - at > SENDING_MAX_AGE_MS && this.done(path.join(dir, f))) dropped++;
      }
      return dropped;
    },

    discard() {
      for (const f of [...sendingFiles().map((s) => path.join(dir, s)), queue, lastVerdictFile]) this.done(f);
    },

    remember(ev) {
      try {
        ensure();
        writeAtomic(lastVerdictFile, JSON.stringify({ id: ev.id, at: ev.at, c: ev.c, t: ev.t, kind: ev.kind, d: ev.d, r: ev.r, sh: ev.sh }));
      } catch {
        return false;
      }
      return true;
    },

    lastVerdict() {
      return readJson(lastVerdictFile);
    },

    writeLastBatch(batch) {
      try {
        ensure();
        writeAtomic(lastBatchFile, JSON.stringify({ sentAt: new Date().toISOString(), ...batch }, null, 2));
      } catch {
        return false;
      }
      return true;
    },

    lastBatch() {
      return readJson(lastBatchFile);
    },

    lastFlushAttempt() {
      const at = readJson(flushStamp)?.at;
      return Number.isFinite(at) ? at : 0;
    },

    markFlushAttempt(now = Date.now()) {
      try {
        ensure();
        writeAtomic(flushStamp, JSON.stringify({ at: now }));
      } catch {
        return false;
      }
      return true;
    },

    lock(now = Date.now(), retried = false) {
      try {
        ensure();
        const fd = fs.openSync(lockFile, 'wx', 0o600);
        fs.writeSync(fd, String(now));
        fs.closeSync(fd);
        return true;
      } catch (e) {
        if (e?.code !== 'EEXIST' || retried) return false;
        let stale = true;
        try {
          stale = now - fs.statSync(lockFile).mtimeMs > LOCK_STALE_MS;
        } catch {
          stale = true;
        }
        if (!stale || !this.done(lockFile)) return false;
        return this.lock(now, true);
      }
    },

    unlock() {
      this.done(lockFile);
    },
  };
}
