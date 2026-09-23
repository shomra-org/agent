export const LOOPBACK_OR_PRIVATE_HOST_RE =
  /^(localhost|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|0\.0\.0\.0|\[::1\]|::1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})$/i;

export const LOOPBACK_HOST_RE = /^(localhost|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[?::1\]?|host\.docker\.internal)$/i;

export const CLOUD_METADATA_HOSTS = new Set(['169.254.169.254', 'metadata.google.internal']);

export function targetsExternalNetwork(line) {
  const urls = line.match(/https?:\/\/[^\s'"`;|)&]+/gi);
  if (!urls?.length) return true;
  return urls.some((raw) => {
    let host;
    try {
      host = new URL(raw).hostname.toLowerCase();
    } catch {
      return true;
    }
    if (CLOUD_METADATA_HOSTS.has(host)) return true;
    return !LOOPBACK_OR_PRIVATE_HOST_RE.test(host);
  });
}

const HOST_LITERAL_RE = /\\?["']((?:\d{1,3}\.){3}\d{1,3}|localhost|\[?::1\]?|[a-z0-9-]+(?:\.[a-z0-9-]+)+)\\?["']/gi;

const SPAWNS_SHELL_RE = /\/bin\/(?:ba|z|da)?sh\b|\bpty\.spawn\b|\bsubprocess\b|\bos\.dup2\b|\bos\.system\b|\bchild_process\b|\bspawn\s*\(|\bexec[lv]?p?e?\s*\(|\bsystem\s*\(|\bpopen\b|\bproc_open\b|\bshell_exec\b|\bcmd\.exe\b/i;

export function socketStaysOnLoopback(line) {
  const hosts = [...String(line).matchAll(HOST_LITERAL_RE)].map((m) => m[1].toLowerCase());
  if (!hosts.length) return false;
  if (SPAWNS_SHELL_RE.test(line)) return false;
  return hosts.every((h) => LOOPBACK_HOST_RE.test(h));
}
