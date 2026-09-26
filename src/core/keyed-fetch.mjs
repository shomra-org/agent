const MAX_HOPS = 5;

export function redirectAllowed(from, to) {
  if (from.origin === to.origin) return true;
  return from.protocol === 'http:' && to.protocol === 'https:' && from.hostname === to.hostname
    && (to.port === '' || to.port === '443') && (from.port === '' || from.port === '80');
}

export async function keyedFetch(url, init = {}) {
  let current = new URL(String(url));
  let opts = { ...init, redirect: 'manual' };
  for (let hop = 0; ; hop += 1) {
    const res = await fetch(current, opts);
    const location = res.status >= 300 && res.status < 400 ? res.headers.get('location') : null;
    if (!location) return res;
    try {
      await res.body?.cancel();
    } catch {
    }
    const next = new URL(location, current);
    if (!redirectAllowed(current, next)) {
      throw new Error(`refused a redirect from ${current.origin} to ${next.origin} - the Shomra key is only sent to the backend it was configured for`);
    }
    if (hop >= MAX_HOPS) throw new Error(`too many redirects from ${current.origin}`);
    const method = String(opts.method ?? 'GET').toUpperCase();
    if (res.status === 303 || ((res.status === 301 || res.status === 302) && method === 'POST')) {
      const { body, ...rest } = opts;
      opts = { ...rest, method: 'GET' };
    }
    current = next;
  }
}
