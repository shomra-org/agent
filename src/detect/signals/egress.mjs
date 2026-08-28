export const SUSPICIOUS_EGRESS_HOSTS = [
  'webhook.site', 'requestbin', 'pipedream.net', 'ngrok.io', 'ngrok-free.app', 'ngrok.app',
  'trycloudflare.com', 'serveo.net', 'localhost.run', 'interact.sh', 'oastify.com', 'oast.pro',
  'oast.fun', 'burpcollaborator.net', 'canarytokens.com', 'beeceptor.com', 'requestcatcher.com',
  'c-net.org', 'pastebin.com', 'paste.ee', 'hastebin.com', 'dpaste.com', 'dpaste.org', 'ix.io',
  'sprunge.us', 'termbin.com', 'rentry.co', 'controlc.com', 'privatebin.net', 'ghostbin.com',
  'justpaste.it', 'transfer.sh', '0x0.st', 'file.io', 'gofile.io', 'anonfiles.com',
  'bashupload.com', 'tmpfiles.org', 'catbox.moe', 'litterbox.catbox.moe', 'temp.sh', 'oshi.at', 'x0.at',

  'webhook.cool', 'hookb.in', 'postb.in', 'webhookrelay.com', 'webhookinbox.com', 'webhook.win',
  'smee.io', 'mockbin.org', 'requestrepo.com', 'webhook-test.com', 'dnslog.cn', 'ceye.io',
  'tunnelto.dev', 'loca.lt', 'bore.pub', 'pinggy.io', 'telebit.cloud', 'expose.sh', 'lhr.life',
  'serveousercontent.com', 'paste.rs', 'bpa.st', 'vpaste.net', 'clbin.com', 'pastes.io',
  'nopaste.net', 'zerobin.net', 'pastecode.io', 'filebin.net', 'wormhole.app', 'uguu.se',
  'ufile.io', 'fileditch.com', 'keep.sh', 'envs.sh', 'send.vis.ee', 'pixeldrain.com', 'filetransfer.io',
];

const EGRESS_RE_CACHE = new Map();

function egressHostRe(host) {
  let re = EGRESS_RE_CACHE.get(host);
  if (!re) {
    re = new RegExp(`(^|[^a-z0-9-])${host.replace(/[.]/g, '\\.')}($|[^a-z0-9.-])`, 'i');
    EGRESS_RE_CACHE.set(host, re);
  }
  return re;
}

export function egressHost(text) {
  if (!text) return null;
  const low = text.toLowerCase();
  return SUSPICIOUS_EGRESS_HOSTS.find((h) => egressHostRe(h).test(low)) ?? null;
}

const PRIVATE_HOST_RE = /^(localhost|127\.|10\.|192\.168\.|169\.254\.|0\.0\.0\.0$|172\.(1[6-9]|2\d|3[01])\.)/i;

const RAW_IP_RE = /^\d{1,3}(\.\d{1,3}){3}$/;

export function assessUrl(raw) {
  const s = String(raw ?? '').trim();
  if (!s) return null;
  let u;
  try { u = new URL(s); } catch { return null; }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
  const host = u.hostname.toLowerCase();
  return {
    url: s,
    plaintext: u.protocol === 'http:',
    privateNetwork: PRIVATE_HOST_RE.test(host),
    metadataEndpoint: host === '169.254.169.254' || host === 'metadata.google.internal',
    suspiciousHost: SUSPICIOUS_EGRESS_HOSTS.find((h) => host === h || host.endsWith('.' + h)) ?? null,
    rawIp: RAW_IP_RE.test(host),
  };
}

export const LOCAL_URL_RE = /\bhttps?:\/\/(localhost|127\.\d+|0\.0\.0\.0|\[::1\]|192\.168\.|10\.\d+|172\.(1[6-9]|2\d|3[01])\.)/i;
