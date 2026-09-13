
export { ALL_SECRET_PATTERNS as SECRET_PATTERNS } from './secret-scanner.mjs';

export const PII_PATTERNS = [
  { name: 'Email address', re: /[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}/ },
  { name: 'US SSN', re: /\b\d{3}-\d{2}-\d{4}\b/ },
  { name: 'Credit card number', re: /\b(?:\d[ -]?){13,16}\b/ },
  { name: 'Phone number', re: /\b(?:\+?1[ .-]?)?\(?\d{3}\)?[ .-]?\d{3}[ .-]?\d{4}\b/ },
  { name: 'IPv4 address', re: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/ },
];

export const RESERVED_IPV4 = /^(0\.|255\.255\.255\.255|127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|8\.8\.(8\.8|4\.4)|1\.1\.1\.1|1\.0\.0\.1|224\.)/;

export const VERSION_CONTEXT = /\b(v|ver|version|release|rev|build|semver|tag)\.?\s*$/i;

export function luhnValid(value) {
  const digits = String(value).replace(/[^\d]/g, '');
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0, alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = parseInt(digits[i], 10);
    if (alt) { d *= 2; if (d > 9) d -= 9; }
    sum += d;
    alt = !alt;
  }
  return sum % 10 === 0;
}

export function isPlaceholderSecret(v) {
  const s = String(v);
  const low = s.toLowerCase();
  if (/(example|sample|placeholder|dummy|redacted|changeme|test[_-]?(key|token|secret)|your[-_]?(key|token|secret|api))/.test(low)) return true;
  if (/(x{6,}|\.{3,}|<[^>]{2,}>|\*{4,}|•{3,})/.test(low)) return true;
  const tail = s.replace(/^\w{1,10}[-_]/, '');
  if (/^(.)\1{7,}/.test(tail)) return true;
  if (/^(0123|1234|abcd|abcdef|deadbeef)/i.test(tail)) return true;
  return false;
}
