export function containsAny(haystack, needles) {
  const h = String(haystack ?? '').toLowerCase();
  for (const n of needles) if (h.includes(n.toLowerCase())) return n;
  return null;
}

const WORD_RE_CACHE = new Map();

function leadingBoundaryRe(needle) {
  let re = WORD_RE_CACHE.get(needle);
  if (!re) {
    const esc = needle.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    re = new RegExp(/^\w/.test(needle) ? `(?<!\\w)${esc}` : esc, 'i');
    WORD_RE_CACHE.set(needle, re);
  }
  return re;
}

export function containsWord(haystack, needles) {
  const h = String(haystack ?? '');
  for (const n of needles) if (leadingBoundaryRe(n).test(h)) return n;
  return null;
}

const MARKER_RE_CACHE = new Map();

export function markerRe(marker) {
  let re = MARKER_RE_CACHE.get(marker);
  if (!re) {
    re = new RegExp(`(?<!\\w)${marker.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?!\\w)`, 'gi');
    MARKER_RE_CACHE.set(marker, re);
  }
  re.lastIndex = 0;
  return re;
}
