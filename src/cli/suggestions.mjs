export function levenshtein(a, b) {
  if (!a.length) return b.length;
  if (!b.length) return a.length;

  let previousRow = Array.from({ length: b.length + 1 }, (_, index) => index);
  for (let i = 1; i <= a.length; i += 1) {
    const currentRow = [i];
    for (let j = 1; j <= b.length; j += 1) {
      const substitution = previousRow[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1);
      currentRow[j] = Math.min(previousRow[j] + 1, currentRow[j - 1] + 1, substitution);
    }
    previousRow = currentRow;
  }
  return previousRow[b.length];
}

export function didYouMean(input, candidates) {
  const needle = String(input).toLowerCase();
  let best = null;
  let bestDistance = Infinity;

  for (const candidate of candidates) {
    if (candidate.startsWith(needle) || needle.startsWith(candidate)) return candidate;
    const distance = levenshtein(needle, candidate);
    if (distance < bestDistance) {
      bestDistance = distance;
      best = candidate;
    }
  }

  const tolerance = Math.max(2, Math.floor(needle.length / 3));
  return bestDistance <= tolerance ? best : null;
}
