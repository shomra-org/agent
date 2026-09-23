const MAX_CELLS = 4_000_000;

function lcsOps(a, b) {
  if (a.length * b.length > MAX_CELLS) return [...a.map((l) => ['-', l]), ...b.map((l) => ['+', l])];
  const w = b.length + 1;
  const t = new Uint32Array((a.length + 1) * w);
  for (let i = a.length - 1; i >= 0; i--) {
    for (let j = b.length - 1; j >= 0; j--) {
      t[i * w + j] = a[i] === b[j] ? t[(i + 1) * w + j + 1] + 1 : Math.max(t[(i + 1) * w + j], t[i * w + j + 1]);
    }
  }
  const ops = [];
  let i = 0;
  let j = 0;
  while (i < a.length && j < b.length) {
    if (a[i] === b[j]) {
      ops.push([' ', a[i]]);
      i++;
      j++;
    } else if (t[(i + 1) * w + j] >= t[i * w + j + 1]) ops.push(['-', a[i++]]);
    else ops.push(['+', b[j++]]);
  }
  while (i < a.length) ops.push(['-', a[i++]]);
  while (j < b.length) ops.push(['+', b[j++]]);
  return ops;
}

function linesOf(text) {
  const out = String(text).split(/\r?\n/);
  if (out.length > 1 && out[out.length - 1] === '') out.pop();
  return out;
}

export function lineOps(before, after) {
  const A = linesOf(before);
  const B = linesOf(after);
  let pre = 0;
  while (pre < A.length && pre < B.length && A[pre] === B[pre]) pre++;
  let suf = 0;
  while (suf < A.length - pre && suf < B.length - pre && A[A.length - 1 - suf] === B[B.length - 1 - suf]) suf++;
  return [
    ...A.slice(0, pre).map((l) => [' ', l]),
    ...lcsOps(A.slice(pre, A.length - suf), B.slice(pre, B.length - suf)),
    ...A.slice(A.length - suf).map((l) => [' ', l]),
  ];
}

export function unifiedDiff(before, after, name = 'file', { context = 3 } = {}) {
  const ops = lineOps(before, after);
  const changed = ops.map((op, i) => (op[0] !== ' ' ? i : -1)).filter((i) => i >= 0);
  if (!changed.length) return '';
  const hunks = [];
  let cur = null;
  for (const i of changed) {
    const lo = Math.max(0, i - context);
    const hi = Math.min(ops.length - 1, i + context);
    if (cur && lo <= cur.hi + 1) cur.hi = hi;
    else hunks.push((cur = { lo, hi }));
  }
  const out = [`--- a/${name}`, `+++ b/${name}`];
  let aLine = 1;
  let bLine = 1;
  let at = 0;
  for (const h of hunks) {
    for (; at < h.lo; at++) {
      if (ops[at][0] !== '+') aLine++;
      if (ops[at][0] !== '-') bLine++;
    }
    const body = ops.slice(h.lo, h.hi + 1);
    const aCount = body.filter((o) => o[0] !== '+').length;
    const bCount = body.filter((o) => o[0] !== '-').length;
    out.push(`@@ -${aCount ? aLine : aLine - 1},${aCount} +${bCount ? bLine : bLine - 1},${bCount} @@`);
    for (const [op, line] of body) out.push(`${op}${line}`);
    for (; at <= h.hi; at++) {
      if (ops[at][0] !== '+') aLine++;
      if (ops[at][0] !== '-') bLine++;
    }
  }
  return out.join('\n');
}
