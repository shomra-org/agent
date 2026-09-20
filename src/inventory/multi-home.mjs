function withOsUser(item, run) {
  if (run.invoking || !run.user) return item;
  const metadata = item.metadata && typeof item.metadata === 'object' ? item.metadata : {};
  return { ...item, metadata: { ...metadata, osUser: run.user } };
}

export function mergeHomeAssets(runs) {
  const seen = new Set();
  const owner = new Map();
  const out = [];
  for (const run of runs) {
    for (const a of run.assets ?? []) {
      const key = `${a.type}::${a.identifier || a.name}::${run.home}`;
      if (seen.has(key)) continue;
      seen.add(key);
      let asset = withOsUser(a, run);
      if (a.identifier) {
        const idKey = `${a.type}::${a.identifier}`;
        const first = owner.get(idKey);
        if (first === undefined) owner.set(idKey, run.home);
        else if (first !== run.home) asset = { ...asset, identifier: `${a.identifier}@${run.user || run.home}` };
      }
      out.push(asset);
    }
  }
  return out;
}

export function mergeHomeArtifacts(runs) {
  const artifacts = [];
  const capped = [];
  const available = new Map();
  for (const run of runs) {
    for (const a of run.artifacts ?? []) artifacts.push(withOsUser(a, run));
    for (const c of run.capped ?? []) capped.push(run.invoking || !run.user ? c : { ...c, osUser: run.user });
    for (const m of run.available ?? []) {
      const prev = available.get(m.marketplace);
      available.set(m.marketplace, { ...m, count: (prev?.count ?? 0) + (m.count ?? 0) });
    }
  }
  return { artifacts, capped, available: [...available.values()].sort((a, b) => b.count - a.count) };
}
