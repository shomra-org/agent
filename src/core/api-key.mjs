export function keyScope(key) {
  if (!key) return null;
  if (/^(shm|dgx)_gw_/.test(key)) return 'gateway';
  if (/^(shm|dgx)_ci_/.test(key)) return 'CI';
  return 'agent';
}
