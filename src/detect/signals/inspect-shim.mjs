import { localScan } from './scan.mjs';


export function inspectText(text, { categories = ['injection'] } = {}) {
  const { findings } = localScan(String(text ?? ''), { categories });
  return { matches: findings.map((f) => ({ label: f.label, severity: f.severity, category: f.category, sample: f.sample ?? '' })) };
}
