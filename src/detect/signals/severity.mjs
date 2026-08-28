export const SEV_RANK = { INFO: 1, LOW: 2, MEDIUM: 3, HIGH: 4, CRITICAL: 5 };

export function grade(findings) {
  const WEIGHT = { INFO: 2, LOW: 8, MEDIUM: 20, HIGH: 40, CRITICAL: 70 };
  let worstRank = 0;
  for (const f of findings) if (SEV_RANK[f.severity] > worstRank) worstRank = SEV_RANK[f.severity];
  const verdict = worstRank >= SEV_RANK.CRITICAL ? 'BLOCK' : worstRank >= SEV_RANK.HIGH ? 'FLAG' : 'ALLOW';
  const riskScore = Math.min(100, findings.reduce((s, f) => s + (WEIGHT[f.severity] ?? 0), 0));
  return { verdict, riskScore };
}
