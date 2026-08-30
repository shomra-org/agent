
export const RUNGS = ['DEFEATED', 'INDISCRIMINATE', 'POROUS', 'ABSENT', 'UNEXERCISED', 'REFUSING', 'HOLDING'];
export const RUNG_RANK = Object.fromEntries(RUNGS.map((r, i) => [r, i]));

export const RUNG_LABEL = {
  DEFEATED: 'Defeated under test',
  INDISCRIMINATE: 'Refuses everything',
  POROUS: 'Traffic goes around it',
  ABSENT: 'No enforcement here',
  UNEXERCISED: 'Never met an attack',
  REFUSING: 'Refused an attack',
  HOLDING: 'Held under test',
};

const GAP_RUNGS = new Set(['DEFEATED', 'INDISCRIMINATE', 'POROUS', 'ABSENT']);
const BELIEF_GAPS = new Set(['DEFEATED', 'INDISCRIMINATE', 'POROUS']);
const POROUS_REACH = new Set(['PARTIAL', 'BYPASSING', 'UNSUPPORTED']);

export function isBeliefGap(rung) {
  return BELIEF_GAPS.has(rung);
}

export function deriveRung(axes) {
  const presence = axes?.presence;
  const reach = axes?.reach ?? null;
  const discrimination = axes?.discrimination;
  const prevention = axes?.prevention;
  const replayed = prevention === 'PREVENTED' && axes?.preventionBasis !== 'executed';

  if (prevention === 'BYPASSED') return 'DEFEATED';
  if (discrimination === 'INVERTED') return 'DEFEATED';
  if (discrimination === 'INDISCRIMINATE') return 'INDISCRIMINATE';
  if (reach && POROUS_REACH.has(reach.state)) return 'POROUS';
  if (discrimination === 'UNGUARDED') return 'ABSENT';
  if (presence === 'NOT_DEPLOYED') return 'ABSENT';
  if (prevention !== 'PREVENTED' && (discrimination === 'UNEXERCISED' || discrimination === 'UNKNOWN')) return 'UNEXERCISED';
  if (prevention === 'PREVENTED' && (replayed || discrimination !== 'DISCRIMINATING')) return 'REFUSING';
  if (prevention !== 'PREVENTED' && discrimination === 'DISCRIMINATING') return 'REFUSING';
  return 'HOLDING';
}

export function deriveUnmeasured(axes) {
  const out = [];
  const reach = axes?.reach ?? null;
  if (!reach || reach.state === 'UNOBSERVED') out.push('reach');
  if (axes?.discrimination === 'UNKNOWN' || axes?.discrimination === 'UNEXERCISED') out.push('discrimination');
  if (axes?.prevention === 'UNPROVEN' || axes?.prevention === 'NOT_ATTEMPTABLE') out.push('prevention');
  return out;
}

export function deriveBasis(axes, rung) {
  if (GAP_RUNGS.has(rung)) return 'conclusive';
  const replayed = axes?.prevention === 'PREVENTED' && axes?.preventionBasis !== 'executed';
  const floor =
    replayed ||
    deriveUnmeasured(axes).length > 0 ||
    !!axes?.truncated ||
    Number(axes?.silentSubjects ?? 0) > 0 ||
    axes?.reach?.state === 'ENFORCED_UNQUANTIFIED';
  return floor ? 'floor' : 'conclusive';
}

export function summarize(rows) {
  if (!rows.length) {
    return (
      'No control on this machine has been measured. That is not a clean result - it is the absence of any result, ' +
      'and it is the state every machine is in until something is fired at it.'
    );
  }
  const totals = Object.fromEntries(RUNGS.map((r) => [r, rows.filter((x) => x.rung === r).length]));
  const gaps = rows.filter((x) => isBeliefGap(x.rung)).length;
  const parts = [`${rows.length} control(s) on the ledger`];
  parts.push(
    gaps
      ? `${gaps} measured weaker than they would be assumed to be (${totals.DEFEATED} defeated, ${totals.INDISCRIMINATE} refusing everything, ${totals.POROUS} with traffic going around them)`
      : 'none measured weaker than assumed',
  );
  if (totals.ABSENT) parts.push(`${totals.ABSENT} path(s) with no enforcement on them`);
  parts.push(
    totals.HOLDING
      ? `${totals.HOLDING} held under a reproduced exploit with ordinary traffic still passing`
      : 'none has been shown to hold under a reproduced exploit',
  );
  if (totals.UNEXERCISED) parts.push(`${totals.UNEXERCISED} never met an attack (neither a pass nor a failure)`);
  return parts.join(' · ');
}

export function buildReport(subjects, version) {
  const controls = subjects.map((s) => {
    const rung = deriveRung(s.axes);
    return {
      id: s.id,
      label: s.label,
      plane: s.plane,
      chokepoint: s.chokepoint,
      mode: s.mode ?? 'ABSENT',
      rung,
      basis: deriveBasis(s.axes, rung),
      axes: {
        presence: s.axes.presence,
        reach: s.axes.reach ?? null,
        discrimination: s.axes.discrimination,
        prevention: s.axes.prevention,
        preventionBasis: s.axes.preventionBasis ?? null,
        truncated: false,
        silentSubjects: s.axes.silentSubjects ?? 0,
      },
      unmeasured: deriveUnmeasured(s.axes),
      statement: s.statement,
    };
  });

  const totals = Object.fromEntries(RUNGS.map((r) => [r, controls.filter((c) => c.rung === r).length]));
  return {
    format: 'controlledger/1',
    specVersion: '1.0',
    producer: { name: 'shomra-cli', version: String(version ?? '') },
    generatedAt: new Date().toISOString(),
    basis: controls.length && controls.every((c) => c.basis === 'conclusive') ? 'conclusive' : 'floor',
    controls,
    totals,
    beliefGaps: controls.filter((c) => isBeliefGap(c.rung)).length,
    unmeasured: controls.filter((c) => c.unmeasured.length > 0).length,
    statement: summarize(controls),
  };
}
