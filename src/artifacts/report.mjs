import path from 'node:path';
import { bold, cyan, dim, gray, yellow } from '../core/terminal.mjs';
import { rollupArtifacts } from '../inventory/agent-artifacts.mjs';

export function printAssets(assets) {
  const byType = {};
  for (const a of assets) byType[a.type] = (byType[a.type] ?? 0) + 1;
  console.log(bold('\n  Discovered AI assets'));
  console.log(
    '  ' +
      Object.entries(byType)
        .map(([t, n]) => `${cyan(n)} ${dim(t.replace('_', ' ').toLowerCase())}`)
        .join(dim('  ·  ')),
  );
  for (const a of assets) {
    console.log(`  ${gray('•')} ${bold(a.name)} ${dim(a.type)} ${a.vendor ? gray('(' + a.vendor + ')') : ''}`);
    if (a.identifier && a.identifier !== a.name) console.log(`      ${dim(a.identifier)}`);
  }
}

export function printArtifacts(artifacts, capped = [], available = []) {
  if (!artifacts.length && !capped.length && !available.length) return;
  const by = rollupArtifacts(artifacts);
  console.log(bold('\n  Installed agent artifacts'));
  console.log(
    '  ' +
      (Object.keys(by).length
        ? Object.entries(by)
            .map(([k, n]) => `${cyan(n)} ${dim(k + (n === 1 ? '' : 's'))}`)
            .join(dim('  ·  '))
        : dim('none found')),
  );
  for (const a of artifacts) {
    const scope = a.scope === 'user' ? yellow('user') : dim('project');
    console.log(`  ${gray('•')} ${bold(a.name)} ${dim(a.kind)} ${scope} ${a.vendor ? gray('(' + a.vendor + ')') : ''}`);
    console.log(`      ${dim(a.path)}`);
    if (a.files?.length) console.log(`      ${dim(a.files.length + ' bundled file(s)')}`);
  }
  if (available.length) {
    const total = available.reduce((n, a) => n + a.count, 0);

    console.log(
      dim(`\n  ${total} more available in ${available.length} checked-out catalogue(s), none enabled:`),
    );
    for (const a of available) console.log(`      ${dim(a.marketplace)} ${gray(a.count)}`);
  }
  if (capped.length) {
    console.log(dim(`\n  Sweep capped (${capped.length}) - this list is a floor, not a total.`));
  }
}
