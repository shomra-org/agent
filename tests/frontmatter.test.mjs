import { test } from 'node:test';
import assert from 'node:assert/strict';
import { frontmatter } from '../src/detect/signals/artifacts.mjs';

test('a block-scalar description stays text, and the grant after it is still read', () => {
  const fm = frontmatter('---\nname: triage\ndescription: |\n  Use when:\n  - a ticket arrives\n  - a customer replies\nallowed-tools: Read, Bash\n---\nbody');
  assert.equal(typeof fm.description, 'string');
  assert.match(fm.description, /a customer replies/);
  assert.equal(fm['allowed-tools'], 'Read, Bash');
});

test('a flow list that wraps onto a second line keeps every tool', () => {
  assert.deepEqual(frontmatter('---\nname: x\ntools: [Read,\n  Bash]\n---\n').tools, ['Read', 'Bash']);
});

test('a block list of tools is still a list', () => {
  assert.deepEqual(frontmatter('---\nallowed-tools:\n  - Read\n  - Bash\n---\n')['allowed-tools'], ['Read', 'Bash']);
});
