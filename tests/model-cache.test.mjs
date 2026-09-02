import { test } from 'node:test';
import assert from 'node:assert/strict';

import { MODEL_CACHE_MAX_ENTRIES, MODEL_CACHE_RETAIN_MS, pruneModelCache } from '../src/models/lookup.mjs';

const NOW = 1_800_000_000_000;

const entry = (ageMs) => ({ cachedAt: NOW - ageMs, data: { found: true } });

test('an unbounded cache is the bug: entries past the horizon are dropped', () => {
  const out = pruneModelCache(
    { fresh: entry(0), old: entry(MODEL_CACHE_RETAIN_MS + 1) },
    { now: NOW },
  );
  assert.deepEqual(Object.keys(out), ['fresh']);
});

test('the stale-fallback window is never shortened by pruning', () => {
  const ttl = 365 * 24 * 3600 * 1000;
  const out = pruneModelCache({ a: entry(MODEL_CACHE_RETAIN_MS + 1) }, { now: NOW, ttl });
  assert.deepEqual(Object.keys(out), ['a'], 'a configured TTL longer than the horizon must widen it, not be overridden');
});

test('the entry count is capped, keeping the most recently cached', () => {
  const cache = {};
  for (let i = 0; i < MODEL_CACHE_MAX_ENTRIES + 25; i += 1) cache[`m${i}`] = entry(i * 1000);
  const out = pruneModelCache(cache, { now: NOW });
  assert.equal(Object.keys(out).length, MODEL_CACHE_MAX_ENTRIES);
  assert.ok(out.m0, 'the newest entry survives');
  assert.ok(!out[`m${MODEL_CACHE_MAX_ENTRIES + 24}`], 'the oldest is evicted');
});

test('a malformed entry is dropped rather than kept forever', () => {
  const out = pruneModelCache({ bad: { data: {} }, worse: null, good: entry(0) }, { now: NOW });
  assert.deepEqual(Object.keys(out), ['good']);
});
