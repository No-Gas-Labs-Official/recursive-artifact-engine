import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { observeBytes, checkClaim } from '../src/evidence.js';

const fixtureUrl = new URL('../experiments/meaningful-plugin-theater/receipts/github-pr47-observation.json', import.meta.url);
const claimsUrl = new URL('../experiments/meaningful-plugin-theater/receipts/github-pr47-claims.json', import.meta.url);

test('external GitHub observation preserves success and governance rejection without laundering', async () => {
  const bytes = await readFile(fixtureUrl);
  const observation = await observeBytes(bytes, 'json');
  const claims = JSON.parse(await readFile(claimsUrl, 'utf8'));
  const results = claims.map(claim => checkClaim(claim, observation));

  assert.equal(results.length, 4);
  assert.ok(results.every(result => result.status === 'VERIFIED'));
  assert.equal(observation.extraction.workflow_runs[0].conclusion, 'success');
  assert.equal(observation.extraction.workflow_runs[1].conclusion, 'success');
  assert.equal(observation.extraction.merge_attempt.result, 'rejected');
  assert.match(observation.extraction.merge_attempt.message, /required status checks are expected/);
});
