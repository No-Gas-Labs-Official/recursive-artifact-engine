import assert from 'node:assert/strict';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { adjudicateModelClaim, validateReceipt, verifyArtifact } from '../src/verifier.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixture = resolve(here, 'fixtures/example.txt');
const fixedObservedAt = '2026-09-16T17:00:00.000Z';

test('trusting the model assertion is rejected before the digest is consulted', async () => {
  const receipt = await verifyArtifact(fixture, { observedAt: fixedObservedAt });
  receipt.observation.model_assertion_trusted = true;

  assert.deepEqual(validateReceipt(receipt), {
    valid: false,
    reason: 'model_assertion_laundered_as_evidence',
  });

  const adjudicated = adjudicateModelClaim('true because the model said so', receipt);
  assert.equal(adjudicated.status, 'PROPOSED');
  assert.equal(adjudicated.accepted_as_observed_state, false);
  assert.equal(adjudicated.circuit_breaker, 'OPEN');
  assert.equal(adjudicated.reason, 'model_assertion_laundered_as_evidence');
});

test('dropping the model-trust flag is the same launder', async () => {
  const receipt = await verifyArtifact(fixture, { observedAt: fixedObservedAt });
  delete receipt.observation.model_assertion_trusted;
  assert.equal(validateReceipt(receipt).reason, 'model_assertion_laundered_as_evidence');
});

test('an empty claim is not adjudicated into a pass', () => {
  assert.throws(() => adjudicateModelClaim('   ', undefined), /claim must be a non-empty string/);
});
