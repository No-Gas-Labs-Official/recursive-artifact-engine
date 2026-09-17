import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

import { adjudicateModelClaim, validateReceipt, verifyArtifact } from '../src/verifier.js';

const execFileAsync = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));
const fixture = resolve(here, 'fixtures/example.txt');
const fixedObservedAt = '2026-09-16T17:00:00.000Z';

test('verifyArtifact independently reads bytes and emits a self-integrity receipt', async () => {
  const receipt = await verifyArtifact(fixture, { observedAt: fixedObservedAt });

  assert.equal(receipt.artifact.name, 'example.txt');
  assert.equal(receipt.artifact.byte_length, 48);
  assert.match(receipt.artifact.sha256, /^[a-f0-9]{64}$/);
  assert.equal(receipt.observation.status, 'OBSERVED');
  assert.equal(receipt.observation.model_assertion_trusted, false);
  assert.deepEqual(validateReceipt(receipt), { valid: true, reason: null });
});

test('file: URL inputs are normalized correctly', async () => {
  const receipt = await verifyArtifact(new URL('./fixtures/example.txt', import.meta.url), {
    observedAt: fixedObservedAt
  });

  assert.equal(receipt.artifact.name, 'example.txt');
  assert.equal(validateReceipt(receipt).valid, true);
});

test('tampering with receipt-observed state is detected', async () => {
  const receipt = await verifyArtifact(fixture, { observedAt: fixedObservedAt });
  receipt.artifact.byte_length += 1;

  assert.deepEqual(validateReceipt(receipt), {
    valid: false,
    reason: 'receipt_integrity_failed'
  });
});

test('model claim without an independent receipt stays PROPOSED', () => {
  const result = adjudicateModelClaim('The artifact is correct.', undefined);

  assert.equal(result.status, 'PROPOSED');
  assert.equal(result.accepted_as_observed_state, false);
  assert.equal(result.circuit_breaker, 'OPEN');
  assert.equal(result.reason, 'receipt_missing');
});

test('a valid receipt backs file existence/integrity but does not prove claim semantics', async () => {
  const receipt = await verifyArtifact(fixture, { observedAt: fixedObservedAt });
  const result = adjudicateModelClaim('The artifact is factually correct.', receipt);

  assert.equal(result.status, 'EVIDENCE_BACKED');
  assert.equal(result.accepted_as_observed_state, false);
  assert.equal(result.circuit_breaker, 'CLOSED');
  assert.equal(result.reason, 'receipt_valid_but_claim_semantics_not_independently_verified');
});

test('CLI verify prints a parseable receipt', async () => {
  const { stdout } = await execFileAsync(process.execPath, [resolve(here, '../src/cli.js'), 'verify', fixture]);
  const receipt = JSON.parse(stdout);
  assert.equal(validateReceipt(receipt).valid, true);
});
