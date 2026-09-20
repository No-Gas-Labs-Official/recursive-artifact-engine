import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { verifyClaims, digest, observeBytes, checkClaim } from '../../src/evidence.js';
import { validateReceipt, RECEIPT_SCHEMA } from '../../src/verifier.js';

test('a fabricated self-hashed incomplete receipt is rejected', () => {
  const r = { schema: RECEIPT_SCHEMA, receipt_version: 1, artifact: { sha256: '0'.repeat(64) },
    observation: { status: 'OBSERVED', model_assertion_trusted: false } };
  r.receipt_sha256 = createHash('sha256').update(JSON.stringify(r)).digest('hex');
  assert.equal(validateReceipt(r).reason, 'receipt_structure_invalid');
});

test('structured predicates reread bytes and cannot be backed by a supplied observation', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'rae-claims-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, 'artifact.json');
  await writeFile(path, '{"a/b":{"~value":7},"ok":true}');
  const claims = [{ kind: 'json.pointer', pointer: '/a~1b/~0value', equals: 7 },
    { kind: 'json.pointer', pointer: '/ok', equals: false },
    { kind: 'json.pointer', pointer: '/missing', equals: null },
    { kind: 'is-factually-correct', equals: true },
    { kind: 'json.pointer', pointer: '/__proto__', equals: {} }];
  const first = await verifyClaims(path, 'json', claims);
  assert.deepEqual(first.results.map(r => r.status), ['VERIFIED','REFUTED','UNVERIFIABLE','UNSUPPORTED','UNVERIFIABLE']);
  await writeFile(path, '{"a/b":{"~value":8}}');
  const second = await verifyClaims(path, 'json', claims);
  assert.equal(second.results[0].status, 'REFUTED');
  assert.notEqual(second.observation.observation_id, first.observation.observation_id);
  await rm(path);
  await assert.rejects(verifyClaims(path, 'json', claims));
});

test('byte identity is precise; malformed APK fails closed', async () => {
  const bytes = Buffer.from('abc');
  const observation = await observeBytes(bytes);
  assert.equal(digest(bytes), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(checkClaim({kind:'artifact.byte_length',equals:3}, observation).status, 'VERIFIED');
  assert.equal(checkClaim({kind:'apk.class',name:'Fake',equals:true}, observation).status, 'UNVERIFIABLE');
  await assert.rejects(observeBytes(bytes, 'apk'), /extraction_failed/);
});
