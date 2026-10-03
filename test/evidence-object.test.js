import test from 'node:test';
import assert from 'node:assert/strict';
import { makeEvidenceObject, contradict, authoritative } from '../src/evidence-object.js';

test('evidence identity is stable and content-derived', () => {
  const input = { kind:'OBSERVATION', subject:'apk:relay', trust:'INDEPENDENTLY_OBSERVED', observer:'apk-adapter', payload:{sha256:'abc'} };
  assert.equal(makeEvidenceObject(input).evidence_id, makeEvidenceObject(input).evidence_id);
});

test('self assertion is preserved but is not authoritative observation', () => {
  const claim = makeEvidenceObject({ kind:'CLAIM', subject:'runtime:android', trust:'SELF_ASSERTED', payload:{running:true} });
  assert.equal(authoritative(claim), false);
});

test('contradictions are first-class and retain both parents', () => {
  const a = makeEvidenceObject({ kind:'OBSERVATION', subject:'ci:test', trust:'INDEPENDENTLY_OBSERVED', payload:{green:true} });
  const b = makeEvidenceObject({ kind:'OBSERVATION', subject:'ci:test', trust:'INDEPENDENTLY_OBSERVED', payload:{green:false} });
  const c = contradict(a,b,'independent observations disagree');
  assert.equal(c.kind,'CONTRADICTION');
  assert.deepEqual(c.parents,[a.evidence_id,b.evidence_id]);
});
