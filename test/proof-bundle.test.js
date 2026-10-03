import test from 'node:test';
import assert from 'node:assert/strict';
import { makeEvidenceObject } from '../src/evidence-object.js';
import { adjudicateProofBundle } from '../src/proof-bundle.js';

const observed=makeEvidenceObject({kind:'OBSERVATION',subject:'exact-head:test',trust:'INDEPENDENTLY_OBSERVED',observer:'external',payload:{conclusion:'success'}});

test('complete required evidence verifies a proof bundle',()=>{
 const r=adjudicateProofBundle({subject:'transition:candidate',evidence:[observed],requirements:[{id:'exact-head',evidence_ids:[observed.evidence_id]}]});
 assert.equal(r.status,'VERIFIED');
 assert.equal(r.checks[0].status,'VERIFIED');
});

test('an assertion naming evidence cannot replace the evidence',()=>{
 const claim=makeEvidenceObject({kind:'CLAIM',subject:'exact-head:test',trust:'SELF_ASSERTED',payload:{evidence_id:observed.evidence_id}});
 const r=adjudicateProofBundle({subject:'transition:candidate',evidence:[claim],requirements:[{id:'exact-head',evidence_ids:[observed.evidence_id]}]});
 assert.equal(r.status,'UNVERIFIABLE');
 assert.deepEqual(r.checks[0].missing,[observed.evidence_id]);
});
