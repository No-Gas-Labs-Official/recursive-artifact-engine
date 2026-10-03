import test from 'node:test';
import assert from 'node:assert/strict';
import { adjudicateSatisfaction } from '../src/satisfaction.js';

const claim = (observation_id, pointer, equals) => ({
  observation_id,
  claim: { kind: 'json.pointer', pointer, equals }
});

test('claim-specific execution can satisfy a requirement while generic green CI cannot', () => {
  const contract = {
    schema: 'ngl.pr-satisfaction.v1',
    repository: 'No-Gas-Labs-Official/no-gas-labs-command-center',
    pull_request: 27,
    requirements: [{
      id: 'media-artifact-produced',
      checks: [claim('pr27', '/claim_specific_execution', true)]
    }]
  };
  const pr27 = adjudicateSatisfaction(contract, [{
    observation_id: 'pr27',
    extractor: 'rae-json-v1',
    artifact: { sha256: 'fixture-pr27', byte_length: 0 },
    extraction: { claim_specific_execution: true, generic_ci_green: true }
  }]);
  assert.equal(pr27.status, 'VERIFIED');

  const pr28Contract = {
    ...contract,
    pull_request: 28,
    requirements: [{
      id: 'contact-tests-executed',
      checks: [claim('pr28', '/claim_specific_execution', true)]
    }]
  };
  const pr28 = adjudicateSatisfaction(pr28Contract, [{
    observation_id: 'pr28',
    extractor: 'rae-json-v1',
    artifact: { sha256: 'fixture-pr28', byte_length: 0 },
    extraction: { claim_specific_execution: false, generic_ci_green: true }
  }]);
  assert.equal(pr28.status, 'REFUTED');
  assert.deepEqual(pr28.unresolved, ['contact-tests-executed']);
});
