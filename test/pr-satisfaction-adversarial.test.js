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


test('green repository evidence cannot satisfy an Android runtime without Android evidence', () => {
  const contract = {
    schema: 'ngl.pr-satisfaction.v1',
    repository: 'No-Gas-Labs-Official/ngl-relay',
    pull_request: 1,
    execution_class: 'ANDROID_RUNTIME',
    requirements: [{
      id: 'repository-ci',
      checks: [claim('ci', '/green', true)]
    }]
  };
  const result = adjudicateSatisfaction(contract, [{
    observation_id: 'ci',
    extractor: 'rae-json-v1',
    artifact: { sha256: 'fixture-ci', byte_length: 0 },
    extraction: { green: true }
  }]);
  assert.equal(result.requirements[0].status, 'VERIFIED');
  assert.equal(result.status, 'UNVERIFIABLE');
  assert.deepEqual(result.unresolved, ['android-runtime-evidence']);
});

test('verified Android evidence permits otherwise verified Android runtime satisfaction', () => {
  const contract = {
    schema: 'ngl.pr-satisfaction.v1',
    repository: 'No-Gas-Labs-Official/ngl-relay',
    pull_request: 1,
    execution_class: 'ANDROID_RUNTIME',
    android_runtime: { required: true, status: 'VERIFIED', artifact_observation_id: 'apk', runtime_observation_id: 'runtime' },
    requirements: [{
      id: 'repository-ci',
      checks: [claim('ci', '/green', true)]
    }]
  };
  const result = adjudicateSatisfaction(contract, [{
    observation_id: 'ci',
    extractor: 'rae-json-v1',
    artifact: { sha256: 'fixture-ci', byte_length: 0 },
    extraction: { green: true }
  }]);
  assert.equal(result.status, 'VERIFIED');
  assert.deepEqual(result.unresolved, []);
});
