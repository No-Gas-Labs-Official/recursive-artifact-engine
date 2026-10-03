import { checkClaim, objectId } from './evidence.js';

const STATES = new Set(['VERIFIED','REFUTED','UNVERIFIABLE','UNSUPPORTED']);

export function adjudicateSatisfaction(contract, observations) {
  if (!contract || contract.schema !== 'ngl.pr-satisfaction.v1' || !Array.isArray(contract.requirements)) throw new Error('satisfaction_contract_invalid');
  const byId = new Map((observations || []).map(o => [o.observation_id, o]));
  const requirements = contract.requirements.map(requirement => {
    if (!requirement?.id || !Array.isArray(requirement.checks) || requirement.checks.length === 0) throw new Error('satisfaction_requirement_invalid');
    const checks = requirement.checks.map(spec => {
      const observation = byId.get(spec.observation_id);
      if (!observation) return { ...spec, status: 'UNVERIFIABLE', reason: 'observation_missing' };
      const result = checkClaim(spec.claim, observation);
      return { ...spec, status: result.status, result };
    });
    const statuses = checks.map(c => c.status);
    const status = statuses.includes('REFUTED') ? 'REFUTED'
      : statuses.includes('UNSUPPORTED') ? 'UNSUPPORTED'
      : statuses.every(s => s === 'VERIFIED') ? 'VERIFIED' : 'UNVERIFIABLE';
    return { id: requirement.id, status, checks };
  });
  const statuses = requirements.map(r => r.status);
  let status = statuses.includes('REFUTED') ? 'REFUTED'
    : statuses.includes('UNSUPPORTED') ? 'UNSUPPORTED'
    : statuses.every(s => s === 'VERIFIED') ? 'VERIFIED' : 'UNVERIFIABLE';

  const androidRuntime = contract.execution_class === 'ANDROID_RUNTIME'
    ? (contract.android_runtime ?? { required: true, status: 'UNVERIFIABLE' })
    : contract.android_runtime;

  if (contract.execution_class === 'ANDROID_RUNTIME' && androidRuntime?.status !== 'VERIFIED' && status === 'VERIFIED') {
    status = androidRuntime?.status === 'REFUTED' ? 'REFUTED'
      : androidRuntime?.status === 'UNSUPPORTED' ? 'UNSUPPORTED'
      : 'UNVERIFIABLE';
  }
  const payload = {
    schema: 'ngl.pr-satisfaction-manifest.v1',
    repository: contract.repository,
    pull_request: contract.pull_request,
    contract_id: objectId(contract),
    status,
    requirements,
    governance: contract.governance ?? { status: 'UNVERIFIABLE' },
    execution_class: contract.execution_class ?? 'SUPPORTING_INFRASTRUCTURE',
    android_runtime: androidRuntime,
    unresolved: [
      ...requirements.filter(r => r.status !== 'VERIFIED').map(r => r.id),
      ...(contract.execution_class === 'ANDROID_RUNTIME' && androidRuntime?.status !== 'VERIFIED' ? ['android-runtime-evidence'] : [])
    ]
  };
  return { ...payload, manifest_id: objectId(payload) };
}

export function assertSatisfactionState(value) {
  if (!STATES.has(value)) throw new Error('satisfaction_state_invalid');
  return value;
}
