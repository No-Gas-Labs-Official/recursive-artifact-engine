import { objectId } from './evidence.js';

const TERMINAL = new Set(['AUTHORIZED','DENIED','UNVERIFIABLE']);

export function authorizeAction({ action, requirements, evidence = [], authority }) {
  if (!action || typeof action !== 'object' || Array.isArray(action)) throw new Error('action_invalid');
  if (!Array.isArray(requirements) || requirements.length === 0) throw new Error('requirements_invalid');
  if (!authority || authority.kind !== 'AUTHORITY') throw new Error('authority_missing');

  const evidenceIds = new Set(evidence.map(x => x?.evidence_id).filter(Boolean));
  const evaluated = requirements.map(r => {
    if (!r?.id || !Array.isArray(r.evidence_ids) || r.evidence_ids.length === 0) throw new Error('requirement_invalid');
    const missing = r.evidence_ids.filter(id => !evidenceIds.has(id));
    return { id: r.id, status: missing.length ? 'UNVERIFIABLE' : 'VERIFIED', missing };
  });

  const authorityCovers = Array.isArray(authority.payload?.allows)
    && authority.payload.allows.includes(action.kind);
  const status = !authorityCovers ? 'DENIED'
    : evaluated.every(r => r.status === 'VERIFIED') ? 'AUTHORIZED'
    : 'UNVERIFIABLE';

  const core = {
    schema: 'ngl.proof-carrying-action.v1',
    action,
    action_id: objectId(action),
    authority_id: authority.evidence_id ?? objectId(authority),
    requirements: evaluated,
    evidence_ids: [...evidenceIds].sort(),
    status
  };
  return { ...core, decision_id: objectId(core) };
}

export function assertDecision(value) {
  if (!TERMINAL.has(value)) throw new Error('decision_state_invalid');
  return value;
}
