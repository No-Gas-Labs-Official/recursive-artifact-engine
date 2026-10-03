import { objectId } from './evidence.js';

export function adjudicateProofBundle({ subject, requirements, evidence = [] }) {
  if (typeof subject !== 'string' || !subject) throw new Error('subject_invalid');
  if (!Array.isArray(requirements) || requirements.length === 0) throw new Error('requirements_invalid');
  const ids = new Set(evidence.map(x => x?.evidence_id).filter(Boolean));
  const checks = requirements.map(r => {
    if (!r?.id || !Array.isArray(r.evidence_ids) || r.evidence_ids.length === 0) throw new Error('requirement_invalid');
    const missing = r.evidence_ids.filter(id => !ids.has(id));
    return { id:r.id, status:missing.length ? 'UNVERIFIABLE' : 'VERIFIED', missing };
  });
  const core = {
    schema:'ngl.proof-bundle.v1',
    subject,
    checks,
    evidence_ids:[...ids].sort(),
    status:checks.every(x => x.status === 'VERIFIED') ? 'VERIFIED' : 'UNVERIFIABLE'
  };
  return { ...core, bundle_id:objectId(core) };
}
