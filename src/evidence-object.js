import { objectId } from './evidence.js';

const KINDS = new Set(['OBSERVATION','CLAIM','RECEIPT','AUTHORITY','DECISION','ACTION','CONTRADICTION']);
const TRUST = new Set(['SELF_ASSERTED','INDEPENDENTLY_OBSERVED','CRYPTOGRAPHICALLY_BOUND','EXTERNALLY_ATTESTED']);

export function makeEvidenceObject(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('evidence_object_invalid');
  if (!KINDS.has(input.kind)) throw new Error('evidence_kind_invalid');
  if (!TRUST.has(input.trust)) throw new Error('evidence_trust_invalid');
  if (typeof input.subject !== 'string' || !input.subject) throw new Error('evidence_subject_invalid');
  if (!Object.hasOwn(input, 'payload')) throw new Error('evidence_payload_missing');
  const parents = input.parents ?? [];
  if (!Array.isArray(parents) || parents.some(x => typeof x !== 'string' || !x)) throw new Error('evidence_parents_invalid');
  const core = {
    schema: 'ngl.evidence-object.v1',
    kind: input.kind,
    subject: input.subject,
    trust: input.trust,
    observer: input.observer ?? null,
    rule_version: input.rule_version ?? null,
    parents: [...parents],
    payload: input.payload
  };
  return { ...core, evidence_id: objectId(core) };
}

export function contradict(left, right, reason) {
  if (!left?.evidence_id || !right?.evidence_id || left.evidence_id === right.evidence_id) throw new Error('contradiction_inputs_invalid');
  return makeEvidenceObject({
    kind: 'CONTRADICTION',
    subject: left.subject === right.subject ? left.subject : `${left.subject} <-> ${right.subject}`,
    trust: 'INDEPENDENTLY_OBSERVED',
    observer: 'rae:contradiction-v1',
    rule_version: 'ngl.contradiction.v1',
    parents: [left.evidence_id, right.evidence_id],
    payload: { left: left.evidence_id, right: right.evidence_id, reason }
  });
}

export function authoritative(object) {
  return object?.kind === 'OBSERVATION' && object?.trust === 'INDEPENDENTLY_OBSERVED'
    || object?.trust === 'CRYPTOGRAPHICALLY_BOUND'
    || object?.trust === 'EXTERNALLY_ATTESTED';
}
