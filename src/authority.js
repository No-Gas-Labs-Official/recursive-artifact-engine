import { verify as verifySignature } from 'node:crypto';
import { canonical, objectId } from './evidence.js';

export const BUILD_CAPABILITIES = ['artifact.read', 'candidate.write', 'trusted-code.execute'];
export const VERIFY_CAPABILITIES = ['artifact.read'];
function controlStructure(c) {
  if (!c || typeof c !== 'object' || Array.isArray(c)) return false;
  const requiredStrings = ['control_surface_id','source_identity','source_revision','source_path','class','intended_consumer','producer','authority_claim','actual_authority_status','instruction_or_behavior_summary','execution_effect','persistence_effect','created_at','status'];
  const arrays = ['references','dependencies','capabilities_requested','capabilities_granted','supersedes','superseded_by','provenance_parents'];
  if (Object.keys(c).some(k => ![...requiredStrings,...arrays,'human_authorization'].includes(k))) return false;
  if (requiredStrings.some(k => typeof c[k] !== 'string')) return false;
  if (['control_surface_id','source_identity','source_revision','source_path','intended_consumer','producer'].some(k => !c[k].length)) return false;
  if (!Number.isFinite(Date.parse(c.created_at))) return false;
  if (arrays.some(k => Object.hasOwn(c,k) && (!Array.isArray(c[k]) || c[k].some(v => typeof v !== 'string')))) return false;
  return Object.hasOwn(c,'provenance_parents');
}
export function controlId(record) {
  const { control_surface_id, ...body } = record;
  return objectId(body);
}

export function validateAuthority(plan, control, grant, publicKey, now = Date.now()) {
  const reject = reason => ({ authorized: false, reason });
  if (!controlStructure(control)) return reject('control_structure_invalid');
  if (!control || control.class !== 'EXECUTABLE_CONTROL') return reject('source_cannot_authorize');
  if (control.status !== 'ACTIVE' || control.actual_authority_status !== 'PROPOSED') return reject('control_inactive_or_self_authorized');
  if (control.superseded_by?.length) return reject('control_superseded');
  if (control.control_surface_id !== controlId(control)) return reject('control_identity_mismatch');
  if (control.source_revision !== objectId(plan) || control.intended_consumer !== 'rae-runtime-v1') return reject('control_plan_mismatch');
  if (!Array.isArray(control.provenance_parents) || !control.provenance_parents.includes(objectId(plan))) return reject('control_parent_missing');
  if (control.human_authorization !== null || !Array.isArray(control.capabilities_granted) || control.capabilities_granted.length) return reject('embedded_authority_rejected');
  const required = plan.operation === 'self-build' ? BUILD_CAPABILITIES : plan.operation === 'verify' ? VERIFY_CAPABILITIES : null;
  if (!required) return reject('operation_not_allowed');
  if (canonical(control.capabilities_requested) !== canonical(required)) return reject('capability_mismatch');
  const b = grant?.body;
  if (!b || b.version !== 1 || b.decision !== 'AUTHORIZE' || typeof b.nonce !== 'string' || !/^[a-f0-9]{32}$/.test(b.nonce)) return reject('grant_invalid');
  if (b.plan_id !== objectId(plan) || b.control_surface_id !== control.control_surface_id || canonical(b.capabilities) !== canonical(required)) return reject('grant_scope_mismatch');
  if (!Number.isSafeInteger(b.not_before) || !Number.isSafeInteger(b.expires_at)
    || now < b.not_before || now >= b.expires_at) return reject('grant_expired_or_not_yet_valid');
  try {
    if (typeof grant.signature !== 'string' || !verifySignature(null, Buffer.from(canonical(b)), publicKey, Buffer.from(grant.signature, 'base64'))) return reject('grant_signature_invalid');
  } catch { return reject('grant_signature_invalid'); }
  return { authorized: true, reason: null, authorization_id: objectId(grant) };
}

export function makeControl(plan) {
  const planId = objectId(plan);
  const record = {
    source_identity: 'rae-runtime-plan', source_revision: planId, source_path: 'plan.json',
    class: 'EXECUTABLE_CONTROL', intended_consumer: 'rae-runtime-v1', producer: 'operator-reviewed-plan',
    authority_claim: '', actual_authority_status: 'PROPOSED', instruction_or_behavior_summary: plan.operation,
    execution_effect: plan.operation === 'self-build' ? 'Execute pinned candidate Node tests and smoke command' : 'Read and verify pinned artifact bytes',
    persistence_effect: 'Append run evidence; self-build also writes a fresh candidate',
    capabilities_requested: plan.operation === 'self-build' ? BUILD_CAPABILITIES : VERIFY_CAPABILITIES,
    capabilities_granted: [], human_authorization: null,
    created_at: new Date().toISOString(), status: 'ACTIVE', provenance_parents: [planId]
  };
  return { control_surface_id: controlId(record), ...record };
}

export function validRevocation(event, publicKey) {
  const b = event?.body;
  if (!b || b.version !== 1 || b.decision !== 'REVOKE' || !/^[a-f0-9]{64}$/.test(b.control_surface_id)
    || !Number.isSafeInteger(b.issued_at) || b.issued_at > Date.now()) return false;
  try { return verifySignature(null, Buffer.from(canonical(b)), publicKey, Buffer.from(event.signature,'base64')); }
  catch { return false; }
}
