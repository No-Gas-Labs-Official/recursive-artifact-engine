import { createHash } from 'node:crypto';
import { open } from 'node:fs/promises';
import { basename, extname, resolve } from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';

export const RECEIPT_SCHEMA = 'https://no-gas-labs-official.github.io/recursive-artifact-engine/schemas/receipt-v1.json';
export const RECEIPT_VERSION = 1;

function normalizeArtifactPath(input) {
  if (input instanceof URL) {
    if (input.protocol !== 'file:') {
      throw new TypeError('Only local file: URLs are supported');
    }
    return resolve(fileURLToPath(input));
  }

  if (typeof input !== 'string' || input.trim() === '') {
    throw new TypeError('artifact must be a non-empty filesystem path or file: URL');
  }

  return resolve(input);
}

function sha256(buffer) {
  return createHash('sha256').update(buffer).digest('hex');
}

function canonicalReceiptPayload(receipt) {
  return JSON.stringify({
    schema: receipt.schema,
    receipt_version: receipt.receipt_version,
    verifier: receipt.verifier,
    artifact: receipt.artifact,
    observation: receipt.observation
  });
}

export async function verifyArtifact(input, options = {}) {
  const artifactPath = normalizeArtifactPath(input);
  const handle = await open(artifactPath, 'r');
  let bytes;
  try {
    if (!(await handle.stat()).isFile()) throw new Error('artifact is not a regular file');
    bytes = await handle.readFile();
  } finally { await handle.close(); }

  const observedAt = options.observedAt ?? new Date().toISOString();
  const artifactDigest = sha256(bytes);

  const receipt = {
    schema: RECEIPT_SCHEMA,
    receipt_version: RECEIPT_VERSION,
    verifier: {
      name: 'recursive-artifact-engine',
      implementation: 'minimal-verifier',
      algorithm: 'sha256'
    },
    artifact: {
      name: basename(artifactPath),
      extension: extname(artifactPath).toLowerCase() || null,
      uri: pathToFileURL(artifactPath).href,
      byte_length: bytes.byteLength,
      sha256: artifactDigest
    },
    observation: {
      status: 'OBSERVED',
      observed_at: observedAt,
      source: 'local-filesystem-read',
      model_assertion_trusted: false
    }
  };

  receipt.receipt_sha256 = sha256(Buffer.from(canonicalReceiptPayload(receipt)));
  return receipt;
}

export function validateReceipt(receipt) {
  if (!receipt || typeof receipt !== 'object') {
    return { valid: false, reason: 'receipt_missing' };
  }

  if (receipt.schema !== RECEIPT_SCHEMA || receipt.receipt_version !== RECEIPT_VERSION) {
    return { valid: false, reason: 'receipt_schema_unsupported' };
  }

  if (receipt.observation?.status !== 'OBSERVED') {
    return { valid: false, reason: 'artifact_not_observed' };
  }

  if (receipt.observation?.model_assertion_trusted !== false) {
    return { valid: false, reason: 'model_assertion_laundered_as_evidence' };
  }

  if (!/^[a-f0-9]{64}$/.test(receipt.artifact?.sha256 ?? '')) {
    return { valid: false, reason: 'artifact_digest_invalid' };
  }

  const keys = (o, expected) => o && typeof o === 'object' && !Array.isArray(o)
    && Object.keys(o).sort().join(',') === expected.sort().join(',');
  const a = receipt.artifact, v = receipt.verifier, o = receipt.observation;
  let uriValid = false;
  try { uriValid = new URL(a.uri).protocol === 'file:'; } catch {}
  if (!keys(receipt, ['schema','receipt_version','verifier','artifact','observation','receipt_sha256'])
    || !keys(a, ['name','extension','uri','byte_length','sha256'])
    || !keys(v, ['name','implementation','algorithm'])
    || !keys(o, ['status','observed_at','source','model_assertion_trusted'])
    || typeof a.name !== 'string' || !a.name.length || !uriValid
    || !(a.extension === null || typeof a.extension === 'string')
    || !Number.isSafeInteger(a.byte_length) || a.byte_length < 0
    || v.name !== 'recursive-artifact-engine' || v.implementation !== 'minimal-verifier'
    || v.algorithm !== 'sha256' || o.source !== 'local-filesystem-read'
    || typeof o.observed_at !== 'string' || !Number.isFinite(Date.parse(o.observed_at))) {
    return { valid: false, reason: 'receipt_structure_invalid' };
  }

  const expectedReceiptDigest = sha256(Buffer.from(canonicalReceiptPayload(receipt)));
  if (receipt.receipt_sha256 !== expectedReceiptDigest) {
    return { valid: false, reason: 'receipt_integrity_failed' };
  }

  return { valid: true, reason: null };
}

export function adjudicateModelClaim(claim, receipt) {
  if (typeof claim !== 'string' || claim.trim() === '') {
    throw new TypeError('claim must be a non-empty string');
  }

  const validation = validateReceipt(receipt);
  if (!validation.valid) {
    return {
      claim,
      status: 'PROPOSED',
      accepted_as_observed_state: false,
      circuit_breaker: 'OPEN',
      reason: validation.reason
    };
  }

  return {
    claim,
    status: 'PROPOSED',
    accepted_as_observed_state: false,
    circuit_breaker: 'OPEN',
    reason: 'receipt_self_integrity_only_claim_not_verified',
    receipt_sha256: receipt.receipt_sha256,
    artifact_sha256: receipt.artifact.sha256
  };
}
