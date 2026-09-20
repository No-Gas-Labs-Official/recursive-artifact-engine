import { createHash } from 'node:crypto';
import { open, readFile } from 'node:fs/promises';
import { constants } from 'node:fs';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';

export const digest = bytes => createHash('sha256').update(bytes).digest('hex');
export function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}';
}
export const objectId = value => digest(canonical(value));

export async function readBounded(path, limit = 32 * 1024 * 1024) {
  const fd = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = await fd.stat();
    if (!stat.isFile() || stat.size > limit) throw new Error('input_not_regular_or_too_large');
    const bytes = Buffer.alloc(limit + 1);
    let size = 0;
    while (size <= limit) {
      const { bytesRead } = await fd.read(bytes, size, Math.min(65536, bytes.length - size), null);
      if (!bytesRead) break;
      size += bytesRead;
    }
    if (size > limit) throw new Error('input_limit');
    return bytes.subarray(0, size);
  } finally { await fd.close(); }
}

export async function observeBytes(bytes, format = 'bytes') {
  const artifact = { sha256: digest(bytes), byte_length: bytes.length };
  let extraction = null, extractor = 'rae-bytes-v1';
  if (format === 'json') {
    extraction = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    extractor = 'rae-json-v1';
  } else if (format === 'apk') {
    const script = fileURLToPath(new URL('../scripts/apk_extract.py', import.meta.url));
    extractor = 'apk_extract.py:sha256:' + digest(await readFile(script));
    const output = await new Promise((resolve, reject) => {
      const child = spawn('python3', ['-I', script], { stdio: ['pipe', 'pipe', 'pipe'], env: { PATH: process.env.PATH } });
      let stdout = '', stderr = '', overflow = false;
      const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('extractor_timeout')); }, 15000);
      child.stdout.on('data', b => { stdout += b; if (stdout.length > 16 * 1024 * 1024) { overflow = true; child.kill('SIGKILL'); } });
      child.stderr.on('data', b => { if (stderr.length < 4096) stderr += b; });
      child.on('error', error => { clearTimeout(timer); reject(error); });
      child.on('close', code => { clearTimeout(timer); code === 0 && !overflow ? resolve(stdout) : reject(new Error('extraction_failed:' + stderr.trim())); });
      child.stdin.on('error', () => {});
      child.stdin.end(bytes);
    });
    extraction = JSON.parse(output);
  } else if (format !== 'bytes') throw new Error('unsupported_format');
  const payload = { version: 1, artifact, extractor, extraction };
  return { ...payload, observation_id: objectId(payload) };
}

export function checkClaim(claim, observation) {
  // This helper is for freshly observed data. External observations are never
  // accepted by the public file-verification entry point.
  if (!claim || typeof claim !== 'object' || Array.isArray(claim)) throw new Error('claim_invalid');
  let actual, supported = true;
  const { extraction: e, artifact: a } = observation;
  switch (claim.kind) {
    case 'artifact.sha256': actual = a.sha256; break;
    case 'artifact.byte_length': actual = a.byte_length; break;
    case 'apk.member': actual = e?.format === 'apk-static-v1' ? e.members.some(m => m.name === claim.name) : undefined; break;
    case 'apk.class': actual = e?.format === 'apk-static-v1' ? Object.values(e.dex).some(d => d.classes.includes(claim.name)) : undefined; break;
    case 'apk.string': actual = e?.format === 'apk-static-v1' ? Object.values(e.dex).some(d => d.strings.includes(claim.name)) : undefined; break;
    case 'json.pointer': {
      if (observation.extractor !== 'rae-json-v1' || typeof claim.pointer !== 'string'
        || (claim.pointer !== '' && !claim.pointer.startsWith('/')) || /~(?:[^01]|$)/.test(claim.pointer)) { supported = false; break; }
      actual = e;
      for (const token of claim.pointer === '' ? [] : claim.pointer.slice(1).split('/')) {
        const key = token.replace(/~1/g, '/').replace(/~0/g, '~');
        actual = actual !== null && typeof actual === 'object' && Object.hasOwn(actual, key) ? actual[key] : undefined;
      }
      break;
    }
    default: supported = false;
  }
  if (!Object.hasOwn(claim, 'equals')) supported = false;
  const status = !supported ? 'UNSUPPORTED' : actual === undefined ? 'UNVERIFIABLE'
    : isDeepStrictEqual(actual, claim.equals) ? 'VERIFIED' : 'REFUTED';
  return { claim, status, accepted_as_observed_state: status === 'VERIFIED',
    observation_id: observation.observation_id, artifact_sha256: a.sha256,
    ...(actual === undefined ? {} : { actual }) };
}

export async function verifyClaims(path, format, claims) {
  if (!Array.isArray(claims) || claims.length > 1000) throw new Error('claims_invalid');
  const observation = await observeBytes(await readBounded(path), format);
  return { observation, results: claims.map(c => checkClaim(c, observation)) };
}
