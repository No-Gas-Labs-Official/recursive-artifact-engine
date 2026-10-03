import { mkdir, readFile, writeFile, readdir, lstat, realpath, open } from 'node:fs/promises';
import { resolve, relative, join, dirname, isAbsolute } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createPublicKey } from 'node:crypto';
import { canonical, objectId, digest, readBounded, observeBytes, checkClaim } from './evidence.js';
import { validateAuthority, validRevocation } from './authority.js';

const execute = promisify(execFile);
const roots = ['src', 'scripts', 'schemas', 'test', 'integration', 'experiments'];
const safePath = p => typeof p === 'string' && p.length && !isAbsolute(p) && !p.includes('\\') && !p.split('/').some(v => !v || v === '.' || v === '..');

export async function sourceManifest(root) {
  const files = [];
  async function visit(path) {
    const stat = await lstat(join(root, path));
    if (stat.isSymbolicLink()) throw new Error('source_symlink');
    if (stat.isDirectory()) {
      for (const name of (await readdir(join(root, path))).sort()) {
        if (name === '__pycache__') continue;
        await visit(path + '/' + name);
      }
    } else if (stat.isFile()) {
      const bytes = await readBounded(join(root, path));
      files.push({ path, sha256: digest(bytes), byte_length: bytes.length });
    } else throw new Error('source_not_regular');
  }
  await visit('package.json');
  for (const dir of roots) {
    try { await lstat(join(root, dir)); } catch (e) { if (e.code === 'ENOENT') continue; throw e; }
    await visit(dir);
  }
  return files.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
}

export async function createPlan(artifactPath, format, claims, sourceRoot = null) {
  const artifact = await realpath(artifactPath);
  const bytes = await readBounded(artifact);
  return { version: 1, operation: sourceRoot ? 'self-build' : 'verify',
    artifact: { path: artifact, sha256: digest(bytes), byte_length: bytes.length, format },
    claims,
    ...(sourceRoot ? { source_root: await realpath(sourceRoot), sources: await sourceManifest(sourceRoot) } : {}) };
}

function assertPlan(plan) {
  if (!plan || plan.version !== 1 || !['verify','self-build'].includes(plan.operation)
    || !plan.artifact || !isAbsolute(plan.artifact.path) || !/^[a-f0-9]{64}$/.test(plan.artifact.sha256)
    || !Number.isSafeInteger(plan.artifact.byte_length) || plan.artifact.byte_length < 0
    || !['bytes','json','apk'].includes(plan.artifact.format) || !Array.isArray(plan.claims) || !plan.claims.length || plan.claims.length > 1000) throw new Error('plan_invalid');
  const allowed = ['version','operation','artifact','claims', ...(plan.operation === 'self-build' ? ['source_root','sources'] : [])];
  if (Object.keys(plan).some(k => !allowed.includes(k)) || Object.keys(plan.artifact).sort().join(',') !== 'byte_length,format,path,sha256') throw new Error('plan_unknown_field');
  if (plan.operation === 'self-build') {
    if (!isAbsolute(plan.source_root) || !Array.isArray(plan.sources) || !plan.sources.length || plan.sources.length > 1000) throw new Error('source_manifest_invalid');
    const seen = new Set();
    for (const f of plan.sources) {
      if (!safePath(f.path) || seen.has(f.path) || !/^[a-f0-9]{64}$/.test(f.sha256) || !Number.isSafeInteger(f.byte_length) || f.byte_length < 0) throw new Error('source_manifest_invalid');
      seen.add(f.path);
    }
  }
}

async function appendEvent(directory, events, type, payload) {
  const body = { sequence: events.length, previous: events.at(-1)?.id ?? null, type, payload };
  const event = { id: objectId(body), ...body };
  const fd = await open(join(directory, `${String(events.length).padStart(6,'0')}-${event.id}.json`), 'wx', 0o600);
  try { await fd.writeFile(canonical(event) + '\n'); await fd.sync(); } finally { await fd.close(); }
  events.push(event);
  return event;
}

export async function auditRun(directory) {
  const names = (await readdir(directory)).filter(n => /^\d{6}-[a-f0-9]{64}\.json$/.test(n)).sort();
  const events = [];
  for (const name of names) {
    const event = JSON.parse(await readBounded(join(directory, name)));
    const { id, ...body } = event;
    if (id !== objectId(body) || event.sequence !== events.length || event.previous !== (events.at(-1)?.id ?? null)
      || name !== `${String(events.length).padStart(6,'0')}-${id}.json`) throw new Error('journal_integrity_failed');
    events.push(event);
  }
  if (!events.length || !['SUCCEEDED','FAILED','REJECTED'].includes(events.at(-1).type)) throw new Error('journal_incomplete');
  return { valid: true, event_count: events.length, head: events.at(-1).id, outcome: events.at(-1).type };
}

export async function runPlan({ plan, control, grant, publicKey, stateDir }) {
  // stateDir + publicKey belong to the operator's trusted launch configuration.
  // This dispatcher is not an OS sandbox for approved candidate code.
  assertPlan(plan);
  await mkdir(stateDir, { recursive: true, mode: 0o700 });
  const state = await realpath(stateDir);
  const attempt = await import('node:crypto').then(c => c.randomUUID());
  const runDir = join(state, 'runs', attempt);
  await mkdir(runDir, { recursive: true, mode: 0o700 });
  const events = [];
  const emit = (type, payload) => appendEvent(runDir, events, type, payload);
  await emit('PROPOSED', { plan, control });
  const decision = validateAuthority(plan, control, grant, publicKey);
  if (!decision.authorized) {
    await emit('REJECTED', decision);
    return { status: 'REJECTED', reason: decision.reason, run_dir: runDir };
  }
  const revokedDir = join(state,'revocations');
  await mkdir(revokedDir,{recursive:true,mode:0o700});
  for (const name of await readdir(revokedDir)) {
    const event = JSON.parse(await readBounded(join(revokedDir,name)));
    if (!validRevocation(event,publicKey) || name !== objectId(event) + '.json') throw new Error('revocation_integrity_failed');
    if (event.body.control_surface_id === control.control_surface_id) {
      await emit('REJECTED',{reason:'control_revoked'});
      return {status:'REJECTED',reason:'control_revoked',run_dir:runDir};
    }
  }
  try {
    await mkdir(join(state, 'spent'), { recursive: true, mode: 0o700 });
    // Atomic exclusive creation consumes a grant even when a later step fails.
    const key = objectId({ publicKey: createPublicKey(publicKey).export({ type: 'spki', format: 'der' }).toString('hex'), nonce: grant.body.nonce });
    await writeFile(join(state, 'spent', key), canonical({ authorization: grant, run: attempt }), { flag: 'wx', mode: 0o600 });
  } catch (e) {
    if (e.code !== 'EEXIST') throw e;
    await emit('REJECTED', { reason: 'authorization_replay' });
    return { status: 'REJECTED', reason: 'authorization_replay', run_dir: runDir };
  }
  await emit('AUTHORIZED', { grant, ...decision });
  try {
    const bytes = await readBounded(plan.artifact.path);
    if (digest(bytes) !== plan.artifact.sha256 || bytes.length !== plan.artifact.byte_length) throw new Error('artifact_changed_after_authorization');
    const observation = await observeBytes(bytes, plan.artifact.format);
    const results = plan.claims.map(c => checkClaim(c, observation));
    await emit('OBSERVED', { observation, results });
    if (results.some(r => r.status !== 'VERIFIED')) throw new Error('claims_not_verified');
    let candidate = null;
    if (plan.operation === 'self-build') {
      // Detect added, removed and modified files, not just changes to listed files.
      if (canonical(await sourceManifest(plan.source_root)) !== canonical(plan.sources)) throw new Error('source_changed_after_authorization');
      candidate = join(runDir, 'candidate');
      await mkdir(candidate);
      let total = 0;
      for (const f of plan.sources) {
        const source = await realpath(join(plan.source_root, f.path));
        const rel = relative(plan.source_root, source);
        if (rel.startsWith('..') || isAbsolute(rel)) throw new Error('source_path_escape');
        const data = await readBounded(source);
        total += data.length;
        if (total > 64 * 1024 * 1024 || digest(data) !== f.sha256 || data.length !== f.byte_length) throw new Error('source_changed_during_snapshot');
        const target = join(candidate, f.path);
        await mkdir(dirname(target), { recursive: true });
        await writeFile(target, data, { flag: 'wx' });
      }
      await emit('BUILT', { source_id: objectId(plan.sources), sources: plan.sources });
      const env = { PATH: process.env.PATH, LANG: 'C.UTF-8', RAE_CANDIDATE_TEST: '1' };
      const testFiles = plan.sources.filter(f => /^test\/.*\.test\.js$/.test(f.path)).map(f => f.path);
      if (!testFiles.length) throw new Error('candidate_tests_missing');
      let testOutput;
      try {
        testOutput = await execute(process.execPath, ['--test', ...testFiles], { cwd: candidate, env, timeout: 60000, maxBuffer: 4 * 1024 * 1024 });
      } catch (e) {
        await emit('TEST_FAILED', { code: e.code ?? null, signal: e.signal ?? null, stdout: e.stdout ?? '', stderr: e.stderr ?? '' });
        throw new Error('candidate_tests_failed');
      }
      await emit('TEST_PASSED', testOutput);
      // The child runtime must independently re-observe the exact same snapshot.
      const input = join(runDir, 'input.bin');
      await writeFile(input, bytes, { flag: 'wx' });
      const claims = join(runDir, 'claims.json');
      await writeFile(claims, canonical(plan.claims), { flag: 'wx' });
      const smoke = await execute(process.execPath, ['src/cli.js', 'inspect', input, '--format', plan.artifact.format, '--claims', claims], { cwd: candidate, env, timeout: 30000, maxBuffer: 16 * 1024 * 1024 });
      const reproduced = JSON.parse(smoke.stdout);
      if (canonical(reproduced.observation) !== canonical(observation) || canonical(reproduced.results) !== canonical(results)) throw new Error('candidate_observation_diverged');
      if (canonical(await sourceManifest(candidate)) !== canonical(plan.sources)) throw new Error('candidate_modified_during_test');
      await emit('CANDIDATE_VERIFIED', { observation_id: reproduced.observation.observation_id, source_id: objectId(plan.sources) });
    }
    const terminal = await emit('SUCCEEDED', { observation_id: observation.observation_id, candidate });
    return { status: 'SUCCEEDED', run_dir: runDir, candidate, head: terminal.id, observation_id: observation.observation_id };
  } catch (e) {
    await emit('FAILED', { reason: e.message });
    return { status: 'FAILED', reason: e.message, run_dir: runDir };
  }
}

export async function revokeControl({ event, publicKey, stateDir }) {
  if (!validRevocation(event,publicKey)) throw new Error('revocation_signature_invalid');
  const dir = join(stateDir,'revocations');
  await mkdir(dir,{recursive:true,mode:0o700});
  const id = objectId(event);
  try { await writeFile(join(dir,id+'.json'),canonical(event),{flag:'wx',mode:0o600}); }
  catch(e) { if(e.code !== 'EEXIST') throw e; }
  return {status:'REVOKED',event_id:id,control_surface_id:event.body.control_surface_id};
}
