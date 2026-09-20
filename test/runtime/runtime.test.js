import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign, randomBytes } from 'node:crypto';
import { mkdtemp, writeFile, readFile, readdir, rm, mkdir } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { canonical, objectId } from '../../src/evidence.js';
import { makeControl, controlId, validateAuthority } from '../../src/authority.js';
import { createPlan, runPlan, auditRun, revokeControl } from '../../src/runtime.js';

const { privateKey, publicKey: pub } = generateKeyPairSync('ed25519');
const publicKey = pub.export({ type: 'spki', format: 'pem' });
function authorize(plan, control, overrides = {}) {
  const body = { version: 1, decision: 'AUTHORIZE', plan_id: objectId(plan),
    control_surface_id: control.control_surface_id, capabilities: control.capabilities_requested,
    nonce: randomBytes(16).toString('hex'), not_before: Date.now() - 1000, expires_at: Date.now() + 60000, ...overrides };
  return { body, signature: sign(null, Buffer.from(canonical(body)), privateKey).toString('base64') };
}
async function fixture(t) {
  const dir = await mkdtemp(join(tmpdir(), 'rae-runtime-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const artifact = join(dir, 'input.json');
  await writeFile(artifact, '{"value":42}');
  const plan = await createPlan(artifact, 'json', [{kind:'json.pointer',pointer:'/value',equals:42}]);
  const control = makeControl(plan);
  return { dir, artifact, plan, control, grant: authorize(plan, control), publicKey, stateDir: join(dir, 'state') };
}

test('authorization rejects forged, stale, wrong-target and self-authorizing records', async t => {
  const f = await fixture(t);
  assert.equal(validateAuthority(f.plan, f.control, f.grant, publicKey).authorized, true);
  for (const cls of ['MODEL_PROPOSAL','CONNECTOR_INPUT','REFERENCE']) {
    const control = {...f.control, class:cls}; control.control_surface_id = controlId(control);
    assert.equal(validateAuthority(f.plan, control, authorize(f.plan,control), publicKey).authorized, false);
  }
  for (const change of [{ status:'SUPERSEDED' }, { actual_authority_status:'AUTHORIZED' },
    { human_authorization:'human:approved:fake' }, { capabilities_requested:['network.any'] },
    { capabilities_granted:['artifact.read'] }, { provenance_parents:[] }]) {
    const control = {...f.control,...change}; control.control_surface_id = controlId(control);
    assert.equal(validateAuthority(f.plan,control,authorize(f.plan,control),publicKey).authorized,false);
  }
  const expired = authorize(f.plan,f.control,{expires_at:Date.now()-1});
  assert.equal(validateAuthority(f.plan,f.control,expired,publicKey).authorized,false);
  const wrongTarget = authorize(f.plan,f.control,{plan_id:'0'.repeat(64)});
  assert.equal(validateAuthority(f.plan,f.control,wrongTarget,publicKey).authorized,false);
  const forged = structuredClone(f.grant); forged.signature = Buffer.alloc(64).toString('base64');
  assert.equal(validateAuthority(f.plan,f.control,forged,publicKey).authorized,false);
});

test('execution survives restart, rejects replay and preserves rejected operations', async t => {
  const f = await fixture(t);
  const success = await runPlan(f);
  assert.equal(success.status,'SUCCEEDED');
  assert.equal((await auditRun(success.run_dir)).outcome,'SUCCEEDED');
  const replay = await runPlan(f);
  assert.equal(replay.reason,'authorization_replay');
  assert.equal((await auditRun(replay.run_dir)).outcome,'REJECTED');
  await writeFile(join(f.dir,'request.json'),JSON.stringify({plan:f.plan,control:f.control}));
  await writeFile(join(f.dir,'grant.json'),JSON.stringify(f.grant));
  await writeFile(join(f.dir,'public.pem'),publicKey);
  try {
    await promisify(execFile)(process.execPath,[fileURLToPath(new URL('../../src/cli.js',import.meta.url)),
      'run',join(f.dir,'request.json'),'--grant',join(f.dir,'grant.json'),'--public-key',join(f.dir,'public.pem'),'--state',f.stateDir]);
    assert.fail('new process accepted replay');
  } catch(e) { assert.equal(JSON.parse(e.stdout).reason,'authorization_replay'); }
  const denied = await runPlan({...f, grant:null});
  assert.equal(denied.status,'REJECTED');
});

test('concurrent execution consumes an authorization exactly once', async t => {
  const f = await fixture(t);
  const results = await Promise.all([runPlan(f),runPlan(f)]);
  assert.deepEqual(results.map(r=>r.status).sort(), ['REJECTED','SUCCEEDED']);
});

test('persisted revocation prevents an old active control from reactivating', async t => {
  const f = await fixture(t);
  const body = {version:1,decision:'REVOKE',control_surface_id:f.control.control_surface_id,issued_at:Date.now()};
  const event = {body,signature:sign(null,Buffer.from(canonical(body)),privateKey).toString('base64')};
  await revokeControl({event,publicKey,stateDir:f.stateDir});
  const rejected = await runPlan(f);
  assert.equal(rejected.reason,'control_revoked');
  await assert.rejects(revokeControl({event:{...event,signature:'fake'},publicKey,stateDir:f.stateDir}),/revocation_signature_invalid/);
});

test('changed bytes, refuted claims and corrupt journals fail closed', async t => {
  const f = await fixture(t);
  await writeFile(f.artifact,'{"value":0}');
  const changed = await runPlan(f);
  assert.equal(changed.reason,'artifact_changed_after_authorization');
  assert.equal((await auditRun(changed.run_dir)).outcome,'FAILED');
  const plan = await createPlan(f.artifact,'json',f.plan.claims);
  const control = makeControl(plan);
  const refuted = await runPlan({...f,plan,control,grant:authorize(plan,control)});
  assert.equal(refuted.reason,'claims_not_verified');
  const file = (await readdir(refuted.run_dir)).find(n=>n.endsWith('.json'));
  const path = join(refuted.run_dir,file);
  const event = JSON.parse(await readFile(path)); event.type = 'SUCCEEDED';
  await writeFile(path,JSON.stringify(event));
  await assert.rejects(auditRun(refuted.run_dir),/journal_integrity_failed/);
});

test('unknown execution commands are rejected before dispatch', async t => {
  const f = await fixture(t);
  await assert.rejects(runPlan({...f,plan:{...f.plan,command:'curl example.com'}}),/plan_unknown_field/);
});

test('failed candidate test output is retained', async t => {
  const f = await fixture(t);
  const source = join(f.dir,'source');
  await mkdir(join(source,'test'),{recursive:true});
  await writeFile(join(source,'package.json'),'{"type":"module"}');
  await writeFile(join(source,'test/fail.test.js'),"import test from 'node:test'; test('intentional failure',()=>{throw Error('retained-failure')});");
  const plan = await createPlan(f.artifact,'json',f.plan.claims,source);
  const control = makeControl(plan);
  const result = await runPlan({...f,plan,control,grant:authorize(plan,control)});
  assert.equal(result.reason,'candidate_tests_failed');
  const event = (await readdir(result.run_dir)).find(n=>n.startsWith('000004-'));
  assert.match(await readFile(join(result.run_dir,event),'utf8'),/retained-failure/);
});

test('runtime rebuilds and starts its own verified candidate', {skip:process.env.RAE_CANDIDATE_TEST === '1'}, async t => {
  const f = await fixture(t);
  const plan = await createPlan(f.artifact,'json',f.plan.claims,fileURLToPath(new URL('../..',import.meta.url)));
  const control = makeControl(plan);
  const result = await runPlan({...f,plan,control,grant:authorize(plan,control)});
  assert.equal(result.status,'SUCCEEDED',JSON.stringify(result));
  assert.equal((await auditRun(result.run_dir)).outcome,'SUCCEEDED');
});
