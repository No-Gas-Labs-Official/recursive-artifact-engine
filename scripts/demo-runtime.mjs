// Demonstration bootstrap only. This ephemeral test key is NOT a human identity.
// Production operators use their own reviewed grant and protected public-key root.
import { generateKeyPairSync, sign, randomBytes } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFile } from 'node:fs/promises';
import { createPlan, runPlan, auditRun } from '../src/runtime.js';
import { makeControl } from '../src/authority.js';
import { canonical, objectId } from '../src/evidence.js';

const [apk, destination] = process.argv.slice(2);
if (!apk || !destination) throw new Error('Usage: node scripts/demo-runtime.mjs reference.apk fresh-output-directory');
const root = fileURLToPath(new URL('..',import.meta.url));
const dir = resolve(destination);
await mkdir(dir); // Refuse to overwrite prior demonstration evidence.
const plan = await createPlan(apk,'apk',JSON.parse(await readFile(new URL('../integration/relay-claims.json',import.meta.url))),root);
const control = makeControl(plan);
const {privateKey,publicKey} = generateKeyPairSync('ed25519');
const body = {version:1,decision:'AUTHORIZE',plan_id:objectId(plan),control_surface_id:control.control_surface_id,
  capabilities:control.capabilities_requested,nonce:randomBytes(16).toString('hex'),not_before:Date.now()-1000,expires_at:Date.now()+300000};
const grant = {body,signature:sign(null,Buffer.from(canonical(body)),privateKey).toString('base64')};
const pem = publicKey.export({type:'spki',format:'pem'});
await writeFile(resolve(dir,'demo-public.pem'),pem,{flag:'wx'});
await writeFile(resolve(dir,'request.json'),canonical({plan,control}),{flag:'wx'});
await writeFile(resolve(dir,'grant.json'),canonical(grant),{flag:'wx'});
const result = await runPlan({plan,control,grant,publicKey:pem,stateDir:resolve(dir,'state')});
const audit = await auditRun(result.run_dir);
const summary = {scope:'Ephemeral test-key demonstration; not a human authorization event',result,audit};
await writeFile(resolve(dir,'summary.json'),JSON.stringify(summary,null,2)+'\n',{flag:'wx'});
console.log(JSON.stringify(summary,null,2));
if(result.status !== 'SUCCEEDED') process.exitCode=1;
