// Operator-side signer. Keep private keys outside source, plans and worker state.
// The runtime never creates grants and never receives the private key.
import { readFile } from 'node:fs/promises';
import { sign, randomBytes } from 'node:crypto';
import { canonical, objectId } from '../src/evidence.js';
const [requestPath, privateKeyPath] = process.argv.slice(2);
if (!requestPath || !privateKeyPath) throw new Error('Usage: node scripts/authorize.mjs request.json operator-private.pem');
const { plan, control } = JSON.parse(await readFile(requestPath, 'utf8'));
const body = process.argv.includes('--revoke') ? { version:1, decision:'REVOKE', control_surface_id:control.control_surface_id, issued_at:Date.now() } : { version: 1, decision: 'AUTHORIZE', plan_id: objectId(plan),
  control_surface_id: control.control_surface_id, capabilities: control.capabilities_requested,
  nonce: randomBytes(16).toString('hex'), not_before: Date.now(), expires_at: Date.now() + 15 * 60 * 1000 };
const signature = sign(null, Buffer.from(canonical(body)), await readFile(privateKeyPath, 'utf8')).toString('base64');
console.log(JSON.stringify({ body, signature }, null, 2));
