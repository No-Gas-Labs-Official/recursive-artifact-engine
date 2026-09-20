#!/usr/bin/env node

import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { adjudicateModelClaim, verifyArtifact } from './verifier.js';
import { verifyClaims } from './evidence.js';
import { createPlan, runPlan, auditRun, revokeControl } from './runtime.js';
import { makeControl } from './authority.js';

function usage() {
  console.error('Usage:');
  console.error('  rae verify <artifact> [--out <receipt.json>]');
  console.error('  rae adjudicate <claim> [--receipt <receipt.json>]');
  console.error('  rae inspect <artifact> --format bytes|json|apk --claims <claims.json>');
  console.error('  rae plan <artifact> --format <format> --claims <claims.json> [--source <runtime-source>]');
  console.error('  rae run <request.json> --grant <grant.json> --public-key <operator.pem> --state <directory>');
  console.error('  rae audit <run-directory>');
  console.error('  rae revoke <signed-revocation.json> --public-key <operator.pem> --state <directory>');
}

async function main(argv) {
  const [command, ...args] = argv;
  const option = key => { const i = args.indexOf(key); if (i < 0 || !args[i+1]) throw new Error(key + ' required'); return args[i+1]; };
  const json = async path => JSON.parse(await readFile(path, 'utf8'));
  const print = value => process.stdout.write(JSON.stringify(value, null, 2) + '\n');
  if (command === 'inspect' || command === 'plan') {
    const claims = await json(option('--claims'));
    const format = option('--format');
    if (command === 'inspect') {
      const result = await verifyClaims(args[0], format, claims);
      print(result);
      if (result.results.some(r => r.status !== 'VERIFIED')) process.exitCode = 1;
    } else {
      const plan = await createPlan(args[0], format, claims, args.includes('--source') ? option('--source') : null);
      print({ plan, control: makeControl(plan) });
    }
    return;
  }
  if (command === 'run') {
    const request = await json(args[0]);
    const result = await runPlan({ ...request, grant: await json(option('--grant')),
      publicKey: await readFile(option('--public-key'), 'utf8'), stateDir: resolve(option('--state')) });
    print(result);
    if (result.status !== 'SUCCEEDED') process.exitCode = 1;
    return;
  }
  if (command === 'audit') { print(await auditRun(args[0])); return; }
  if (command === 'revoke') {
    print(await revokeControl({event:await json(args[0]),publicKey:await readFile(option('--public-key'),'utf8'),stateDir:resolve(option('--state'))}));
    return;
  }

  if (command === 'verify') {
    const artifact = args[0];
    if (!artifact) {
      usage();
      process.exitCode = 2;
      return;
    }

    const outIndex = args.indexOf('--out');
    const outPath = outIndex >= 0 ? args[outIndex + 1] : null;
    if (outIndex >= 0 && !outPath) {
      throw new Error('--out requires a path');
    }

    const receipt = await verifyArtifact(artifact);
    const serialized = `${JSON.stringify(receipt, null, 2)}\n`;

    if (outPath) {
      await writeFile(resolve(outPath), serialized, 'utf8');
    } else {
      process.stdout.write(serialized);
    }
    return;
  }

  if (command === 'adjudicate') {
    const claim = args[0];
    if (!claim) {
      usage();
      process.exitCode = 2;
      return;
    }

    const receiptIndex = args.indexOf('--receipt');
    let receipt;
    if (receiptIndex >= 0) {
      const receiptPath = args[receiptIndex + 1];
      if (!receiptPath) throw new Error('--receipt requires a path');
      const { readFile } = await import('node:fs/promises');
      receipt = JSON.parse(await readFile(resolve(receiptPath), 'utf8'));
    }

    process.stdout.write(`${JSON.stringify(adjudicateModelClaim(claim, receipt), null, 2)}\n`);
    return;
  }

  usage();
  process.exitCode = 2;
}

main(process.argv.slice(2)).catch((error) => {
  console.error(`rae: ${error.message}`);
  process.exitCode = 1;
});
