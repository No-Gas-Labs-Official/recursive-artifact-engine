#!/usr/bin/env node

import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { adjudicateModelClaim, verifyArtifact } from './verifier.js';

function usage() {
  console.error('Usage:');
  console.error('  rae verify <artifact> [--out <receipt.json>]');
  console.error('  rae adjudicate <claim> [--receipt <receipt.json>]');
}

async function main(argv) {
  const [command, ...args] = argv;

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
