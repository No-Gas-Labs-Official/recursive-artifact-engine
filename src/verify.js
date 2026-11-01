#!/usr/bin/env node
/**
 * Minimal verifier. A hash proves bytes. It does not prove a claim.
 * A claim with no receipt is laundering. A receipt that sets verified=true
 * without an independent_check is the model grading its own homework.
 */
import { createHash } from "node:crypto";
import fs from "node:fs";

export function receiptFor(bytes, claim = null) {
  const buf = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  return {
    schema: "rae/receipt/v1",
    sha256: createHash("sha256").update(buf).digest("hex"),
    bytes: buf.length,
    claim,
    verified: false,
    note: "Hash proves bytes. It does not prove the claim.",
  };
}

export function launderCheck({ claim, receipt }) {
  if (claim && !receipt) return { ok: false, code: "CLAIM_WITHOUT_RECEIPT" };
  if (receipt?.verified === true && !receipt.independent_check) {
    return { ok: false, code: "SELF_VERIFIED" };
  }
  if (receipt && receipt.schema !== "rae/receipt/v1") {
    return { ok: false, code: "BAD_SCHEMA" };
  }
  return { ok: true, code: "OK" };
}

function main() {
  const file = process.argv[2];
  if (!file) {
    console.error("usage: node src/verify.js <file> [--claim text]");
    process.exit(2);
  }
  const claimFlag = process.argv.indexOf("--claim");
  const claim = claimFlag >= 0 ? process.argv[claimFlag + 1] : null;
  const bytes = fs.readFileSync(file);
  const receipt = receiptFor(bytes, claim);
  process.stdout.write(JSON.stringify(receipt, null, 2) + "\n");
}

if (process.argv[1] && process.argv[1].endsWith("verify.js")) {
  main();
}
