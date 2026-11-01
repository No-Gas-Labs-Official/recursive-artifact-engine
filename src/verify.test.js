import { test } from "node:test";
import assert from "node:assert/strict";
import { launderCheck, receiptFor } from "./verify.js";

test("hash is stable and does not mark the claim verified", () => {
  const receipt = receiptFor("hello", "this file is the constitution");
  assert.equal(receipt.sha256, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
  assert.equal(receipt.verified, false);
  assert.equal(receipt.claim, "this file is the constitution");
});

test("a claim without a receipt is rejected", () => {
  const result = launderCheck({ claim: "the model says this docx is correct", receipt: null });
  assert.equal(result.ok, false);
  assert.equal(result.code, "CLAIM_WITHOUT_RECEIPT");
});

test("verified=true without an independent check is rejected", () => {
  const receipt = receiptFor("bytes", "ok");
  receipt.verified = true;
  const result = launderCheck({ claim: "ok", receipt });
  assert.equal(result.code, "SELF_VERIFIED");
});

test("a honest receipt passes", () => {
  const receipt = receiptFor("bytes", "unverified note");
  assert.equal(launderCheck({ claim: "unverified note", receipt }).ok, true);
});
