# recursive-artifact-engine

**Classification:** RUNNABLE — minimal verifier  
**Type:** provenance / anti-laundering foundation  
**Implementation status:** **minimal implementation present**

The Recursive Artifact Engine (RAE) starts from one rule:

> Model-generated state is not trusted merely because a model asserts that it is correct.

This repository now implements the first executable slice of that rule. It independently reads an artifact, hashes the bytes, emits a machine-readable verification receipt, validates receipt integrity, and refuses to promote an unreceipted model claim into observed state.

## What is implemented

- `rae verify <artifact>` independently reads a local file and emits a JSON receipt.
- Receipts bind the artifact name, file URI, byte length, SHA-256 digest, observation timestamp, verifier identity, and the explicit fact that model assertion was not trusted as evidence.
- Every receipt includes a SHA-256 integrity digest over its canonical evidence payload.
- `rae adjudicate <claim> [--receipt receipt.json]` exercises the anti-laundering circuit breaker.
- A missing or invalid receipt keeps the claim at `PROPOSED` and opens the circuit breaker.
- A valid file receipt may make a claim `EVIDENCE_BACKED`, but it still does **not** make the claim's semantics observed or true. File integrity is not factual correctness.
- The receipt format is declared in `schemas/receipt-v1.json`.

## Install / run

Requires Node.js 20+ and no third-party dependencies.

```bash
npm test
node ./src/cli.js verify ./test/fixtures/example.txt
node ./src/cli.js verify ./test/fixtures/example.txt --out receipt.json
node ./src/cli.js adjudicate "The artifact is correct."
node ./src/cli.js adjudicate "The artifact exists with these bytes." --receipt receipt.json
```

You can also use the package script:

```bash
npm run verify -- ./test/fixtures/example.txt
```

## Receipt semantics

A receipt proves only what this implementation independently observed at verification time:

1. the verifier successfully read a local regular file;
2. the file had the reported byte length and SHA-256 digest;
3. the receipt evidence payload has not been modified without invalidating `receipt_sha256`.

It does **not** prove that prose inside the artifact is factually correct, that an AI claim is true, or that a document renderer preserved meaning across formats. Those require additional independent extractors and comparators.

## Circuit-breaker invariant

The core negative test is intentional:

```text
MODEL CLAIM + NO VALID RECEIPT => PROPOSED / NOT OBSERVED
```

Even with a valid receipt:

```text
VALID FILE RECEIPT != VERIFIED CLAIM SEMANTICS
```

This prevents evidence laundering: a model cannot convert its own assertion into observed state by wrapping the assertion in confident language or by pointing to a file that has merely been hashed.

## Current repository layout

```text
package.json
src/
  cli.js
  verifier.js
schemas/
  receipt-v1.json
test/
  verifier.test.js
  fixtures/example.txt
.github/workflows/test.yml
README.md
```

## Scope boundary

The earlier specification mentioned multi-format documents (DOCX / PDF / PPTX / XLSX). This first implementation treats all artifacts as raw bytes. Format-aware verification, deterministic extraction, cross-format comparison, provenance graphs, and richer anti-laundering policies remain future work.

## Relation to Protocol X / EvidenceOS

Shared vocabulary is not shared implementation. Nothing in this repository should be treated as implementing Protocol X or the EvidenceOS Inference Engine unless concrete code is added and independently verified.

---

*A name is not an engine. A passing model response is not evidence. A receipt is the beginning of verification, not the end.*
