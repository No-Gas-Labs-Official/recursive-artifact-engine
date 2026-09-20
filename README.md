# Recursive Artifact Engine

An executable evidence verifier and bounded host runtime. **Assertion is not observation.**

Requires Node.js 20+ and Python 3.12+; no third-party packages. The runtime is NEW development, not a reconstruction of the Android Relay engine.

## Execute the vertical slice

```sh
npm test
node src/cli.js inspect /path/to/NGL_BUS.apk --format apk --claims integration/relay-claims.json
node scripts/demo-runtime.mjs /path/to/NGL_BUS.apk /path/to/fresh-demo-output
```

The demo independently checks the reference APK, verifies 27 explicit predicates, creates a pinned source snapshot of this runtime, executes the candidate's tests, starts the candidate CLI, and requires identical independently extracted observations. Failures remain recorded. Its ephemeral signing key is explicitly a **test bootstrap**, not proof of human authorization. The private key is never written to disk or supplied to the worker.

A self-build produces a runnable source distribution in the run's `candidate/` directory. It does not generate new source, compile an Android APK, upgrade the running process, deploy itself, or claim to be an unrestricted autonomous agent. Candidate test output excludes only the recursively self-building test to avoid an infinite test/build loop; the outer test exercises that loop once.

## Evidence and claims

- `verify <file>` reads local bytes and produces the original v1 receipt.
- `validateReceipt()` checks receipt structure and self-integrity. A self-hash is neither an observer signature nor proof that the referenced file was read.
- `adjudicate <free-text-claim>` always leaves natural-language claims `PROPOSED`, with the circuit open, including when supplied a structurally valid receipt. This intentionally changes v0.1's misleading `EVIDENCE_BACKED`/`CLOSED` result.
- `inspect` freshly reads bounded file bytes, extracts facts, and returns `VERIFIED`, `REFUTED`, `UNVERIFIABLE`, or `UNSUPPORTED` for each structured predicate. Caller-supplied observations are not accepted by this entry point.
- Supported predicates: exact SHA-256, byte length, APK ZIP member presence, DEX class-definition presence, DEX string-table presence, and JSON Pointer equality.
- APK extraction checks ZIP bounds/duplicates/CRC and supported DEX header, table bounds, Adler32 and SHA-1 integrity. It never executes or writes APK members. The extractor's source hash is part of observation identity.
- Static class/string presence does not prove reachability, app behavior, live provider success, signer authenticity, or factual truth. Binary Android manifest semantics and APK signing verification are not implemented.

Example JSON claims:

```json
[{"kind":"json.pointer","pointer":"/result/count","equals":3}]
```

## Operator-authorized execution

Generate a reviewable request first:

```sh
node src/cli.js plan /path/to/NGL_BUS.apk --format apk --claims integration/relay-claims.json --source "$PWD" > request.json
```

The operator reviews the plan's exact artifact identity, source file manifest, requested capabilities, and executable tests. On the operator's trusted side:

```sh
node scripts/authorize.mjs request.json /protected/operator-private.pem > grant.json
```

Then the worker, given only the public key and signed grant:

```sh
node src/cli.js run request.json --grant grant.json --public-key /protected/operator-public.pem --state /protected/runtime-state
node src/cli.js audit /protected/runtime-state/runs/RUN_ID
```

The grant binds the plan, control record, exact capabilities, one-use nonce, and validity window using Ed25519. Model proposals, connector inputs, embedded approval strings, self-declared authority, expired grants, changed inputs, changed source manifests, and replayed grants are rejected. `self-build` requires `artifact.read`, `candidate.write`, and **`trusted-code.execute`**; `verify` requires `artifact.read`.

Revoke an active control, including unused grants:

```sh
node scripts/authorize.mjs request.json /protected/operator-private.pem --revoke > revocation.json
node src/cli.js revoke revocation.json --public-key /protected/operator-public.pem --state /protected/runtime-state
```

Revocation is persistent and signed. A revocation prevents future admission; it does not interrupt an already admitted operation. Identical authority nonces are atomically consumed once per persistent state root. Failed builds consume their grant too. Model and connector records cannot directly invoke the dispatcher; an operator must authorize a distinct executable control.

## Trust and persistence boundaries

The launch configuration's public key, private operator key, installed runtime, and state directory are trusted. A signature proves possession of that key; it does not by itself establish a real-world human identity. Workers must not be able to replace the trust root, delete replay/revocation state, or invoke the signer with a private key.

**This is an application policy gate, not an OS sandbox.** Approved candidate tests execute with host process permissions. They receive a reduced environment and a timeout, but those are not network/filesystem isolation. Arbitrary untrusted code needs an external sandbox before receiving execution grants. No such isolation, automatic privilege elevation, or provider account access is claimed here.

Each run writes exclusive, hash-linked event files and retains observations, grants, stdout/stderr, rejections, and failures. `audit` detects altered links and missing terminal outcomes. It is a self-integrity check: a host writer could rewrite the entire chain or roll back state. Independent anchoring is needed to detect a forged whole history or truncation to an earlier valid terminal head. It is not a crash-recovering transactional database.

## Relay integration

The public mesh anchor is at commit `29619ef46516f759617e100fce6bf501c423fb26`, file `forensics/relay/REFERENCE_ARTIFACT.md`. The APK bytes remain an explicit operator-provided input; they are not checked into this repository. The predicates in `integration/relay-claims.json` are expectations until an actual inspection verifies them.

The companion `ngl-mesh/integration/relay` bridge compiles against recovered Relay Java source. It independently rereads APK identity, appends the RAE report as a system artifact in the original CaseStore, preserves parents and stage state, and grants no authority to imported report claims. It does not replace MethodologyEngine or its five stages.

## Next boundary

This implements byte/static-content verification, structured claims, signed execution admission, one-use grants, revocation, failure evidence, and a self-build/child-verification loop. Remaining work includes an isolated code executor, independently protected provenance storage, Android packaging/device verification, and an explicit proposal/review/candidate-promotion protocol. Multi-format office-document extraction and cross-format semantic equivalence are not implemented.
