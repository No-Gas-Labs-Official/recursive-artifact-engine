# recursive-artifact-engine

**Classification:** SPECIFICATION  
**Type:** design intent only  
**Implementation status:** **not present in this repository**

## What exists

| Path | Role |
|------|------|
| `README.md` | This file (sole content as of last audit) |

There is no source tree, no package manifest, no tests, and no runnable entrypoint.

## Stated intent (from prior description)

An AI artifact-orchestration system where model-generated state is not trusted solely because the model asserts correctness — with independent verification, provenance, and anti-laundering checks for multi-format documents (DOCX / PDF / PPTX / XLSX).

That sentence is a **goal statement**, not evidence of code.

## Relation to Protocol X / EvidenceOS

| Concept | Connection |
|---------|------------|
| Evidence before narrative | Compatible *as an idea* |
| Protocol X gates | **Not implemented here** — do not treat this repo as Protocol X |
| EvidenceOS Inference Engine | Separate repo; also specification-led |

No forced mapping. Shared vocabulary does not equal shared codebase.

## What a stranger should conclude

- This name is reserved for a future or external implementation.
- Cloning this repository will not yield software.
- Effort should go to either (a) implementing a minimal verifier here, or (b) archiving until implementation starts.

## Next executable milestone (if kept active)

1. Add `package.json` or language-equivalent and a single CLI: `verify <artifact>` that hashes a file and writes a JSON receipt.  
2. Add one fixture document and one failing test for “model claim without receipt.”  
3. Until then, status remains **SPECIFICATION**.

## Verification

Repository root listing (2026-09-09): only `README.md`.

---

*A name is not an engine.*
