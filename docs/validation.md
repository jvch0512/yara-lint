# Validation on real data

Counts below were produced by running the tool on public data, not on the synthetic samples in `examples/`.

## Corpus
Neo23x0/signature-base at commit `eb8c53c`, directory `yara/`: 754 files.

## Result
1,747 findings: 1,488 YAR006 (low), 138 YAR004 (medium), 117 YAR007 (low) and 4 info. The first run reported 10,069 findings, so 8,322 were false positives removed by the fixes below.

## What the real data exposed (all fixed, with regression tests)
- Comments inside hex strings (`// ...` and `/* ... */` inside `{ }`) were counted as hex bytes. The tokenizer now skips them.
- Jumps such as `[2-4]` and wildcards such as `??` and `4?` were miscounted when estimating the number of fixed bytes. Only complete two-digit hex pairs now count.

## Limits
The remaining YAR006 findings are style notes (for example missing metadata) that many maintained rulesets choose not to follow. Treat them as hygiene, not as defects.
