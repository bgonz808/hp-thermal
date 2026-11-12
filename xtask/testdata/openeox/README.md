# OpenEoX Core v1.0 conformance corpus (vendored, verbatim)

Test vectors for the OpenEoX Core Schema v1.0 validator in `xtask/src/eox.rs` (#376), taken
byte-for-byte from the OASIS OpenEoX TC repository at commit
`fd771fe484a37e1cd5ed4e2e422e4d0a45313a5d` (2026-07-13, the CSD01 editorial state):

- `examples/` — `eox-core-v-1-0/examples/*.json`
- `validator-data/` — `eox-core-v-1-0/test/validator/data/` (`testcases.json` is the TC's own
  manifest of which vector fails which test in section 7 of the specification)

`xtask`'s unit tests run every vector through the committed schema copy
(`supply-chain/policy/eox/schema/core.json`) and assert the TC's verdicts: mandatory-test
failures are errors, recommended-test failures are warnings on a still-valid document,
informative-test failures are notices. The leap-second vector (7.1.2 #02) is included: the TC's
own Python harness skips it for lack of library support, `testcases.json` still marks it invalid,
and the in-tree parser rejects leap seconds as section 4.1.6 requires.

Content governed by the OASIS IPR Policy (Non-Assertion mode) as stated in the repository's
LICENSE.md: https://github.com/oasis-tcs/openeox/blob/main/LICENSE.md
