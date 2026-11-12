# `policy/eox/` — lifecycle (EoX) records (#376)

- **`records.json`** — one product per environment the workflows run on (hosted runner images),
  the OS under each, and the pinned Rust channel. Each carries an **OpenEoX Core v1.0** document
  under `eox` (OASIS OpenEoX TC; vendor-announced dates or `tba`, never an estimate) inside a
  thin shell: `runs_on` labels, `end_of_active_support` (deprecation start — not an OpenEoX Core
  event), an optional `projection` with its `basis`, and the endoflife.date release to
  cross-check against. The `_doc` array in the file states the field semantics.
- **`schema/core.json`, `schema/meta.json`** — the TC's schema, byte-for-byte as published at
  the CSD01 stage; **`SCHEMA.lock`** pins both by sha256 and says how to bump.

Checked by `cargo xtask eox-check` in PR CI (offline) and weekly in the supply-chain monitor
(with the endoflife.date cross-check and a probe for a newer schema stage).

## Updating

- **Vendor announces a date** (the monitor fails with a cross-check mismatch): replace the `tba`
  in `eox` / `end_of_active_support` with the announced date, delete the now-superseded entry
  from `projection`, bump `last_updated`, cite the announcement in `sources`.
- **Adopting a new runner label**: add its product first; `eox-check` fails on an unknown label.
- **Bumping the toolchain**: the `rust-toolchain/<channel>` product id must match
  `tools/TOOLCHAIN.lock`.
- **A newer schema stage** (monitor warning): read the TC's change log, copy the new files
  verbatim, update all three fields of each `SCHEMA.lock` line in one PR. If the new stage uses a
  JSON Schema keyword the validator does not implement, `eox-check` refuses to evaluate (exit 1)
  until `xtask/src/eox.rs` is extended — deliberately, so a schema change cannot pass unread.
