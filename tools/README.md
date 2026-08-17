# Prebuilt build tools (#138)

The release build needs four `cargo-*` utilities — `cargo-deny`, `cargo-auditable`,
`cargo-audit`, `cargo-cyclonedx` — that run *during* the build but never ship inside
`hp-thermal.exe`. Compiling them from source cost ~970s (≈75%) of every release build and ran
~1192 dependency build scripts inside the job that produces the signed bytes.

This directory moves that work **out of the release path**: build the tools once, publish the
binaries, and have the release job **download + digest-verify** them instead of recompiling.

## Files

- **`TOOLS.lock`** — the anchor. `name repo rev sha256` per tool. `rev` is the human-edited pin;
  `sha256` is filled from a `build-tools.yml` run and reviewed on commit. The digest is the
  integrity anchor — the `tools` release is only a byte store.
- **`.github/workflows/build-tools.yml`** — the producer (manual dispatch). Builds each tool from
  its pinned rev, publishes the binaries to the `tools` release, and prints the digests to commit.
- **`.github/workflows/tool-updates.yml`** — the hook (weekly). Flags when an upstream is newer
  than a pin.

## Why the tools are stable (and when they are not)

Each tool is pinned by immutable **git rev** (content-addressed) plus **`--locked`** (its entire
dependency tree is frozen at that rev's `Cargo.lock`). Consequences:

- The tools' dependencies **cannot drift**. There is no "a dep got a new version" — the rev pin
  freezes the whole graph.
- Editing `hp-thermal`'s own code or bumping its Rust toolchain does **not** change the tools —
  they are self-contained binaries, independent of the product build.
- The **only** thing that warrants a rebuild is deliberately changing a `rev` in `TOOLS.lock`.

## Dependabot interplay

**Dependabot does not track these tools, and #138 does not change that.** Dependabot's `cargo`
ecosystem updates `Cargo.lock` library dependencies; its `github-actions` ecosystem updates
`uses:` action pins. Neither covers `cargo install --git --rev` tool pins. (`release.yml` has
said "git-rev tool pins are bumped by hand" from the start.)

We keep the git-rev pins deliberately: a rev is content-addressed, so a maintainer-account
compromise can publish a new crates.io version but cannot rewrite a pinned commit. Switching to
crates.io `--version` pins purely to get Dependabot coverage would trade that away; the committed
digest would compensate, but **git-rev + digest is strictly stronger than version + digest**, so
we don't.

`tool-updates.yml` fills the gap Dependabot leaves — a purpose-built weekly check that opens an
issue when an upstream cuts a release newer than the pin.

## Updating a tool

1. `tool-updates.yml` opens/refreshes a tracking issue when an upstream is ahead (or you notice
   a needed security fix yourself).
2. Edit the tool's `rev` in `TOOLS.lock` (a reviewed change).
3. Run **build-tools.yml** (Actions → Build release tools → Run workflow). It recompiles the
   tools off the release critical path and prints the new digest(s).
4. Paste the new `sha256` into `TOOLS.lock` and open a PR. **That commit is the "release" of the
   new tool** — the reviewed digest is what the release job will trust.
5. Merge. Every subsequent release downloads and verifies the new binary; no recompilation.

Because Rust builds are not bit-reproducible, re-running `build-tools.yml` on the *same* rev
yields a *different* digest. Build once per rev and keep that digest; the digest attests "what our
reviewed workflow produced," not a value an outsider can independently re-derive — still a real
anchor, weaker only than a reproducible build.

## Rollout status

- [x] Producer (`build-tools.yml`), anchor (`TOOLS.lock`), hook (`tool-updates.yml`), docs.
- [ ] Populate `TOOLS.lock` digests from the first `build-tools.yml` run.
- [ ] Flip `release.yml` to download + verify the prebuilt tools (removing the `cargo install`
      step). Staged as a follow-up so the digests are real and the change is validated by a
      dry run before the working signing pipeline depends on it.
