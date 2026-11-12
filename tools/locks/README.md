# Frozen tool locks (#241)

A `<tool>.lock` here is a **reviewed, resolved `Cargo.lock` that the producer builds with
instead of the upstream repo's own** — used when upstream's lockfile pins a dependency
version we have deliberately moved off (a yanked release, a version below a soundness fix)
and upstream has not yet moved.

## The rule this encodes

**Non-`--locked` is a *discovery* property, never a *build-output* property.** Exploration
may reason about newer versions; a build never floats. `cargo xtask freeze` performs the one
re-resolution, in one place, and writes the result here — after which the candidate is fully
pinned again and every build is `--locked` against this file. We never bless a floating
resolve; we bless the frozen resolution that discovery proposed.

## How one gets here

```
cargo xtask freeze --tool cargo-vet --repo mozilla/cargo-vet --rev <sha> \
    --update futures-util=0.3.34 --update hermit-abi=0.3.9
```

`freeze` refuses unless every target is safe and the result is an improvement:

- each target version must **exist, be non-yanked, and be past soak** on crates.io;
- the advisory delta is measured **before vs after at one advisory-DB state**, so the diff
  isolates the resolution change from DB drift;
- a resolution that **adds** an advisory instance is **refused** (`--allow-added-advisories`
  records such a trade deliberately — it is a human decision, never a default).

It blesses nothing. The digest still comes from a `build-tools.yml` run over this lock, and
`xtask gate` still evaluates that digest before anything is trusted.

## Why a file, not a TOOLS.lock column

`gate::parse_tools_lock` accepts **exactly five** fields, so a sixth column would make the
line silently **skipped** — a tool left unverified — and bash `read -r name repo rev target
sha` would fold the extra field into `sha`, breaking digest verification. Adding a file
breaks no parser; changing the format breaks several.

## Producer behaviour

`build-tools.yml` checks for `tools/locks/<name>.lock`. If present it clones the pinned rev,
copies this lock over the tree's own, locates the crate **by name** via `cargo metadata`
(never a hardcoded path — two upstreams are monorepos), and runs `cargo install --path …
--locked`. If absent, it uses the normal `cargo install --git --rev --locked` path. Either
way the build is fully pinned; the difference is *whose* resolution is pinned, and this
directory makes ours a committed, diffable artifact.

## Removing one

Delete the file when upstream's own lock catches up (their release moves past the version we
were working around). The next producer run then builds from upstream's resolution again —
fewer deviations to maintain is always the better end state.
