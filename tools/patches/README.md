# Downstream tool patches (patch-carrying, Debian/nixpkgs model)

A `<tool>/*.patch` here is a **reviewed source deviation** the producer applies to the
upstream rev before building — used when upstream's manifest carries technical lag we
must discharge (e.g. a dependency major pinned below every advisory fix) and upstream
has not yet moved. The TOOLS.lock `rev` stays UPSTREAM's commit: provenance remains
theirs; our entire deviation is this committed, diffable artifact.

Rules:
- **Manifest-level patches preferred**; source-code hunks only when a bumped dependency's
  API forces them (keeps the diff reviewable and the shed cheap).
- Every patch dir carries **`patch.json`**: machine-readable intents (what the patch
  ensures), the rev it applies to, reason, refs, author, timestamp, and the shed
  condition.
- **Supersession is fail-closed**: the producer (and candidate builds) run
  `git apply --check` first — the moment upstream touches those manifest lines, the
  apply conflicts loudly with "superseded or conflicting; refresh or drop". A rev bump
  that adopts upstream's own fix deletes the patch dir in the same PR.
- Shedding = deleting the directory, exactly like retiring a `tools/locks/` entry.
  Fewer deviations is always the better end state.
- Patched builds still go through everything else: frozen lock, producer caps gate,
  attestation, 3-axis gate, sign-off. A patch changes WHAT is built, never what is
  verified.
