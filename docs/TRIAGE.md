# Triage & issue methodology

How work is classified, prioritized, and closed here — one reference so we don't
re-derive it each time.

## Hierarchy

- **Epic** — a bounded, completable initiative with a single success condition.
  Labeled `epic`, grouped by milestone, children attached as native
  [sub-issues](https://docs.github.com/en/issues/tracking-your-work-with-issues/using-issues/adding-sub-issues).
  An epic closes when its children do.
- **Issue** — one reviewable unit of work: one outcome, objective acceptance
  criteria, its own rollback.
- **Label** — a permanent classifying *dimension* you filter by; it never "closes."

Rule of thumb: can it be *done*? → epic/issue. Is it a *property* many issues
share forever? → label. (A CWE is a weakness *class* — permanent — so it's a
label, never a task.)

## Labels

Namespaced `area / priority / effort / CWE`, per the GitHub convention (cf.
kubernetes `kind/`, `area/`). Labels are flat strings with **no schema** —
nothing enforces one priority per issue — so by convention keep **one priority +
one effort** each. If we ever need enforced single-select or numeric sorting,
that is a job for [Projects v2 custom fields](https://docs.github.com/en/issues/planning-and-tracking-with-projects/understanding-fields),
not labels.

- **Type:** `bug` · `enhancement` · `refactor` · `documentation` · `question`
- **Area:** `security` (root-of-trust) · `hardening` (defense-in-depth, not a fixed vuln) · `rust` · `github_actions` · `dependencies`
- **Weakness class:** `CWE-###` — zero, one, or more per issue; searchable
- **Priority:** `P0-critical` (blocker) · `P1-high` (next up) · `P2-normal` (backlog) · `P3-low` (someday)
- **Effort (Fibonacci):** `effort/1` trivial · `/2` small · `/3` ~half-day · `/5` multi-day · `/8` large (split candidate). Epics are unpointed.
- **Status:** `blocked` — waiting on another issue (name it in the body)

## Priority vs. ordering

`P#` is a coarse band. **Within a band, order by WSJF-lite:** highest
*(value + risk-reduction + unblocks-others) ÷ effort* first — "biggest cut for
least effort." This is SAFe's [Weighted Shortest Job First](https://scaledagileframework.com/wsjf/)
used as a convention, not a maintained numeric field. WSJF is domain-agnostic;
for reach-heavy product work the equivalent is
[RICE](https://www.intercom.com/blog/rice-simple-prioritization-for-product-managers/)
(Reach·Impact·Confidence ÷ Effort). Vulnerabilities (not tasks) are scored with
[CVSS](https://www.first.org/cvss/) separately.

## Definition of done

Every issue carries: **objective** (risk/outcome + trust boundary), **acceptance
criteria** (machine-verifiable where possible), **evidence** (test output, PE
import report, ACL export, signed hash), and a **rollback** that does not
silently weaken a control. Security issues link their CWE.

## Milestones

Release grouping (`v0.2.0`, `backlog`), orthogonal to priority.
