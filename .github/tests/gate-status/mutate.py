"""Breaks each guard of candidate-eval.yml's claim and verdict scripts in turn; test.py must fail
every time. Usage: python3 -I .github/tests/gate-status/mutate.py .github/workflows/candidate-eval.yml
A guard in the shared helpers is broken in both copies (else the helpers-identical check alone
would catch it).
"""
import os, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
WF = sys.argv[1]
src = open(WF, encoding="utf-8").read()
BOTH, FIRST, SECOND = "both", 1, 2
M = [
    # helpers
    ("post: retried", BOTH, "for i in 1 2 3; do", "for i in 1; do"),
    ("post: says what landed", BOTH, 'export GATE_POSTED="$state"', 'export GATE_POSTED="$2"'),
    ("app_status: no App slug is unreadable", BOTH, '[ -n "${APP_SLUG:-}" ] || return 1', ":"),
    ("app_status: the App's statuses only", BOTH, ' and .creator.login == \\"${APP_SLUG}[bot]\\"', ""),
    ("app_status: the newest first", BOTH, '<<< "$(head -n 1 <<< "$rows")"', '<<< "$(tail -n 1 <<< "$rows")"'),
    ("on_head: open", BOTH, '[ "${f[0]}" = open ]', "true"),
    ("on_head: to main", BOTH, '[ "${f[1]}" = main ]', "true"),
    ("on_head: this head", BOTH, '[ "${f[2]}" = "$VERDICT_SHA" ]', "true"),
    ("on_head: every field read", BOTH, '[ "${#f[@]}" -eq 3 ] && ', ""),
    ("newer: run id", BOTH, '[ "$1" -gt "$GITHUB_RUN_ID" ] ||', "false ||"),
    ("newer: attempt", BOTH, '[ "$2" -gt "$GITHUB_RUN_ATTEMPT" ]', "false"),
    ("spoofed: a failed lookup counts", BOTH, "--jq '.check_runs[].name') || return 0", "--jq '.check_runs[].name') || return 1"),
    ("spoofed: case and spacing", BOTH, "| tr '[:upper:]' '[:lower:]' | tr -d ' \\t\\r'", ""),
    ("withdraw: only this pull request's", BOTH, '[ "$owner" = "$VERDICT_PR" ] && ', ""),
    ("withdraw: never a newer run's", BOTH, ' && ! newer "$run" "$attempt"', ""),
    ("withdraw: an unreadable head withdraws", BOTH, "local s state=unknown owner=unknown run=0 attempt=0", "local s state=unknown owner=0 run=0 attempt=0"),
    ("withdraw: nothing to withdraw from a failure", BOTH, '[ "$state" = failure ] && return 0', ":"),
    ("post: from 900 statuses, failure only", BOTH, 'if [ "$n" -ge 900 ]; then', "if false; then"),
    ("post: an unreadable count counts as full", BOTH, "| awk '{ s += $1 } END { print s + 0 }') || n=1000", "| awk '{ s += $1 } END { print s + 0 }') || n=0"),
    ("app_status: this context only", BOTH, '.context == \\"candidate-eval/gate\\" and .creator', ".creator"),
    ("withdraw: a failed post fails", BOTH, '{ echo "::error::could not withdraw #$VERDICT_PR\'s verdict from $1"; return 1; }', "true"),
    # claim
    ("claim: a failed withdrawal fails the run", FIRST, 'withdraw "$BEFORE_SHA" "moved to a new head" || rc=1', 'withdraw "$BEFORE_SHA" "moved to a new head" || true'),
    ("claim: no head before, nothing to withdraw", FIRST, '[ -n "${BEFORE_SHA:-}" ]', "true"),
    ("claim: a push withdraws the head left", FIRST, 'withdraw "$BEFORE_SHA" "moved to a new head" || rc=1', ":"),
    ("claim: a close withdraws", FIRST, '[ "$MERGED" = true ] || withdraw "$VERDICT_SHA" "closed" || rc=1', ":"),
    ("claim: a merge withdraws nothing", FIRST, '[ "$MERGED" = true ] || withdraw', "withdraw"),
    ("claim: off main withdraws", FIRST, 'withdraw "$VERDICT_SHA" "not a pull request to main" || rc=1', ":"),
    ("claim: off main claims nothing", FIRST, 'withdraw "$VERDICT_SHA" "not a pull request to main" || rc=1\n            exit "$rc"', 'withdraw "$VERDICT_SHA" "not a pull request to main" || rc=1'),
    ("claim: a spoof fails", FIRST, 'if spoofed; then\n            post "$VERDICT_SHA" failure', 'if false; then\n            post "$VERDICT_SHA" failure'),
    ("claim: never over a newer run", FIRST, 'if newer "$run" "$attempt" \\', 'if false \\'),
    ("claim: never over its own run's verdict", FIRST, '|| { [ "$run" = "$GITHUB_RUN_ID" ] && [ "$attempt" = "$GITHUB_RUN_ATTEMPT" ]; }; then', "; then"),
    # verdict
    ("verdict: fails with a pass held back at the cap", FIRST, 'if [ "$GATE_POSTED" != "$state" ]; then', "if false; then"),
    ("verdict: the evaluation succeeded", FIRST, '[ "${VERDICT:-}" = success ] && [ "$EVALUATED" = success ]', '[ "${VERDICT:-}" = success ]'),
    ("verdict: a spoof fails", FIRST, 'if spoofed; then\n            state=failure', 'if false; then\n            state=failure'),
    ("verdict: only while open on the head", FIRST, 'if ! on_head "$VERDICT_PR"; then', "if false; then"),
    ("verdict: never over a newer run", FIRST, '            if newer "$run" "$attempt"; then', "            if false; then"),
    ("verdict: an unreadable head fails", FIRST, 'state=failure desc="this head\'s status could not be read; re-run to judge"', ":"),
    ("verdict: the re-check posts without reading", FIRST, 'post "$VERDICT_SHA" failure "closed or moved while judged; its verdict no longer stands" || true', 'withdraw "$VERDICT_SHA" "closed or moved while judged" || true'),
    ("verdict: withdrawn when moved while judged", FIRST, 'if [ "$state" = success ] && ! on_head "$VERDICT_PR"; then', "if false; then"),
]


def nth_replace(s, old, new, n):
    i = -1
    for _ in range(n):
        i = s.index(old, i + 1)
    return s[:i] + new + s[i + len(old):]


out = os.path.join(tempfile.mkdtemp(prefix="gs-mut-"), "candidate-eval.yml")
bad = 0
for name, where, old, new in M:
    count = src.count(old)
    if (where == BOTH and count != 2) or (where != BOTH and count < where):
        print(f"BADPATTERN {name} (count {count})")
        bad += 1
        continue
    m = src.replace(old, new) if where == BOTH else nth_replace(src, old, new, where)
    open(out, "w", encoding="utf-8", newline="\n").write(m)
    r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "test.py"), out, "--quiet"],
                       capture_output=True, text=True)
    caught = r.returncode != 0
    if not caught:
        bad += 1
    first = next((l for l in r.stdout.splitlines() if l.startswith("FAIL")), "")
    print(("killed   " if caught else "SURVIVED ") + name + (f"   <- {first[6:70]}" if caught else ""))
os.remove(out)
print(f"{len(M)} mutants, {bad} survived or bad")
sys.exit(1 if bad else 0)
