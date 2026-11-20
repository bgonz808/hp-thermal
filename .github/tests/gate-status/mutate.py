"""Breaks each guard of candidate-eval.yml's claim and verdict scripts in turn; test.py must fail
every time. Usage: python3 -I .github/tests/gate-status/mutate.py .github/workflows/candidate-eval.yml
"""
import os, subprocess, sys, tempfile
HERE = os.path.dirname(os.path.abspath(__file__))
WF = sys.argv[1]
src = open(WF, encoding="utf-8").read()
ALL, FIRST, SECOND = "all", 1, 2
M = [
    ("defer: owner must be same-repo, open, on the head", ALL, '&& on_head "$1" same-repo', "&& true"),
    ("on_head: from this repository", ALL, '{ [ "${2:-}" != same-repo ] || [ "${f[3]}" = "$GITHUB_REPOSITORY" ]; }', "true"),
    ("on_head: open", ALL, '[ "${f[0]}" = open ]', "true"),
    ("on_head: to main", ALL, '[ "${f[1]}" = main ]', "true"),
    ("on_head: this head", ALL, '[ "${f[2]}" = "$VERDICT_SHA" ]', "true"),
    ("defer: only a fork defers", ALL, '[ "$HEAD_REPO" != "$GITHUB_REPOSITORY" ] && ', ""),
    ("newer: run id", ALL, '[ "$1" -gt "$GITHUB_RUN_ID" ] ||', "false ||"),
    ("newer: attempt", ALL, '[ "$2" -gt "$GITHUB_RUN_ATTEMPT" ]', "false"),
    ("app_status: the App's statuses only", ALL, ' and .creator.login == \\"${APP_SLUG}[bot]\\"', ""),
    ("spoofed: a failed lookup counts", ALL, "--jq '.check_runs[].name') || return 0", "--jq '.check_runs[].name') || return 1"),
    ("close: withdraws its own verdict", FIRST, 'if [ "$owner" = "$VERDICT_PR" ] || [ "$owner" = unknown ]; then', "if false; then"),
    ("close: an unreadable head withdraws", FIRST, "owner=unknown", "owner=0"),
    ("close: a merge withdraws nothing", FIRST, '[ "$MERGED" = true ] && exit 0', ":"),
    ("claim: never over its own run's verdict", FIRST, '|| { [ "$run" = "$GITHUB_RUN_ID" ] && [ "$attempt" = "$GITHUB_RUN_ATTEMPT" ]; }; then', "; then"),
    ("claim: a fork defers", FIRST, 'if defers_to "$owner"; then', "if false; then"),
    ("verdict: a fork defers", SECOND, 'if defers_to "$owner"; then', "if false; then"),
    ("verdict: never over a newer run", FIRST, 'if newer "$run" "$attempt"; then', "if false; then"),
    ("verdict: the evaluation succeeded", FIRST, '[ "${VERDICT:-}" = success ] && [ "$EVALUATED" = success ]', '[ "${VERDICT:-}" = success ]'),
    ("verdict: an unreadable head fails", FIRST, 'state=failure desc="this head\'s status could not be read; re-run to judge"', ":"),
    ("verdict: withdrawn when closed while judged", FIRST, 'if [ "$state" = success ] && ! on_head "$VERDICT_PR"; then', "if false; then"),
    ("verdict: a spoof fails", FIRST, 'if spoofed; then\n            state=failure', 'if false; then\n            state=failure'),
    ("verdict: only while open on the head", FIRST, 'if ! on_head "$VERDICT_PR"; then', "if false; then"),
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
    if count == 0 or (where == ALL and count != 2) or (where == FIRST and count < 1) or (where == SECOND and count < 2):
        print(f"BADPATTERN {name} (count {count})"); bad += 1; continue
    m = src.replace(old, new) if where == ALL else nth_replace(src, old, new, where)
    open(out, "w", encoding="utf-8", newline="\n").write(m)
    r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "test.py"), out, "--quiet"],
                       capture_output=True, text=True)
    caught = r.returncode != 0
    if not caught:
        bad += 1
    first = next((l for l in r.stdout.splitlines() if l.startswith("FAIL")), "")
    print(("killed   " if caught else "SURVIVED ") + name + (f"   <- {first[6:70]}" if caught else ""))
os.remove(out)
print(f"{bad} survived or bad")
sys.exit(1 if bad else 0)
