"""Scenario tests for candidate-eval.yml's `claim` and `verdict` scripts (the gate's commit
status), run as written in the workflow against a fake `gh api` (fake_gh.py) that keeps each
head's statuses, the pull requests and the check runs as files. Standard library, bash and jq.

Usage: python3 -I .github/tests/gate-status/test.py .github/workflows/candidate-eval.yml [--quiet]
Exit 0 when every scenario holds. mutate.py breaks each guard in turn and expects a failure.

What is not here: the jobs' `if:` conditions and the trigger (GitHub evaluates those). The
scripts do not rely on them for safety: `claim` reads the action and base itself, and `verdict`
posts only for a pull request open to main on its head.
"""
import json, os, shutil, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
H, H2 = "a" * 40, "b" * 40
REPO = "o/r"
BASH = shutil.which("bash")  # on Windows, Git Bash: never System32's WSL bash
assert BASH and "system32" not in BASH.lower(), BASH
assert shutil.which("jq"), "jq is required"


def step_run(text, name):
    """The `run: |` block of the step whose name starts with `name`, dedented."""
    lines = text.split("\n")
    i = next(k for k, l in enumerate(lines) if l.lstrip().startswith(f"- name: {name}"))
    i = next(k for k in range(i + 1, len(lines)) if lines[k].strip() == "run: |")
    key = len(lines[i]) - len(lines[i].lstrip())
    body = []
    for l in lines[i + 1:]:
        if l.strip() and len(l) - len(l.lstrip()) <= key:
            break
        body.append(l)
    while body and not body[-1].strip():
        body.pop()
    ind = min(len(l) - len(l.lstrip()) for l in body if l.strip())
    return "\n".join(l[ind:] for l in body) + "\n"


def scripts(wf):
    text = open(wf, encoding="utf-8").read()
    return step_run(text, "Claim the head"), step_run(text, "Post the verdict")


def helpers(script):
    return script[script.index("# --- gate status helpers"):script.index("# --- end of gate status helpers ---")]


FAKEBIN = tempfile.mkdtemp(prefix="gs-bin-")
with open(os.path.join(FAKEBIN, "gh"), "w", newline="\n") as f:
    f.write(f'#!/usr/bin/env bash\nexec "{sys.executable}" -I "{os.path.join(HERE, "fake_gh.py")}" "$@"\n')
os.chmod(os.path.join(FAKEBIN, "gh"), 0o755)


def status(state, pr, run, attempt=1, creator="gate-app[bot]", desc=None, url=None):
    return {"context": "candidate-eval/gate", "state": state,
            "description": desc if desc is not None else f"#{pr}: x",
            "target_url": url if url is not None else f"https://github.com/{REPO}/actions/runs/{run}/attempts/{attempt}",
            "creator": {"login": creator}}


def pull(state="open", base="main", head=H):
    return {"state": state, "base": {"ref": base}, "head": {"sha": head}}


class World:
    def __init__(self, statuses=None, pulls=None, checkruns=(), fail=()):
        self.dir = tempfile.mkdtemp(prefix="gs-")
        for sha, st in (statuses or {}).items():
            self.put(f"statuses_{sha}.json", list(st))
        self.put("checkruns.json", list(checkruns))
        for n, p in (pulls or {}).items():
            self.put(f"pull_{n}.json", p)
        for k in fail:
            open(os.path.join(self.dir, "fail_" + k), "w").close()

    def put(self, name, obj):
        json.dump(obj, open(os.path.join(self.dir, name), "w"))

    def top(self, sha=H):
        p = os.path.join(self.dir, f"statuses_{sha}.json")
        st = [s for s in (json.load(open(p)) if os.path.exists(p) else [])
              if s["creator"]["login"] == "gate-app[bot]" and s["context"] == "candidate-eval/gate"]
        return (st[0]["state"], st[0]["description"]) if st else None

    def posts(self):
        p = os.path.join(self.dir, "posts.log")
        return open(p).read().splitlines() if os.path.exists(p) else []

    def run(self, script, pr, run_id, attempt=1, sha=H, before="", base="main", action="opened",
            merged="false", verdict="", evaluated="success", app_slug="gate-app"):
        env = dict(os.environ)
        env.update(FAKE=self.dir, PATH=FAKEBIN + os.pathsep + env["PATH"], GITHUB_REPOSITORY=REPO,
                   GITHUB_SERVER_URL="https://github.com", GITHUB_RUN_ID=str(run_id),
                   GITHUB_RUN_ATTEMPT=str(attempt), GH_TOKEN="gh-token", STATUS_TOKEN="app-token",
                   APP_SLUG=app_slug, VERDICT_SHA=sha, VERDICT_PR=str(pr), BEFORE_SHA=before,
                   BASE_REF=base, ACTION=action, MERGED=merged, VERDICT=verdict, EVALUATED=evaluated)
        return subprocess.run([BASH, "-c", script], env=env, capture_output=True, text=True).returncode

    def close(self):
        shutil.rmtree(self.dir, ignore_errors=True)


PASS = ("success", "#1: x")


def scenarios(claim, verdict):
    """Yields (name, ok, detail)."""
    # --- a verdict stands only while its pull request is open to main on that head ---
    # #1 passes on H; #2 (any pull request) has H too; #1 pushes H -> H2
    w = World({H: [status("success", 1, 100)]}, {1: pull(head=H2), 2: pull()})
    w.run(claim, 1, 200, sha=H2, before=H, action="synchronize")
    yield "a push withdraws the pass from the head left", w.top(H) == ("failure", "#1: moved to a new head; its verdict no longer stands"), w.top(H)
    yield "a push claims the new head", w.top(H2) == ("pending", "#1: evaluating"), w.top(H2)
    w.close()
    w = World({H: [status("success", 3, 100)]}, {1: pull(head=H2), 3: pull()})
    w.run(claim, 1, 200, sha=H2, before=H, action="synchronize")
    yield "a push leaves another pull request's status alone", w.top(H) == ("success", "#3: x"), w.top(H)
    w.close()
    w = World({H: [status("success", 1, 300)]}, {1: pull()})
    w.run(claim, 1, 200, sha=H2, before=H, action="synchronize")
    yield "a delayed push run leaves a newer run's status alone", w.top(H) == ("success", "#1: x"), w.top(H)
    w.close()
    w = World({H: [status("success", 1, 100)]}, {1: pull(head=H2)}, fail=["statuses"])
    w.run(claim, 1, 200, sha=H2, before=H, action="synchronize")
    yield "a push that cannot read the head it left withdraws", w.top(H) is not None and w.top(H)[0] == "failure", w.top(H)
    w.close()
    # a close
    w = World({H: [status("success", 1, 100)]}, {1: pull(state="closed")})
    rc = w.run(claim, 1, 200, action="closed")
    yield "a close withdraws the pass", w.top() == ("failure", "#1: closed; its verdict no longer stands") and rc == 0, (w.top(), rc)
    w.close()
    w = World({H: [status("success", 3, 100)]}, {1: pull(state="closed"), 3: pull()})
    w.run(claim, 1, 200, action="closed")
    yield "a close leaves another pull request's status alone", w.top() == ("success", "#3: x") and not w.posts(), (w.top(), w.posts())
    w.close()
    w = World({H: [status("success", 1, 100)]}, {1: pull(state="closed")})
    w.run(claim, 1, 200, action="closed", merged="true")
    yield "a merge withdraws nothing", not w.posts(), w.posts()
    w.close()
    w = World({H: [status("success", 3, 100)]}, {1: pull(state="closed")}, fail=["statuses"])
    w.run(claim, 1, 200, action="closed")
    yield "a close that cannot read the head withdraws", w.posts() and w.posts()[-1].split("\t")[1] == "failure", w.posts()
    w.close()
    # leaving main
    w = World({H: [status("success", 1, 100)]}, {1: pull(base="dev")})
    w.run(claim, 1, 200, base="dev", action="edited")
    yield "a retarget away from main withdraws the pass", w.top() == ("failure", "#1: not a pull request to main; its verdict no longer stands"), w.top()
    w.close()
    w = World({H: [status("success", 1, 100)]}, {1: pull(state="closed", base="dev")})
    w.run(claim, 1, 200, base="dev", action="closed")
    yield "a close off main withdraws the pass", w.top()[0] == "failure", w.top()
    w.close()
    w = World({H: [status("success", 1, 100)]}, {1: pull(base="dev", head=H2)})
    w.run(claim, 1, 200, sha=H2, before=H, base="dev", action="synchronize")
    yield "a push off main withdraws from the head left", w.top(H)[0] == "failure" and w.top(H2) is None, (w.top(H), w.top(H2))
    w.close()
    w = World({}, {1: pull(base="dev")})
    w.run(claim, 1, 200, base="dev")
    yield "a pull request off main claims nothing", w.top() is None and not w.posts(), w.posts()
    w.close()
    # --- no pull request defers to another: the latest evaluation of a head stands ---
    w = World({H: [status("success", 1, 100)]}, {1: pull(), 2: pull()})
    w.run(claim, 2, 300)
    claimed = w.top()
    w.run(verdict, 2, 300, verdict="failure", evaluated="failure")
    yield "another pull request on the head claims it", claimed == ("pending", "#2: evaluating"), claimed
    yield "its own verdict stands", w.top() == ("failure", "#2: blocked or not evaluated: see the run"), w.top()
    w.close()
    # status sources and formats
    w = World({H: [status("success", 1, 100, creator="github-actions[bot]")]}, {1: pull()})
    w.run(claim, 1, 50)
    yield "another source's status is not the App's", w.top() == ("pending", "#1: evaluating"), w.top()
    w.close()
    w = World({H: [status("success", 1, 100, desc="all axes ALLOW or signed", url="https://github.com/o/r/actions/runs/100")]},
              {1: pull(state="closed")})
    w.run(claim, 1, 200, action="closed")
    yield "an unparseable status names no pull request (nothing to withdraw)", not w.posts(), w.posts()
    w.close()
    # --- order: nothing overwrites a newer run's status ---
    w = World({H: [status("success", 1, 500)]}, {1: pull()})
    w.run(verdict, 1, 400, verdict="failure", evaluated="failure")
    w.run(claim, 1, 400)
    yield "an older run never overwrites a newer one", w.top() == PASS and not w.posts(), (w.top(), w.posts())
    w.close()
    w = World({H: [status("success", 1, 500, attempt=2)]}, {1: pull()})
    w.run(verdict, 1, 500, attempt=1, verdict="failure", evaluated="failure")
    w.run(claim, 1, 500, attempt=1)
    yield "an older attempt of the run never overwrites a newer one", w.top() == PASS and not w.posts(), (w.top(), w.posts())
    w.close()
    # several App statuses on one head: the newest is the head's
    w = World({H: [status("pending", 1, 500), status("success", 1, 100)]}, {1: pull()})
    w.run(claim, 1, 400)
    yield "the newest status is read (a claim)", not w.posts(), w.posts()
    w.close()
    w = World({H: [status("failure", 2, 300), status("success", 1, 100)]}, {1: pull(state="closed"), 2: pull()})
    w.run(claim, 1, 400, action="closed")
    yield "the newest status is read (a close)", not w.posts(), w.posts()
    w.close()
    w = World({H: [status("failure", 1, 500, attempt=1)]}, {1: pull()})
    w.run(claim, 1, 500, attempt=1)
    same = w.top()
    w.run(claim, 1, 500, attempt=2)
    yield "a run's claim never overwrites its own verdict", same == ("failure", "#1: x"), same
    yield "a re-run attempt claims", w.top() == ("pending", "#1: evaluating"), w.top()
    w.close()
    # --- the verdict ---
    w = World({H: [status("pending", 1, 500)]}, {1: pull()})
    w.run(verdict, 1, 500, verdict="success", evaluated="success")
    yield "a pass is posted", w.top() == ("success", "#1: all axes ALLOW or signed"), w.top()
    w.close()
    for name, kw in (("a pass needs the evaluation to have succeeded", dict(verdict="success", evaluated="failure")),
                     ("only the exact word passes", dict(verdict="Success", evaluated="success")),
                     ("no verdict handed on is a failure", dict(verdict="", evaluated="success"))):
        w = World({H: [status("pending", 1, 500)]}, {1: pull()})
        w.run(verdict, 1, 500, **kw)
        yield name, w.top()[0] == "failure", w.top()
        w.close()
    w = World({H: [status("pending", 1, 500)]}, {1: pull()}, fail=["statuses"])
    w.run(verdict, 1, 500, verdict="success", evaluated="success")
    yield "an unreadable status is answered with failure", w.posts() and w.posts()[-1].split("\t")[1:] == ["failure", "#1: this head's status could not be read; re-run to judge"], w.posts()
    w.close()
    for name, after in (("closed", pull(state="closed")), ("pushed", pull(head=H2)), ("retargeted", pull(base="dev"))):
        w = World({H: [status("pending", 1, 500)]}, {1: pull()})
        w.put("after_post.json", {"pull_1.json": after})
        w.run(verdict, 1, 500, verdict="success", evaluated="success")
        yield f"{name} while judged: the pass is withdrawn", w.top() == ("failure", "#1: closed or moved while judged; its verdict no longer stands"), w.top()
        w.close()
    for name, p in (("a moved", pull(head=H2)), ("a closed", pull(state="closed")), ("a retargeted", pull(base="dev"))):
        w = World({H: [status("pending", 1, 500)]}, {1: p})
        w.run(verdict, 1, 500, verdict="success", evaluated="success")
        yield f"{name} pull request posts nothing", w.top() == ("pending", "#1: x") and not w.posts(), (w.top(), w.posts())
        w.close()
    for kind in ("pulls_1", "pulls_1_silent"):
        w = World({H: [status("pending", 1, 500)]}, {1: pull()}, fail=[kind])
        rc = w.run(verdict, 1, 500, verdict="success", evaluated="success")
        yield f"an unreadable pull request posts nothing ({kind})", not w.posts() and rc == 0, (w.posts(), rc)
        w.close()
    w = World({H: [status("pending", 1, 500)]}, {1: pull()})
    w.put("after_post.json", {"fail_pulls_1_silent": 1})
    w.run(verdict, 1, 500, verdict="success", evaluated="success")
    yield "a pull request unreadable after the pass: the pass is withdrawn", w.top() is not None and w.top()[0] == "failure", w.top()
    w.close()
    # --- posting ---
    w = World({}, {1: pull()}, fail=["post_once"])
    rc = w.run(claim, 1, 500)
    yield "a failed post is retried", w.top() == ("pending", "#1: evaluating") and rc == 0, (w.top(), rc)
    w.close()
    w = World({H: [status("success", 1, 100)]}, {1: pull(state="closed")}, fail=["post"])
    rc = w.run(claim, 1, 200, action="closed")
    yield "a withdrawal that cannot post fails the run", rc != 0, rc
    w.close()
    w = World({H: [status("success", 1, 100)]}, {1: pull(head=H2)}, fail=["post_" + H])
    rc = w.run(claim, 1, 200, sha=H2, before=H, action="synchronize")
    yield "a push whose withdrawal cannot post fails the run", rc != 0 and w.top(H2) == ("pending", "#1: evaluating"), (rc, w.top(H2))
    w.close()
    w = World({}, {1: pull()})
    rc = w.run(claim, 1, 200, before="", action="synchronize")
    yield "a push with no head before it withdraws nothing", rc == 0 and all(not l.startswith("\t") for l in w.posts()), (rc, w.posts())
    w.close()
    other = dict(status("success", 1, 900), context="other/context")
    w = World({H: [other, status("pending", 1, 500)]}, {1: pull()})
    w.run(claim, 1, 600)
    yield "the App's statuses of another context are not the head's", w.top() == ("pending", "#1: evaluating"), w.top()
    w.close()
    # --- GitHub keeps at most 1000 statuses per head and context: from 900 on, failure only ---
    filler = lambda n: [status("failure", 9, 1, creator="github-actions[bot]")] * n
    TOOMANY = ("failure", "#1: too many statuses on this head; push a new commit")
    w = World({H: [status("pending", 1, 500)] + filler(899)}, {1: pull()})
    rc = w.run(verdict, 1, 500, verdict="success", evaluated="success")
    yield "at 900 statuses a pass becomes failure", w.top() == TOOMANY, w.top()
    yield "and the verdict job fails with it", rc != 0, rc
    w.close()
    # no App slug: the App's statuses cannot be told apart, so the head reads as unreadable
    w = World({H: [status("success", 1, 100)]}, {1: pull(state="closed")})
    w.run(claim, 1, 200, action="closed", app_slug="")
    yield "without the App's slug a close still withdraws", w.posts() and w.posts()[-1].split("\t")[1] == "failure", w.posts()
    w.close()
    w = World({H: [status("pending", 1, 500)] + filler(898)}, {1: pull()})
    w.run(verdict, 1, 500, verdict="success", evaluated="success")
    passed = w.top()
    w.put("pull_1.json", pull(state="closed"))
    w.run(claim, 1, 600, action="closed")
    yield "below 900 a pass is posted", passed == ("success", "#1: all axes ALLOW or signed"), passed
    yield "past it, the withdrawal still lands", w.top()[0] == "failure", w.top()
    w.close()
    w = World({H: filler(900)}, {1: pull()})
    w.run(claim, 1, 500)
    yield "at 900 statuses a claim is failure", w.top() == TOOMANY, w.top()
    w.close()
    w = World({H: [status("pending", 1, 500)]}, {1: pull()}, fail=["statuses_count"])
    w.run(verdict, 1, 500, verdict="success", evaluated="success")
    yield "a count that cannot be read counts as full", w.top() == TOOMANY, w.top()
    w.close()
    # an attacker's pull request off main, pushing back and forth, adds no statuses to a head
    # whose latest is already a failure
    w = World({H: [status("failure", 2, 100)]}, {2: pull(base="dev")})
    for k in range(10):
        a, b = (H, H2) if k % 2 else (H2, H)
        w.run(claim, 2, 200 + k, sha=a, before=b, base="dev", action="synchronize")
    yield "pushes off main add nothing to a failed head", not w.posts(), w.posts()
    w.close()
    # the verdict's re-check posts without reading: a read that missed its own pass, seeing the
    # move's withdrawal on top, would take it for newer and leave the pass
    w = World({H: [status("pending", 1, 500)]}, {1: pull()})
    w.put("before_post.json", {H: [status("failure", 1, 600)]})
    w.put("after_post.json", {"pull_1.json": pull(head=H2), "fail_stale_once": 1})
    w.run(verdict, 1, 500, verdict="success", evaluated="success")
    yield "a pass is withdrawn without trusting a second read", w.top() == ("failure", "#1: closed or moved while judged; its verdict no longer stands"), w.top()
    w.close()
    # --- spoofs ---
    for name, kw in (("a spoof check run", {"checkruns": ["Candidate-Eval / Gate"]}), ("a failed spoof lookup", {"fail": ["checkruns"]})):
        w = World({}, {1: pull()}, **kw)
        rc = w.run(claim, 1, 500)
        yield f"claim: {name} fails the head", w.top() is not None and w.top()[0] == "failure" and rc != 0, (w.top(), rc)
        w.close()
        w = World({H: [status("pending", 1, 500)]}, {1: pull()}, **kw)
        w.run(verdict, 1, 500, verdict="success", evaluated="success")
        yield f"verdict: {name} fails the head", w.top()[0] == "failure", w.top()
        w.close()


def main():
    wf = sys.argv[1]
    quiet = "--quiet" in sys.argv
    claim, verdict = scripts(wf)
    ok = helpers(claim) == helpers(verdict)
    if not quiet:
        print(("ok    " if ok else "FAIL  ") + "the helpers are identical in claim and verdict")
    failed, n = (0 if ok else 1), 1
    for name, good, detail in scenarios(claim, verdict):
        n += 1
        if not good:
            failed += 1
        if not quiet or not good:
            print(("ok    " if good else "FAIL  ") + name + ("" if good else f"   {detail}"))
    print(f"{n} checks, {failed} failed")
    shutil.rmtree(FAKEBIN, ignore_errors=True)
    sys.exit(1 if failed else 0)


main()
