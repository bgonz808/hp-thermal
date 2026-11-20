"""Scenario tests for candidate-eval.yml's `claim` and `verdict` scripts (the gate's commit
status), run as written in the workflow against a fake `gh api` that keeps statuses, pull
requests and check runs as files. Standard library, bash and jq only.

Usage: python3 -I .github/tests/gate-status/test.py .github/workflows/candidate-eval.yml [--quiet]
Exit 0 when every scenario holds. mutate.py breaks each guard in turn and expects a failure.
"""
import json, os, shutil, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
H = "a" * 40
REPO, FORK = "o/r", "x/r"
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


FAKEBIN = tempfile.mkdtemp(prefix="gs-bin-")
with open(os.path.join(FAKEBIN, "gh"), "w", newline="\n") as f:
    f.write(f'#!/usr/bin/env bash\nexec "{sys.executable}" -I "{os.path.join(HERE, "fake_gh.py")}" "$@"\n')
os.chmod(os.path.join(FAKEBIN, "gh"), 0o755)


def helpers(script):
    a = script.index("# --- gate status helpers")
    b = script.index("# --- end of gate status helpers ---")
    return script[a:b]


def status(state, pr, run, attempt=1, creator="gate-app[bot]", desc=None, url=None):
    return {"context": "candidate-eval/gate", "state": state,
            "description": desc if desc is not None else f"#{pr}: x",
            "target_url": url if url is not None else f"https://github.com/{REPO}/actions/runs/{run}/attempts/{attempt}",
            "creator": {"login": creator}}


def pull(state="open", base="main", head=H, repo=REPO):
    return {"state": state, "base": {"ref": base}, "head": {"sha": head, "repo": {"full_name": repo}}}


class World:
    def __init__(self, statuses=(), pulls=None, checkruns=(), fail=()):
        self.dir = tempfile.mkdtemp(prefix="gs-")
        self.put("statuses.json", list(statuses))
        self.put("checkruns.json", list(checkruns))
        for n, p in (pulls or {}).items():
            self.put(f"pull_{n}.json", p)
        for k in fail:
            open(os.path.join(self.dir, "fail_" + k), "w").close()

    def put(self, name, obj):
        json.dump(obj, open(os.path.join(self.dir, name), "w"))

    def top(self):
        st = [s for s in json.load(open(os.path.join(self.dir, "statuses.json")))
              if s["creator"]["login"] == "gate-app[bot]"]
        return (st[0]["state"], st[0]["description"]) if st else None

    def posts(self):
        p = os.path.join(self.dir, "posts.log")
        return open(p).read().splitlines() if os.path.exists(p) else []

    def run(self, script, pr, run_id, attempt=1, head_repo=REPO, action="opened", merged="false",
            verdict="", evaluated="success"):
        env = dict(os.environ)
        env.update(FAKE=self.dir, PATH=FAKEBIN + os.pathsep + env["PATH"], GITHUB_REPOSITORY=REPO,
                   GITHUB_SERVER_URL="https://github.com", GITHUB_RUN_ID=str(run_id),
                   GITHUB_RUN_ATTEMPT=str(attempt), GH_TOKEN="gh-token", STATUS_TOKEN="app-token",
                   APP_SLUG="gate-app", VERDICT_SHA=H, VERDICT_PR=str(pr), HEAD_REPO=head_repo,
                   ACTION=action, MERGED=merged, VERDICT=verdict, EVALUATED=evaluated)
        r = subprocess.run([BASH, "-c", script], env=env, capture_output=True, text=True)
        return r.returncode

    def close(self):
        shutil.rmtree(self.dir, ignore_errors=True)


def scenarios(claim, verdict):
    """Yields (name, ok, detail)."""
    # F1: a closed same-repo pull request's pass, its head reused by a fork
    w = World([status("success", 1, 100)], {1: pull(state="closed"), 2: pull(repo=FORK)})
    w.run(claim, 1, 200, action="closed")
    after_close = w.top()
    w.run(claim, 2, 300, head_repo=FORK)
    after_claim = w.top()
    w.run(verdict, 2, 300, head_repo=FORK, verdict="failure", evaluated="failure")
    yield "close withdraws the closing pull request's pass", after_close == ("failure", "#1: closed; its verdict no longer stands"), after_close
    yield "a fork reusing a closed head claims it", after_claim == ("pending", "#2: evaluating"), after_claim
    yield "the fork's own verdict stands", w.top()[0] == "failure", w.top()
    w.close()
    # F1 with no close run: the owner is closed, so the fork does not defer
    w = World([status("success", 1, 100)], {1: pull(state="closed"), 2: pull(repo=FORK)})
    w.run(claim, 2, 300, head_repo=FORK)
    yield "no close run: a fork still claims a head whose owner is closed", w.top() == ("pending", "#2: evaluating"), w.top()
    w.close()
    # owner moved off the head, or off main
    for name, p in (("moved head", pull(head="b" * 40)), ("retargeted", pull(base="dev"))):
        w = World([status("success", 1, 100)], {1: p, 2: pull(repo=FORK)})
        w.run(claim, 2, 300, head_repo=FORK)
        yield f"owner {name}: the fork claims", w.top() == ("pending", "#2: evaluating"), w.top()
        w.close()
    # an open same-repo owner keeps the head; the fork posts nothing
    w = World([status("success", 1, 100)], {1: pull(), 2: pull(repo=FORK)})
    w.run(claim, 2, 300, head_repo=FORK)
    w.run(verdict, 2, 300, head_repo=FORK, verdict="failure", evaluated="failure")
    yield "a fork defers to an open same-repo owner", w.top() == ("success", "#1: x") and not w.posts(), (w.top(), w.posts())
    w.close()
    # forks do not defer to forks
    w = World([status("success", 2, 100)], {2: pull(repo=FORK), 3: pull(repo=FORK)})
    w.run(claim, 3, 300, head_repo=FORK)
    yield "a fork does not defer to a fork", w.top() == ("pending", "#3: evaluating"), w.top()
    w.close()
    # a same-repo pull request never defers
    w = World([status("success", 1, 100)], {1: pull(), 3: pull()})
    w.run(claim, 3, 300)
    yield "a same-repo pull request claims", w.top() == ("pending", "#3: evaluating"), w.top()
    w.close()
    # a status from another source is not the App's: no deferral to it
    w = World([status("success", 1, 100, creator="github-actions[bot]")], {1: pull(), 2: pull(repo=FORK)})
    w.run(claim, 2, 300, head_repo=FORK)
    yield "another source's status is ignored", w.top() == ("pending", "#2: evaluating"), w.top()
    w.close()
    # an unparseable App status names no owner
    w = World([status("success", 1, 100, desc="all axes ALLOW or signed", url="https://github.com/o/r/actions/runs/100")],
              {1: pull(), 2: pull(repo=FORK)})
    w.run(claim, 2, 300, head_repo=FORK)
    yield "an unparseable status names no owner", w.top() == ("pending", "#2: evaluating"), w.top()
    w.close()
    # ordering
    w = World([status("success", 1, 500)], {1: pull()})
    w.run(verdict, 1, 400, verdict="failure", evaluated="failure")
    w.run(claim, 1, 400)
    yield "an older run never overwrites a newer one", w.top() == ("success", "#1: x") and not w.posts(), (w.top(), w.posts())
    w.close()
    w = World([status("success", 1, 500, attempt=2)], {1: pull()})
    w.run(verdict, 1, 500, attempt=1, verdict="failure", evaluated="failure")
    w.run(claim, 1, 500, attempt=1)
    yield "an older attempt of the run never overwrites a newer one", w.top() == ("success", "#1: x") and not w.posts(), (w.top(), w.posts())
    w.close()
    w = World([status("failure", 1, 500, attempt=1)], {1: pull()})
    w.run(claim, 1, 500, attempt=1)
    same = w.top()
    w.run(claim, 1, 500, attempt=2)
    yield "a run's claim never overwrites its own verdict", same == ("failure", "#1: x"), same
    yield "a re-run attempt claims", w.top() == ("pending", "#1: evaluating"), w.top()
    w.close()
    # verdict
    w = World([status("pending", 1, 500)], {1: pull()})
    w.run(verdict, 1, 500, verdict="success", evaluated="success")
    yield "a pass is posted", w.top() == ("success", "#1: all axes ALLOW or signed"), w.top()
    w.close()
    w = World([status("pending", 1, 500)], {1: pull()})
    w.run(verdict, 1, 500, verdict="success", evaluated="failure")
    yield "a pass needs the evaluation to have succeeded", w.top()[0] == "failure", w.top()
    w.close()
    w = World([status("pending", 1, 500)], {1: pull()})
    w.run(verdict, 1, 500, verdict="Success", evaluated="success")
    yield "only the exact word passes", w.top()[0] == "failure", w.top()
    w.close()
    w = World([status("pending", 1, 500)], {1: pull()}, fail=["statuses"])
    w.run(verdict, 1, 500, verdict="success", evaluated="success")
    yield "an unreadable status is answered with failure", w.posts() and w.posts()[-1].startswith("failure"), w.posts()
    w.close()
    w = World([status("pending", 1, 500)], {1: pull()})
    w.put("after_post.json", {"pull_1.json": pull(state="closed")})
    w.run(verdict, 1, 500, verdict="success", evaluated="success")
    yield "closed while judged: the pass is withdrawn", w.top() == ("failure", "#1: closed or moved while judged"), w.top()
    w.close()
    w = World([status("pending", 1, 500)], {1: pull(head="b" * 40)})
    w.run(verdict, 1, 500, verdict="success", evaluated="success")
    yield "a moved pull request posts nothing", w.top() == ("pending", "#1: x") and not w.posts(), (w.top(), w.posts())
    w.close()
    w = World([status("pending", 1, 800)], {1: pull(), 2: pull(repo=FORK)})
    w.run(verdict, 2, 900, head_repo=FORK, verdict="success", evaluated="success")
    yield "a fork's verdict defers to a same-repo owner still evaluating", w.top() == ("pending", "#1: x") and not w.posts(), (w.top(), w.posts())
    w.close()
    # spoofs
    for name, kw in (("a spoof check run", {"checkruns": ["Candidate-Eval / Gate"]}), ("a failed spoof lookup", {"fail": ["checkruns"]})):
        w = World([], {1: pull()}, **kw)
        rc = w.run(claim, 1, 500)
        yield f"claim: {name} fails the head", w.top() is not None and w.top()[0] == "failure" and rc != 0, (w.top(), rc)
        w.close()
        w = World([status("pending", 1, 500)], {1: pull()}, **kw)
        w.run(verdict, 1, 500, verdict="success", evaluated="success")
        yield f"verdict: {name} fails the head", w.top()[0] == "failure", w.top()
        w.close()
    # closes
    w = World([status("success", 1, 100)], {1: pull(), 2: pull(state="closed", repo=FORK)})
    w.run(claim, 2, 300, head_repo=FORK, action="closed")
    yield "closing another pull request leaves the owner's status", w.top() == ("success", "#1: x") and not w.posts(), (w.top(), w.posts())
    w.close()
    w = World([status("success", 1, 100)], {1: pull(state="closed")})
    w.run(claim, 1, 300, action="closed", merged="true")
    yield "a merge withdraws nothing", not w.posts(), w.posts()
    w.close()
    w = World([status("success", 2, 100)], {1: pull(state="closed")}, fail=["statuses"])
    w.run(claim, 1, 300, action="closed")
    yield "a close that cannot read the head withdraws", w.posts() and w.posts()[-1].startswith("failure"), w.posts()
    w.close()


def main():
    wf = sys.argv[1]
    quiet = "--quiet" in sys.argv
    claim, verdict = scripts(wf)
    ok = helpers(claim) == helpers(verdict)
    if not quiet:
        print(("ok    " if ok else "FAIL  ") + "the helpers are identical in claim and verdict")
    failed = 0 if ok else 1
    for name, good, detail in scenarios(claim, verdict):
        if not good:
            failed += 1
        if not quiet or not good:
            print(("ok    " if good else "FAIL  ") + name + ("" if good else f"   {detail}"))
    print(f"{failed} failed")
    shutil.rmtree(FAKEBIN, ignore_errors=True)
    sys.exit(1 if failed else 0)


main()
