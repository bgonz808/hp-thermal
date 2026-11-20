"""A fake `gh api` for test.py. State is JSON files in $FAKE:
  statuses_<sha>.json  a head's statuses, newest first (as GitHub lists them)
  pull_<n>.json        a pull request
  checkruns.json       check run names on the head being claimed
  fail_<kind>          make a call fail: statuses, statuses_count (the count read alone),
                       checkruns, pulls_<n>, pulls_<n>_silent (no
                       output at all), post (every POST), post_<sha>, post_once (the next POST);
                       stale_once: the next statuses read misses the newest status
  before_post.json     {sha: [statuses]} landed just before the next POST (another run's)
  after_post.json      {file: content} written after the next successful POST (then removed)
A POST past 1000 statuses of one context on a head fails (422), as on GitHub; an empty SHA is
not found.
A failed call prints the error body and exits 1, as gh does (it applies no --jq to errors).
"""
import json, os, subprocess, sys

fake = os.environ["FAKE"]
args = sys.argv[1:]
assert args and args[0] == "api", args
method, jq, endpoint, fields = "GET", None, None, {}
i = 1
while i < len(args):
    a = args[i]
    if a == "-X":
        method = args[i + 1]; i += 2
    elif a == "--jq":
        jq = args[i + 1]; i += 2
    elif a == "--paginate":
        i += 1
    elif a in ("-f", "-F"):
        k, v = args[i + 1].split("=", 1); fields[k] = v; i += 2
    else:
        endpoint = a; i += 1
parts = endpoint.split("?")[0].split("/")  # repos/o/r/...


def path(name):
    return os.path.join(fake, name)


def failing(kind):
    return os.path.exists(path("fail_" + kind))


def error(status=404):
    sys.stdout.buffer.write(json.dumps({"message": "Not Found", "status": str(status)}).encode())
    sys.exit(1)


def load(name, default):
    return json.load(open(path(name))) if os.path.exists(path(name)) else default


def out(obj):
    data = json.dumps(obj).encode()
    if jq is None:
        sys.stdout.buffer.write(data)
        return
    r = subprocess.run(["jq", "-r", jq], input=data, capture_output=True)
    # as gh on the ubuntu runners prints: LF line ends (Windows jq prints CRLF)
    sys.stdout.buffer.write(r.stdout.replace(bytes([13, 10]), bytes([10])))
    if r.returncode:
        sys.stderr.buffer.write(r.stderr)
        sys.exit(r.returncode)


if method == "POST" and parts[3] == "statuses":
    if failing("post"):
        error(500)
    if failing("post_once"):
        os.remove(path("fail_post_once"))
        error(502)
    sha = parts[4] if len(parts) > 4 else ""
    if not sha:
        error(404)
    if failing("post_" + sha):
        error(500)
    # a status another run posts between this run's read and this post
    before = load("before_post.json", None)
    if before is not None:
        for s, rows in before.items():
            json.dump(rows + load(f"statuses_{s}.json", []), open(path(f"statuses_{s}.json"), "w"))
        os.remove(path("before_post.json"))
    st = load(f"statuses_{sha}.json", [])
    # GitHub: "a limit of 1000 statuses per sha and context within a repository"
    if sum(1 for x in st if x["context"] == fields["context"]) >= 1000:
        error(422)
    creator = "gate-app[bot]" if os.environ.get("GH_TOKEN") == "app-token" else "github-actions[bot]"
    st.insert(0, {"context": fields["context"], "state": fields["state"],
                  "description": fields["description"], "target_url": fields["target_url"],
                  "creator": {"login": creator}})
    json.dump(st, open(path(f"statuses_{sha}.json"), "w"))
    with open(path("posts.log"), "a") as f:
        f.write(f'{sha[:1]}\t{fields["state"]}\t{fields["description"]}\n')
    hook = load("after_post.json", None)
    if hook is not None:
        for name, obj in hook.items():
            json.dump(obj, open(path(name), "w"))
        os.remove(path("after_post.json"))
    sys.exit(0)
if parts[3] == "commits" and parts[5] == "statuses":
    if failing("statuses") or not parts[4]:
        error(502 if parts[4] else 404)
    if failing("statuses_count") and jq and "length" in jq:  # the count read alone
        error(502)
    rows = load(f"statuses_{parts[4]}.json", [])
    if failing("stale_once"):  # a read that does not yet show the newest status
        os.remove(path("fail_stale_once"))
        rows = rows[1:]
    out(rows)
elif parts[3] == "commits" and parts[5] == "check-runs":
    if failing("checkruns"):
        error(502)
    out({"check_runs": [{"name": n} for n in load("checkruns.json", [])]})
elif parts[3] == "pulls":
    n = parts[4]
    if failing(f"pulls_{n}_silent"):  # a failure with nothing on stdout (a dropped connection)
        sys.exit(1)
    if failing("pulls_" + n) or not os.path.exists(path(f"pull_{n}.json")):
        error(404)
    out(load(f"pull_{n}.json", None))
else:
    sys.stderr.write(f"fake gh: unhandled {method} {endpoint}\n")
    sys.exit(2)
