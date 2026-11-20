"""A fake `gh api` for test.py: statuses, pull requests and check runs are JSON files in $FAKE;
`fail_<kind>` files make a lookup fail; `after_post.json` rewrites files after the next POST."""
import json, os, subprocess, sys
fake = os.environ["FAKE"]
args = sys.argv[1:]
assert args and args[0] == "api", args
method, jq, endpoint, fields = "GET", None, None, {}
i = 1
while i < len(args):
    a = args[i]
    if a == "-X": method = args[i + 1]; i += 2
    elif a == "--jq": jq = args[i + 1]; i += 2
    elif a == "--paginate": i += 1
    elif a in ("-f", "-F"):
        k, v = args[i + 1].split("=", 1); fields[k] = v; i += 2
    else: endpoint = a; i += 1
path = endpoint.split("?")[0]
parts = path.split("/")  # repos/o/r/...
def fail(kind):
    return os.path.exists(os.path.join(fake, "fail_" + kind))
def out(obj):
    data = json.dumps(obj)
    if jq is None:
        sys.stdout.buffer.write(data.encode()); return
    r = subprocess.run(["jq", "-r", jq], input=data.encode(), capture_output=True)
    # as gh on the ubuntu runners prints: LF line ends (Windows jq prints CRLF)
    sys.stdout.buffer.write(r.stdout.replace(bytes([13, 10]), bytes([10])))
    if r.returncode: sys.stderr.buffer.write(r.stderr); sys.exit(r.returncode)
def load(name, default):
    p = os.path.join(fake, name)
    return json.load(open(p)) if os.path.exists(p) else default
if method == "POST" and parts[3] == "statuses":
    st = load("statuses.json", [])
    creator = "gate-app[bot]" if os.environ.get("GH_TOKEN") == "app-token" else "github-actions[bot]"
    st.insert(0, {"context": fields["context"], "state": fields["state"],
                  "description": fields["description"], "target_url": fields["target_url"],
                  "creator": {"login": creator}})
    json.dump(st, open(os.path.join(fake, "statuses.json"), "w"))
    with open(os.path.join(fake, "posts.log"), "a") as f:
        f.write(f'{fields["state"]}\t{fields["description"]}\n')
    hook = os.path.join(fake, "after_post.json")
    if os.path.exists(hook):
        for name, obj in json.load(open(hook)).items():
            json.dump(obj, open(os.path.join(fake, name), "w"))
        os.remove(hook)
    sys.exit(0)
if parts[3] == "commits" and parts[5] == "statuses":
    if fail("statuses"): sys.exit(1)
    out(load("statuses.json", []))
elif parts[3] == "commits" and parts[5] == "check-runs":
    if fail("checkruns"): sys.exit(1)
    out({"check_runs": [{"name": n} for n in load("checkruns.json", [])]})
elif parts[3] == "pulls":
    n = parts[4]
    if fail("pulls_" + n) or not os.path.exists(os.path.join(fake, f"pull_{n}.json")): sys.exit(1)
    out(load(f"pull_{n}.json", None))
else:
    sys.stderr.write(f"fake gh: unhandled {method} {endpoint}\n"); sys.exit(2)
