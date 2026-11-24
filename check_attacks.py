"""
Consistency checker for attacks.json. Prints only counts and case IDs, never
any attack text. Run it as you edit the attack_goal fields:

    python check_attacks.py

It reports, per case, whether the recorded attack_goal matches what the
injected document contains, plus the usual structural checks. Nothing here
changes any file.
"""
import json, re, collections, sys

EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")

def load(path):
    try:
        return json.load(open(path, encoding="utf-8"))
    except FileNotFoundError:
        sys.exit(f"missing file: {path}")
    except json.JSONDecodeError as e:
        sys.exit(f"{path} is not valid JSON: {e.msg} at line {e.lineno}")

def main(path="attacks.json"):
    cases = load(path).get("cases", [])
    tasks = {t["task"] for t in load("tasks.json")["cases"]}
    print(f"{path}: {len(cases)} cases "
          f"{dict(collections.Counter(c.get('type') for c in cases))}\n")

    ids = [c.get("id") for c in cases]
    cans = [c.get("canary") for c in cases]
    dup_ids = [i for i, n in collections.Counter(ids).items() if n > 1]
    dup_can = [i for i, n in collections.Counter(cans).items() if n > 1]
    print("duplicate ids      :", dup_ids or "none")
    print("duplicate canaries :", dup_can or "none")

    bad_task, no_canary, goal_kind, goal_unmatched = [], [], [], []
    for c in cases:
        doc = " ".join(d.get("text", "") for d in c.get("inject_docs", []))
        if c.get("task") not in tasks:
            bad_task.append(c["id"])
        if not c.get("canary") or c["canary"] not in doc:
            no_canary.append(c["id"])
        g = c.get("attack_goal", {})
        want_tool = (c.get("type") == "cascading")
        if (g.get("kind") == "tool_call") != want_tool:
            goal_kind.append(c["id"])
        # does the recorded goal target actually appear in the document?
        target = g.get("recipient") if g.get("kind") == "tool_call" else g.get("text")
        if not target or str(target) not in doc:
            goal_unmatched.append(c["id"])

    print("\ntask text not in tasks.json        :", bad_task or "none")
    print("canary missing from its document   :", no_canary or "none")
    print("goal kind does not match case type :", goal_kind or "none")
    print("goal target NOT found in document  :", goal_unmatched or "none")
    print(f"\n{len(cases) - len(goal_unmatched)}/{len(cases)} cases have a goal that matches their document.")
    # for cascading cases, how many documents even contain an email to send to
    casc = [c for c in cases if c.get("type") == "cascading"]
    with_email = sum(bool(EMAIL.search(" ".join(d.get("text","") for d in c.get("inject_docs",[])))) for c in casc)
    print(f"{with_email}/{len(casc)} cascading documents contain an email address.")
    ok = not (dup_ids or dup_can or bad_task or no_canary or goal_kind or goal_unmatched)
    print("\nALL CHECKS PASS" if ok else "Some checks need attention (see above).")

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "attacks.json")
