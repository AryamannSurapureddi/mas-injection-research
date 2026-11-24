"""
Runs every case under every chosen condition and writes one log per run:
    logs/<tag>/<condition>/<case_id>.jsonl

Runs that already have a finished log are skipped, so an interrupted
overnight run can simply be started again.

Examples:
    python run_benchmark.py --conditions none --limit 3        # quick check
    python run_benchmark.py --conditions none prompt
    python run_benchmark.py --cases tasks.json attacks.json --conditions none prompt classifier gateway
    python run_benchmark.py --mock --tag mock                  # no model needed
Then score with:
    python score.py logs/<tag> --cases tasks.json attacks.json
"""
import argparse, json, os, re, time
import agent, pipeline

def finished(path):
    if not os.path.exists(path):
        return False
    with open(path, encoding="utf-8") as f:
        return any('"event": "case_end"' in line for line in f)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--cases", nargs="+", default=["tasks.json"])
    p.add_argument("--conditions", nargs="+", default=["none"], choices=pipeline.CONDITIONS)
    p.add_argument("--tag", default=None, help="log folder name (default: the model name)")
    p.add_argument("--limit", type=int, default=None, help="run only the first N cases")
    p.add_argument("--pipeline", default="summarize", choices=list(pipeline.RESEARCH_PROMPTS))
    p.add_argument("--ablate", default=None, choices=list(__import__("gateway").COMPONENTS),
                   help="run only the gateway with this component removed (one ablation)")
    p.add_argument("--mock", action="store_true")
    a = p.parse_args()

    tag = a.tag or re.sub(r"[^A-Za-z0-9._-]", "_", "mock" if a.mock else agent.MODEL)
    if a.pipeline != "summarize":          # keep each pipeline's logs separate
        tag = f"{tag}_{a.pipeline}"
    components = None
    if a.ablate:                           # ablation: gateway minus one component
        import gateway
        a.conditions = ["gateway"]
        components = tuple(c for c in gateway.COMPONENTS if c != a.ablate)
        tag = f"{tag}_abl_{a.ablate}"
    cases = pipeline.load_cases(*a.cases)[: a.limit]
    jobs = [(c, cond) for cond in a.conditions for c in cases]
    print(f"{len(jobs)} runs: {len(cases)} cases x {len(a.conditions)} conditions "
          f"| pipeline={a.pipeline}{' | ablate='+a.ablate if a.ablate else ''} -> logs/{tag}")

    if not a.mock:  # load the model first so its load time is not counted as case latency
        t0 = time.time()
        try:
            agent.call_model([{"role": "user", "content": "Reply with OK."}], [])
        except Exception as e:
            raise SystemExit(f"Cannot reach the model {agent.MODEL} at {agent.BASE_URL}: {e}")
        print(f"Model loaded in {time.time() - t0:.0f}s")

    done, t_start = 0, time.time()
    for i, (case, cond) in enumerate(jobs, 1):
        path = os.path.join("logs", tag, cond, f"{case['id']}.jsonl")
        if finished(path):
            continue
        if os.path.exists(path):
            os.remove(path)  # half-written log from an interrupted run
        t0 = time.time()
        try:
            pipeline.run_case(case, cond, a.mock, path, a.pipeline, components)
        except NotImplementedError as e:
            raise SystemExit(f"Stopped: {e}")
        except Exception as e:
            agent.RunLogger(path=path).log("error", agent="coordinator", output=f"run crashed: {e}")
            print(f"  crashed: {e}")
        done += 1
        avg = (time.time() - t_start) / done
        left = len(jobs) - i
        print(f"[{i}/{len(jobs)}] {cond:<10} {case['id']:<9} {time.time() - t0:6.1f}s"
              f"   about {left * avg / 60:.0f} min left")
    print("Done.")

if __name__ == "__main__":
    main()
