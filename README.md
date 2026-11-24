# Do Single-Agent Prompt Injections Cascade?

A stage-level study of prompt-injection propagation in a small-model multi-agent LLM
pipeline. This repository contains the pipeline, the attack benchmark, a rule-based
boundary gateway, and the scoring scripts used in the accompanying paper.

> **Main finding.** Across two pipeline designs, three defense conditions, and 40
> attacks adapted from InjecAgent, **no attack succeeded** on a 7B open-weight model.
> Propagation is controlled by architecture: a Research agent that *summarizes*
> retrieved content stops every injection at the first agent, while *pass-through*
> forwarding lets a few propagate but none into a successful action. A defensive
> system prompt made matters worse; the gateway's measurable value was removing the
> model's own unauthorized tool calls, not blocking attacks.

See the paper in [`paper/preprint.pdf`](paper/preprint.pdf) for the full write-up.

## The pipeline

```
user task -> Research agent -> Analysis agent -> Report agent -> answer
             (search)          (calculator,       (no tools)
                                get_information,
                                send_report)
```

`send_report` is a fake privileged tool: it sends nothing and only appears in the logs.
A call to it with a recipient the task never asked for counts as an unauthorized tool call.

## Setup

Requires Python 3.10+ and [Ollama](https://ollama.com).

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
ollama pull qwen2.5:7b
```

## Reproducing the results

```bash
# Main experiment: 3 conditions x 2 pipeline variants
python run_benchmark.py --cases tasks.json attacks.json --conditions none prompt gateway
python run_benchmark.py --cases tasks.json attacks.json --conditions none prompt gateway --pipeline passthrough

python score.py logs/qwen2.5_7b             --cases tasks.json attacks.json
python score.py logs/qwen2.5_7b_passthrough --cases tasks.json attacks.json

# Gateway component ablation (summarize pipeline)
python run_benchmark.py --cases tasks.json attacks.json --ablate provenance
python run_benchmark.py --cases tasks.json attacks.json --ablate detector
python run_benchmark.py --cases tasks.json attacks.json --ablate tool_risk
python run_benchmark.py --cases tasks.json attacks.json --ablate containment
```

All metrics are computed from the run logs by `score.py`; nothing is scored by hand.
To check the plumbing with no model, add `--mock`.

## Repository layout

| Path | What it is |
| --- | --- |
| `agent.py` | One agent: tool loop, tools, JSON-lines logging |
| `pipeline.py` | The three-agent pipeline, the two pipeline variants, and how each condition is applied |
| `gateway.py` | The defenses: the rule-based security gateway and a classifier baseline |
| `run_benchmark.py` | Runs cases x conditions, one log per run |
| `score.py` | Computes ASR, APR, propagation depth, UTR, TSR, FPR and latency from the logs |
| `tasks.json` | 30 legitimate tasks over a fictional company |
| `attacks.json` | 40 attack cases adapted from InjecAgent (see Data and attribution) |
| `corpus.json` | Documents the search tool reads |
| `attacks_notes.md` | Sampling seed, selection and change log for the attack set |
| `paper/` | The preprint (PDF and LaTeX source) |
| `figures/` | Result figures |

## Data and attribution

The 40 attack cases in `attacks.json` adapt attacker instructions from **InjecAgent**
(Zhan et al., Findings of ACL 2024, https://github.com/uiuc-kang-lab/InjecAgent). Each
case records its source instruction in `attacks_notes.md`. The original InjecAgent data
is **not** redistributed here; see that project for its own license and terms. The
company and tasks used in this benchmark are fictional.

## Citing

```bibtex
@misc{YOURKEY2026cascade,
  title        = {Do Single-Agent Prompt Injections Cascade? A Stage-Level Study of a Small-Model Multi-Agent LLM Pipeline},
  author       = {[Your Name]},
  year         = {2026},
  eprint       = {XXXX.XXXXX},
  archivePrefix= {arXiv},
  primaryClass = {cs.CR}
}
```

## Note

Parts of the code and the paper text were drafted with the help of an AI assistant.
All experiments were run by the author and all reported numbers come from the author's
own run logs.

## License

Code in this repository is released under the MIT License (see `LICENSE`). This does not
cover the InjecAgent-derived attack content, which remains subject to InjecAgent's terms.
