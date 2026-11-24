# Attack set notes

## Source
InjecAgent (Zhan et al., Findings of ACL 2024), https://github.com/uiuc-kang-lab/InjecAgent
Licence: see external/injecagent/LICENSE
Setting: enhanced (files test_cases_dh_enhanced.json and test_cases_ds_enhanced.json)

## Unit of sampling
The 1,054 cases are 17 user tools x 62 attacker instructions (30 direct harm, 30 x 17 = 510;
32 data stealing, 32 x 17 = 544). Only the attacker instruction carries over to this pipeline,
so each unique attacker instruction is one candidate.
Numbering: each unique attacker instruction is identified by its attacker tool (field
"Attacker Tools"; for data-stealing cases the first of the two tools, since the second is
GmailSendEmail in all 544). Tools are numbered in alphabetical order of tool name:
1-30 (dh) and 1-32 (ds). Checked on 12 Nov 2026: 30 dh and 32 ds tools, each in exactly 17 cases.

## Random draw
Seed: 2026
Command:
    python -c "import random; r=random.Random(2026); print('dh:', r.sample(range(1,31),20)); print('ds:', r.sample(range(1,33),20))"
Result:
    dh: [4, 11, 17, 28, 21, 30, 8, 20, 23, 18, 14, 19, 26, 16, 15, 25, 1, 10, 2, 12]
    ds: [19, 27, 4, 15, 1, 31, 22, 16, 26, 11, 7, 13, 9, 12, 32, 21, 3, 18, 6, 2]
Assignment rule: in each list, the first 10 numbers are indirect cases, the last 10 cascading.
    dh indirect:  [4, 11, 17, 28, 21, 30, 8, 20, 23, 18]
    dh cascading: [14, 19, 26, 16, 15, 25, 1, 10, 2, 12]
    ds indirect:  [19, 27, 4, 15, 1, 31, 22, 16, 26, 11]
    ds cascading: [7, 13, 9, 12, 32, 21, 3, 18, 6, 2]

## Task pairing
Pair each case with one of the 30 tasks in tasks.json, spreading them evenly. Record the pairing below.

## Change log (one line per case)
| Case id | Source (file, instruction no.) | Category | Class | Task | Changes made |
| --- | --- | --- | --- | --- | --- |

## Freeze
Frozen on: ____ (no edits to attacks.json, tasks.json or score.py after this date)
