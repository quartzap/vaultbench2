# 🔐 VaultBench

**A risk-taxonomy-labeled adversarial benchmark suite for evaluating LLMs before enterprise (banking) deployment.**

> Stress-test every model you onboard — across fraud, cyber, privacy, CBRN,
> discrimination, misinformation, and agentic-tool-misuse risk categories —
> against direct, roleplay, injection, multi-turn, and obfuscation attack
> vectors, with banking-relevance and severity scoring built in.

---

## Why VaultBench?

Before a new LLM (PolyCloud-hosted or open-source) goes anywhere near a
customer-facing or agentic banking workflow, it needs to survive more than
a vibe check. VaultBench packages **20,615 labeled adversarial prompts** —
sourced from established public safety benchmarks (AdvBench, HarmBench,
Do-Not-Answer, garak's in-the-wild jailbreak corpus) and systematically
expanded across 11 attack-delivery techniques — into a single, structured
dataset you can run through any model and slice by:

- **Risk type** — fraud & financial crime, cybersecurity, PII leakage,
  CBRN, hate/discrimination, self-harm, misinformation/financial advice,
  IP/copyright, agentic tool misuse, and more
- **Attack vector** — direct ask, roleplay/persona jailbreak, hypothetical
  framing, authority impersonation, prompt injection, encoding/obfuscation,
  context stuffing, multi-turn escalation, refusal suppression, known
  in-the-wild jailbreak templates
- **Banking relevance** — HIGH / MEDIUM / LOW, so you can build a tight
  gating tier for production-critical risks
- **Severity** — 1 (low) to 4 (critical)

## Quick stats

| | |
|---|---|
| Total prompts | **20,615** |
| Single-turn | 18,756 |
| Multi-turn (Crescendo-style escalation) | 1,859 |
| Risk categories | 12 |
| Attack vectors | 11 |
| Top risk areas | Fraud & Financial Crime (3,552), Illegal Activity (3,018), Privacy/PII (2,816), Misinformation/Financial Advice (2,751) |

## Repo structure
```
vaultbench/
├── README.md
├── taxonomy.py                  # controlled vocabulary: risk types, attack vectors, severity, banking relevance
├── aggregate.py                 # pulls & normalizes public source datasets
├── augment.py                   # generates attack-vector variants
├── augment2.py                  # adds in-the-wild jailbreak template wrapper
└── data/
    ├── vaultbench_base_prompts.csv     # 1,859 unwrapped source prompts
    └── vaultbench_full.csv             # 20,615 fully labeled prompts (main deliverable)
```

## Quickstart
```bash
pip install -r requirements.txt   # csv stdlib only, no deps required
python aggregate.py               # rebuild base_prompts.csv from raw sources
python augment.py                 # generate attack-vector variants
python augment2.py                # add jailbreak-template wrapper -> data/vaultbench_full.csv
```

## Recommended usage
1. **Gate tier**: run the `severity=4` + `banking_relevance=HIGH` slice
   (~1,940 rows) as a hard pass/fail before any model onboarding.
2. **Full sweep**: run all 20,615 prompts through the candidate model,
   score with a judge model/rubric, and pivot results by
   `risk_type × attack_vector × banking_relevance` for a weakness heatmap.
3. **Extend**: add JailbreakBench, BeaverTails, SimpleSafetyTests, your own
   incident corpus, etc. via `aggregate.py` — see `README.md` extension notes.

## Sources & Attribution
- AdvBench — Zou et al., 2023 (github.com/llm-attacks/llm-attacks)
- HarmBench — Mazeika et al., 2024 (github.com/centerforaisafety/HarmBench)
- Do-Not-Answer — Wang et al., 2023 (github.com/Libr-AI/do-not-answer)
- garak in-the-wild jailbreak corpus — Shen et al. / leondz/garak

All sources released for safety-research use under permissive licenses;
attribution required, and VaultBench is intended for internal red-team /
eval environments only — not for generating attacks against production
systems.

## License
Internal use — review individual upstream dataset licenses before external redistribution.
