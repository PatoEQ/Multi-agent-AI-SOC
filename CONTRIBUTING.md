# Contributing

Thanks for helping! Contributions of all sizes are welcome: new SIEM
connectors, eval cases, better prompts, docs and bug fixes.

## Setup

```bash
git clone https://github.com/PatoEQ/soc-sentinel-crew.git
cd soc-sentinel-crew
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
cp .env.example .env
```

## Before opening a pull request

```bash
ruff check .                         # lint, including security rules
pytest                               # unit tests, no API keys needed
python evals/run_eval.py --validate-only
```

If you changed **prompts, agents or tasks**, also run the full evaluation
(needs an LLM key) and paste the score in your PR:

```bash
python evals/run_eval.py --runs 3
```

## Ground rules

- **No secrets or real data.** Never commit keys, real alerts, hostnames,
  usernames or internal IPs. Use synthetic data like `sample_alerts/`.
- **Tools never raise.** A tool's `_run` returns an `ERROR: ...` string, so the
  agent can recover.
- **No curly-brace placeholders** in prompts other than the documented ones.
  CrewAI interpolates `{word}`, and `tests/test_pipeline.py` checks this.
- **Keep the gate binding.** Anything that could let a report be produced after
  the Auditor said `HALT` needs a test proving it can't.

## Good places to start

See [docs/GOOD_FIRST_ISSUES.md](docs/GOOD_FIRST_ISSUES.md) and
[docs/CONNECTORS.md](docs/CONNECTORS.md).

## Code of conduct

Be kind and constructive. Harassment or discrimination of any kind is not
tolerated. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
