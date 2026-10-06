# Good first issues

Ideas sized for new contributors. Maintainers: create each one as a GitHub issue
with the `good first issue` label.

1. **Add an eval case: lateral movement.** Create an alert where a host uses
   PsExec (`T1021.002`) to reach another host. Add a matching fixture in
   `siem/chronicle_mock.py`, and a case in `evals/cases.json`.
2. **Add an eval case: phishing link click.** Write a proxy alert for a user
   visiting a newly registered domain, labelled `true_positive`.
3. **Suricata engine check in CI.** Install `suricata` in the workflow and add a
   test that loads a known-good rule with `suricata -T`. The test should skip
   when the binary is missing.
4. **QRadar connector.** Follow `docs/CONNECTORS.md`.
5. **Real Google SecOps connector.** Call the Chronicle Search API with a service
   account, keeping the same output contract as the mock.
6. **MISP export.** Convert the STIX bundle into a MISP event JSON.
7. **Cost estimate in the UI.** Turn token counts into an approximate cost, using a
   user-editable price table (prices change, so don't hard-code them).
8. **Spanish UI translation.** Add a language toggle to `app.py`.
9. **Better YARA-L linting.** Validate `match:` windows and `outcome:` variables
   in `rule_validation.py`.
10. **Persist run history.** Save each `run_summary.json` and show past runs in a
    sidebar list.
