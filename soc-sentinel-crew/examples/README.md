# Example outputs

This folder is for **real outputs** produced by the crew, so visitors can see
the result without running anything.

It is intentionally empty in the first commit, because example reports should
come from an actual run, not be written by hand. To generate them:

```bash
python main.py --sample --mock --output-dir examples/sample_run
```

Then commit these files from `examples/sample_run/`:

- `incident_report.md`: executive report, detection rules and validation appendix
- `iocs.stix.json`: STIX 2.1 bundle
- `attack_navigator_layer.json`: open it at <https://mitre-attack.github.io/attack-navigator/>
- `run_summary.json`: gate decision, token usage and timing

The sample alert and mock tools use only synthetic data, so these files are safe
to publish. Do **not** publish outputs from real alerts.
