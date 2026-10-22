# Contributing to Thryve

Thryve is a defensive SOC and digital-forensics workstation. Contributions should remain defensive, evidence-led, and safe to run on systems the operator owns or is authorized to investigate.

Before opening a pull request:

1. Run `python -m unittest discover -s tests -v`.
2. Run `python -m compileall -q .`.
3. Do not commit credentials, endpoint databases, evidence, screenshots, or generated reports.
4. Document any new collector, API route, or forensic-tool integration.
