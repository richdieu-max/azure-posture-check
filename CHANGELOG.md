# Changelog

## 1.0.0 (2026-10-19)

First public release.

- Read-only checks across identity, governance, network, Key Vault, storage, compute, backup, logging, Defender and alerting.
- Policy findings split into enforced guardrails (FAIL) and audit-only initiatives (INFO).
- NIST SP 800-53 Rev. 5 control references on every finding.
- Evidence folder per run: Markdown report, JSON findings and a SHA-256 manifest.
- `-FailOn` exit code policy for pipelines.
- Helper module with Pester tests and a CI workflow.
