# Changelog

## Unreleased

- README: name the two local-only `Set-`/`New-` calls (`Set-AzContext`, `New-Item`) so the read-only claim is precise.
- CI: reuse the Pester and PSScriptAnalyzer modules already on the GitHub runner instead of reinstalling them on every run.
- Fixed: a rule object whose single-value `SourceAddressPrefix` or `DestinationPortRange` is an empty string (the REST shape, with the values in the `...Prefixes` / `...Ranges` lists) was ignored or made the NSG check report WARN; `Get-PropValue` now treats empty strings and empty lists as absent and reads the list field, and `Test-PortInRange` tolerates empty entries.
- Tests: cover `Test-IsInternetSource` directly (IPv4, IPv6 and service tags), prefix and port lists on NSG rules, port ranges that cover a management port, caller-supplied management ports, INFO rows and empty runs in the verdict, line breaks in report details, and manifest idempotence.

## 1.0.0 (2026-10-19)

First public release.

- Read-only checks across identity, governance, network, Key Vault, storage, compute, backup, logging, Defender and alerting.
- Policy findings split into enforced guardrails (FAIL) and audit-only initiatives (INFO).
- NIST SP 800-53 Rev. 5 control references on every finding.
- Evidence folder per run: Markdown report, JSON findings and a SHA-256 manifest.
- `-FailOn` exit code policy for pipelines.
- Helper module with Pester tests and a CI workflow.
