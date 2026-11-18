# Changelog

## Unreleased

- Added `rule-register/`: a skeleton grader that checks a tenant against governance rules written as JSON (resource, resource count and setting checks), with a pure-function module, Pester tests, an example register and a fictional sample state.
- Added `remediation/`: a skeleton phased remediation engine (Report, Safe, Network, Identity, Advisory) with ShouldProcess on every change, before-and-after tests, an exceptions register, 'Manual' fixes, and a `-Demo` mode; a read-only Secure Score planner; and a method for mapping a threat advisory to controls, checks and fixes.
- Added five diagrams in `docs/diagrams/` explaining the remediation ladder, the fix loop, the rule register, Secure Score triage and the advisory method.
- CI: parse and run the new skeletons offline (rule register against the sample state, remediation in Report, WhatIf and Demo apply, Secure Score plan against the sample).
- Added `tenant-hardening/`: SOP-SEC-TA-01, Tenant Hardening Assessment (concept edition), and `Get-TenantHardeningReport.skeleton.ps1`, a runnable skeleton of the tenant-wide assessment script.
- CI: parse-check the skeleton and dry-run it with `-SkipAzure -SkipGraph`, so the merge, score and write stages are exercised on every push.
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
