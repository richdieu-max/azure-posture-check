# azure-posture-check

![CI](https://github.com/richdieu-max/azure-posture-check/actions/workflows/ci.yml/badge.svg)
![PowerShell 7.2+](https://img.shields.io/badge/PowerShell-7.2%2B-5391FE)
![Read-only](https://img.shields.io/badge/changes%20made-none-2ea44f)

A read-only security posture check for an Azure subscription. One command walks identity, policy, network, Key Vault, storage, compute, backup, logging, Defender and alerting, then gives a PASS / WARN / FAIL line per check, the NIST SP 800-53 Rev. 5 controls each check supports, and an evidence folder an auditor can verify.

I wrote the first version of this during an Azure tenant build to answer one question quickly and repeatably: *is everything we built still the way we built it?* This repository is the general-purpose rewrite. Every name, ID and threshold is a parameter; nothing is tied to one tenant.

## Why it exists

Azure Policy and Defender for Cloud score a subscription against benchmarks, but their numbers mix two different things: **guardrails you enforce** (deny, modify) and **benchmarks you audit against**. A low benchmark score can hide one real drift problem under dozens of expected findings. This tool separates the two, checks the settings that matter most in a hardened build, and turns the result into evidence instead of a screenshot.

## What it checks

| Area | Checks | FAIL when |
|---|---|---|
| Identity | Standing Owner at subscription and (optionally) management group; guest Owners; direct user vs group assignments | A guest account holds standing Owner |
| Governance | Policy compliance split into enforced guardrails and audit-only initiatives; delete locks | A resource breaks a deny or modify guardrail |
| Network | Internet-facing NSG allows; public IPs on VM NICs; Network Watcher coverage | RDP, SSH or WinRM is open to the internet; a VM NIC has a public IP |
| Secrets | Key Vault RBAC, purge protection, network exposure, audit logging | A vault is reachable from any network, has no purge protection, or logs nothing |
| Storage | HTTPS only, TLS 1.2+, anonymous access, shared key, network exposure | HTTP, old TLS, or anonymous blob access is allowed |
| Compute | Trusted Launch, secure boot, encryption at host, managed identity, SSH password login, patch assessment | Not Trusted Launch, or SSH password login is allowed |
| Backup | Vault redundancy, immutability, soft delete, cross-region restore, VM backup freshness, unprotected VMs | A VM has no backup, or the newest recovery point is too old |
| Logging | Activity log export, Log Analytics retention | The activity log is not exported |
| Threat protection | Defender for Cloud plans, security contact | An expected plan is off, or alerts go to nobody |
| Alerting | Action groups, email receivers, activity-log alerts | No one receives alerts |

The full list, with the reasoning and control mapping for each check, is in [docs/checks.md](docs/checks.md).

## How a run works

```mermaid
flowchart LR
    A[Connect-AzAccount<br/>Reader role] --> B[Resolve scope<br/>subscription + RG prefix]
    B --> C{Run each check<br/>in isolation}
    C -->|ok| D[PASS / WARN / FAIL<br/>+ NIST controls]
    C -->|error or missing module| E[WARN line,<br/>run continues]
    D --> F[Console table<br/>+ one-line verdict]
    E --> F
    F --> G[evidence/posture-&lt;UTC&gt;/<br/>report.md · findings.json]
    G --> H[MANIFEST.json<br/>SHA-256 per file]
    H --> I[Exit code for CI<br/>-FailOn None | Fail | Warn]
```

## Quick start

```powershell
Install-Module Az -Scope CurrentUser          # once
Connect-AzAccount

./src/Invoke-AzurePostureCheck.ps1 -SubscriptionId <subscription-id>

# Only the production resource groups, and fail a pipeline on any FAIL
./src/Invoke-AzurePostureCheck.ps1 -SubscriptionId <subscription-id> -ResourceGroupPrefix 'app-prd-' -FailOn Fail

# Also check standing Owner at a management group, and expect the Containers plan
./src/Invoke-AzurePostureCheck.ps1 -SubscriptionId <subscription-id> -ManagementGroupId 'org-root' `
    -DefenderPlans VirtualMachines, KeyVaults, StorageAccounts, Arm, Containers
```

| Parameter | Default | Purpose |
|---|---|---|
| `-SubscriptionId` | required | Subscription to check |
| `-TenantId` | current | Refuse to run if signed in to another tenant |
| `-ResourceGroupPrefix` | all | Limit checks to resource groups starting with this prefix |
| `-ManagementGroupId` | none | Also check standing Owner at this management group |
| `-DefenderPlans` | VM, Key Vault, Storage, ARM | Plans expected to be on |
| `-MinLogRetentionDays` | 90 | Log Analytics retention below this warns |
| `-MaxBackupAgeHours` | 26 | Newest VM recovery point older than this fails |
| `-OutputPath` | `./evidence` | Parent folder for each run's evidence |
| `-FailOn` | `None` | Exit code policy for pipelines |

**Permissions:** Reader on the subscription covers almost every check. Security Reader adds the Defender checks. The script calls only `Get-*` cmdlets.

## Sample output

From a run against a **fictional** subscription (see [examples/sample-report.md](examples/sample-report.md)):

```text
Status Area              Check                          Resource               Detail
------ ----              -----                          --------               ------
FAIL   Identity          Guest with standing Owner                             guest Owner: Vendor Engineer
FAIL   Network           NSG inbound from the internet  nsg-app/allow-rdp-temp management port(s) 3389 open to the internet
FAIL   Threat protection Defender for Cloud plans                              not on: StorageAccounts
FAIL   Threat protection Defender security contact                             no security contact: Defender alerts reach nobody
WARN   Compute           VM hardening                   vm-app-01              periodic patch assessment off
WARN   Storage           Storage account posture        stappdata01            shared key access on
...
ATTENTION NEEDED  ·  11 pass, 4 warn, 4 fail
```

Each run writes:

```text
evidence/posture-20261019-144151Z/
├── report.md        # tables by area, ready to paste into a findings report
├── findings.json    # every finding with status, resource, detail and controls
└── MANIFEST.json    # SHA-256 of each file, the tool version and who ran it
```

## Design choices

- **Read-only by construction.** No `Set-`, `New-`, `Remove-` or `Update-` calls on Azure. Safe to hand to an auditor with Reader.
- **One failure never stops the run.** Each check is wrapped on its own; a permission gap becomes a WARN line for that check.
- **Tolerant of Az module drift.** Properties are read through `Get-PropValue`, which tries several names and returns `$null` instead of throwing.
- **Evidence, not screenshots.** The manifest hashes let a reviewer confirm the report was not edited after the run.
- **Testable.** All decision logic lives in `PostureCheck.Helpers.psm1` with no Azure calls, and is covered by Pester tests in CI.

## Repository layout

```text
src/Invoke-AzurePostureCheck.ps1     the check
src/PostureCheck.Helpers.psm1        pure helpers (classification, verdict, report, manifest)
tests/PostureCheck.Helpers.Tests.ps1 Pester 5 tests for every helper
docs/checks.md                       each check, why it matters, control mapping
examples/                            report from a fictional subscription
.github/workflows/ci.yml             PSScriptAnalyzer + Pester on every push
```

## Limits

- Checks the control plane. It does not scan inside VMs, review application code or test exploitability.
- Control mappings show which NIST SP 800-53 controls a check **supports**; passing a check does not by itself satisfy a control.
- Thresholds are defaults for a production subscription. Tune them with the parameters for your environment.

## License

MIT. See [LICENSE](LICENSE).
