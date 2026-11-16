# Tenant Hardening Assessment

A read-only security assessment of a Microsoft 365 and Azure tenant, written as a standard operating procedure (SOP-SEC-TA-01) together with the PowerShell script behind it. Where `azure-posture-check` checks one subscription against a hardened build, this assessment looks at the whole tenant: Azure and Entra ID together, any number of subscriptions, and tenants run by guest administrators.

- **[SOP-SEC-TA-01 (PDF, 37 pages)](SOP-SEC-TA-01-Tenant-Hardening-Assessment.pdf)**: the concept edition of the procedure. It covers prerequisites, sign-in, the 20 numbered steps with checkpoints, how the script is built, troubleshooting taken from real runs, known false positives, and the quarterly cycle and evidence retention.
- **[Get-TenantHardeningReport.skeleton.ps1](Get-TenantHardeningReport.skeleton.ps1)**: a runnable 365-line reduction of the full script (v3.0.1, about 1,200 lines). It has the same nine blocks, helper names and output files as the full script, with one example check of each kind.

The concept edition contains no tenant identifiers, account names or findings.

## What one run does

| | |
|---|---|
| Changes made to the tenant | **0**. Every call is a GET or a Resource Graph query |
| Data sources read | **17**, through about 30 read-only queries (Resource Graph, Resource Manager, Microsoft Graph) |
| Sign-in | Device code, delegated, read-only scopes. The script never sees a password, and the token is never written to disk |
| Files produced | **4**: HTML report, remediation tracker CSV, evidence JSON, SHA-256 manifest, all tied together by one run ID |
| Frameworks | CIS Microsoft Azure Foundations, NIST CSF 2.0, NIST SP 800-53 Rev 5, ISO/IEC 27001:2022, HIPAA Security Rule, PCI DSS (boundary only), STRIDE |

## How the script turns raw results into a report

1. **Collect.** About 30 queries feed 17 data sources. Each source is logged as OK, Failed or Skipped, so a gap is never silent.
2. **Name.** Defender, Resource Graph and the custom checks spell the same resource in different ways, so the script gives each resource one canonical name.
3. **Merge.** Findings with the same issue key, subscription and resource group become one row. For example, a custom NSG check and three Defender recommendations about open SSH or RDP become one finding, *Admin ports reachable from the Internet*, with four sources listed.
4. **Calibrate.** Context lowers severity where it should. A single Owner on a personal developer subscription is by design.
5. **Score.** Pass counts 1, Warn 0.5 and Fail 0. N/A and "Could not check" rows are excluded, so a missing licence cannot inflate or deflate a domain's score.
6. **Map.** Every finding carries the framework references of its domain.
7. **Write.** The script writes the tracker (F001, F002 …, with Owner, Target date, Status, Change ticket and Verified columns), the evidence JSON, the HTML report and the hash manifest.

A missing permission never produces a false failure. The data source shows as Failed and its checks become "Could not check".

## Try the skeleton without signing in

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
./Get-TenantHardeningReport.skeleton.ps1 -TenantId 00000000-0000-0000-0000-000000000000 -SkipAzure -SkipGraph -OutputPath ./out
```

This runs the merge, score and write stages end to end and writes four nearly empty files. Leave off `-SkipAzure -SkipGraph` to run it against a tenant where you hold Reader and Global Reader (or Security Reader).

## Adding a check

Each check follows the same pattern: a query, a decision, an `Add-Finding` call for every outcome (passes as well as failures, so the scorecard's denominator is honest), `Log-Source` on success, and a `catch` that logs Failed instead of stopping the run. Azure checks go in block 5 and Entra ID checks in block 6. The merge, score and write stages pick up new rows with no further changes. Section 6 of the SOP has the full rules.
