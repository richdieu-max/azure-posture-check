# Azure posture check

Run 20261019-144159Z UTC | subscription `00000000-0000-0000-0000-000000000000` | scope `resource groups app-prd-*` | tool v1.0.0 | read-only

**ATTENTION NEEDED**: 11 pass, 4 warn, 4 fail

## Identity

| Status | Check | Resource | Detail | Controls |
|---|---|---|---|---|
| FAIL | Guest with standing Owner |  | guest Owner: Vendor Engineer | AC-2, AC-6(5) |
| WARN | Standing Owner (subscription) |  | 2 user account(s) hold standing Owner: confirm each is intended | AC-6(5) |
| PASS | Role assignments to individual users |  | 2 direct user assignments at subscription scope, 1 group assignments visible | AC-2, AC-6 |

## Governance

| Status | Check | Resource | Detail | Controls |
|---|---|---|---|---|
| PASS | Guardrail policies (deny/modify) |  | every in-scope resource meets the enforced guardrails | CM-2, CM-6 |
| INFO | Audit-only initiatives |  | 2 resource(s) with audit findings (benchmark scoring, not drift): cis-azure-foundations=1, nist-800-53-r5=1 | CA-7, RA-5 |
| PASS | Delete locks |  | 2 resource group(s) locked | CM-3 |

## Network

| Status | Check | Resource | Detail | Controls |
|---|---|---|---|---|
| FAIL | NSG inbound from the internet | nsg-app/allow-rdp-temp | management port(s) 3389 open to the internet | SC-7, AC-17, CM-7 |
| PASS | Public IPs on VM NICs |  | 1 public IP(s), none attached to a VM NIC | SC-7 |
| WARN | Network Watcher |  | no Network Watcher (so no flow logs) in: westus3 | AU-12, SI-4 |

## Secrets

| Status | Check | Resource | Detail | Controls |
|---|---|---|---|---|
| PASS | Key Vault posture | kv-app-prd-01 | RBAC, purge protection, public access Disabled, default action Deny | SC-12, SC-28, AC-3, SC-7 |
| PASS | Key Vault audit logging | kv-app-prd-01 | diagnostic setting: kv-to-law | AU-2, AU-12 |

## Storage

| Status | Check | Resource | Detail | Controls |
|---|---|---|---|---|
| WARN | Storage account posture | stappdata01 | shared key access on | SC-8, SC-28, AC-3, SC-7 |

## Compute

| Status | Check | Resource | Detail | Controls |
|---|---|---|---|---|
| WARN | VM hardening | vm-app-01 | periodic patch assessment off | CM-6, SI-2, SC-28, IA-2 |

## Backup

| Status | Check | Resource | Detail | Controls |
|---|---|---|---|---|
| PASS | Vault resilience | rsv-app-prd-01 | redundancy GeoRedundant, cross-region restore True, immutability Unlocked, soft delete AlwaysON | CP-9, CP-6, CP-10 |
| PASS | VM backup freshness | vm-app-01 | last run Completed; latest recovery point 9 h ago | CP-9, CP-10 |

## Logging

| Status | Check | Resource | Detail | Controls |
|---|---|---|---|---|
| PASS | Activity log export |  | diagnostic setting: activity-to-law | AU-2, AU-6, AU-12 |
| PASS | Log Analytics retention | law-app-prd-01 | 365 days (minimum set to 90) | AU-11 |

## Threat protection

| Status | Check | Resource | Detail | Controls |
|---|---|---|---|---|
| FAIL | Defender for Cloud plans |  | not on: StorageAccounts | SI-4, RA-5 |
| FAIL | Defender security contact |  | no security contact: Defender alerts reach nobody | IR-6, SI-4 |

## Alerting

| Status | Check | Resource | Detail | Controls |
|---|---|---|---|---|
| PASS | Action groups and activity alerts |  | 1 action group(s), 1 email receiver(s), 8 enabled activity-log alert(s) | SI-4, AU-6, IR-6 |

