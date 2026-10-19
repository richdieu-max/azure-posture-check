# Check catalog

Each check, what it reads, how it decides, and the NIST SP 800-53 Rev. 5 controls it supports. "Supports" means the check produces evidence toward the control; it does not satisfy the control on its own.

Status meanings: **FAIL** a setting that should not exist in a hardened subscription · **WARN** not wrong, but a decision or follow-up is open · **PASS** as expected · **INFO** context, no judgment.

## Identity

| Check | Reads | FAIL | WARN | Controls |
|---|---|---|---|---|
| Guest with standing Owner | Owner assignments at subscription scope | Any guest (`#EXT#`) Owner | | AC-2, AC-6(5) |
| Standing Owner (subscription) | Same | | One or more user accounts hold standing Owner (just-in-time access through PIM is the target) | AC-6, AC-6(5) |
| Standing Owner (management group) | Owner at `-ManagementGroupId` | | Any standing Owner at that scope | AC-6(5) |
| Role assignments to individual users | All assignments | | More direct user assignments than group assignments | AC-2, AC-6 |

## Governance

| Check | Reads | FAIL | WARN | Controls |
|---|---|---|---|---|
| Guardrail policies | Non-compliant policy states whose effect is deny, denyAction, modify, append or deployIfNotExists | Any in-scope resource | | CM-2, CM-6, CM-7 |
| Audit-only initiatives | Non-compliant states with audit effects | | (INFO) count by initiative | CA-7, RA-5 |
| Delete locks | Locks on each in-scope resource group | | A resource group has no CanNotDelete or ReadOnly lock | CM-3 |

The split matters: a benchmark initiative such as CIS or NIST will always show findings, many of them on resources outside the build or on plans that do not apply. Those are scoring inputs. A resource breaking an enforced guardrail is drift.

## Network

| Check | Reads | FAIL | WARN | Controls |
|---|---|---|---|---|
| NSG inbound from the internet | Every inbound Allow rule with source `*`, `Internet`, `0.0.0.0/0` or `Any` | The rule covers 22, 3389, 5985 or 5986 | Any other port | SC-7, AC-17, CM-7 |
| Public IPs on VM NICs | Public IP attachments | A public IP on a VM network interface | (INFO) unattached public IPs | SC-7, AC-17 |
| Network Watcher | Regions of in-scope VNets vs Network Watcher instances | | A region with VNets and no Network Watcher, so no flow logs | AU-12, SI-4 |

## Secrets (Key Vault)

| Check | Reads | FAIL | WARN | Controls |
|---|---|---|---|---|
| Key Vault posture | RBAC mode, purge protection, public network access, firewall default action | Reachable from any network, or purge protection off | Access policies instead of RBAC | SC-12, SC-28, AC-3, SC-7 |
| Key Vault audit logging | Diagnostic settings on the vault | None: secret reads go unrecorded | | AU-2, AU-12 |

## Storage

| Check | FAIL | WARN | Controls |
|---|---|---|---|
| Storage account posture | HTTP allowed; TLS below 1.2; anonymous blob access | Shared key access on; reachable from any network | SC-8, SC-28, AC-3, SC-7 |

## Compute

| Check | FAIL | WARN | Controls |
|---|---|---|---|
| VM hardening | Not Trusted Launch (or Confidential VM); SSH password login allowed | Secure boot off; encryption at host off; no managed identity; periodic patch assessment off | CM-6, SI-2, SC-28, IA-2 |

## Backup

| Check | FAIL | WARN | Controls |
|---|---|---|---|
| Recovery Services vaults | VMs in scope and no vault | | CP-9 |
| Vault resilience | | Not geo-redundant; immutability disabled | CP-9, CP-6, CP-10 |
| VM backup freshness | Newest recovery point older than `-MaxBackupAgeHours`, or last run failed | No recovery point yet | CP-9, CP-10 |
| VMs without backup | Any in-scope VM not protected by an in-scope vault | | CP-9 |

Immutability is a WARN, not a FAIL, on purpose: *Unlocked* is the reversible first step, and *Locked* is a one-way decision the data owner should make.

## Logging

| Check | FAIL | WARN | Controls |
|---|---|---|---|
| Activity log export | No subscription diagnostic setting: control-plane history ends after 90 days | | AU-2, AU-6, AU-11, AU-12 |
| Log Analytics retention | | Retention below `-MinLogRetentionDays` | AU-11 |

## Threat protection

| Check | FAIL | Controls |
|---|---|---|
| Defender for Cloud plans | An expected plan is not Standard | SI-4, RA-5 |
| Defender security contact | No contact: alerts reach nobody | IR-6, SI-4 |

## Alerting

| Check | FAIL | WARN | Controls |
|---|---|---|---|
| Action groups and activity alerts | No email receiver in any action group | Fewer than five enabled activity-log alerts | SI-4, AU-6, IR-6 |
