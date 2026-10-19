#Requires -Version 7.2
<#
.SYNOPSIS
    Read-only security posture check for an Azure subscription. Changes nothing.

.DESCRIPTION
    Walks identity, policy, network, Key Vault, storage, compute, backup, logging, Defender and
    alerting, and reports PASS, WARN or FAIL per check with the NIST SP 800-53 Rev. 5 controls each
    check supports. Writes a Markdown report, a JSON file and a SHA-256 manifest per run, so the
    output can be filed as audit evidence.

    WARN means "not wrong, but a decision or a follow-up is open". FAIL means a setting that
    should not be there in a hardened subscription.

    Every check is isolated: a missing module or a permission error becomes a WARN line for that
    check and the run continues. Reader on the subscription is enough for almost everything;
    Security Reader adds the Defender checks.

.PARAMETER SubscriptionId
    Subscription to check.
.PARAMETER TenantId
    Entra tenant. Optional; used only when the current Az context is in another tenant.
.PARAMETER ResourceGroupPrefix
    Only check resource groups whose name starts with this prefix. Default: every resource group.
.PARAMETER ManagementGroupId
    Also check standing Owner assignments at this management group.
.PARAMETER DefenderPlans
    Defender for Cloud plans expected to be on (Standard).
.PARAMETER MinLogRetentionDays
    Minimum Log Analytics retention before the check warns.
.PARAMETER MaxBackupAgeHours
    A VM whose latest recovery point is older than this fails the backup check.
.PARAMETER OutputPath
    Parent folder for the evidence. Each run writes its own time-stamped subfolder.
.PARAMETER FailOn
    Exit code policy for pipelines: None (always 0), Fail (1 on any FAIL), Warn (1 on any FAIL or WARN).

.EXAMPLE
    ./Invoke-AzurePostureCheck.ps1 -SubscriptionId 00000000-0000-0000-0000-000000000000
.EXAMPLE
    ./Invoke-AzurePostureCheck.ps1 -SubscriptionId $sub -ResourceGroupPrefix 'app-prd-' -FailOn Fail
.NOTES
    Version 1.0.0. Every name, ID and threshold is a parameter; nothing is hard-coded to one tenant.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidatePattern('^[0-9a-fA-F-]{36}$')] [string] $SubscriptionId,
    [string] $TenantId,
    [string] $ResourceGroupPrefix = '',
    [string] $ManagementGroupId,
    [string[]] $DefenderPlans = @('VirtualMachines', 'KeyVaults', 'StorageAccounts', 'Arm'),
    [ValidateRange(30, 4383)] [int] $MinLogRetentionDays = 90,
    [ValidateRange(1, 720)] [int] $MaxBackupAgeHours = 26,
    [string] $OutputPath = './evidence',
    [ValidateSet('None', 'Fail', 'Warn')] [string] $FailOn = 'None'
)

Set-StrictMode -Off
$ErrorActionPreference = 'Stop'
$WarningPreference = 'SilentlyContinue'
$ToolVersion = '1.0.0'
$RunStamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss') + 'Z'

Import-Module (Join-Path $PSScriptRoot 'PostureCheck.Helpers.psm1') -Force

$Findings = [System.Collections.Generic.List[object]]::new()
function Add-Finding {
    param($Area, $Check, $Status, $Detail = '', [string[]]$Controls = @(), $Resource = '')
    $Findings.Add((New-Finding -Area $Area -Check $Check -Status $Status -Detail $Detail -Controls $Controls -Resource $Resource))
}
function Invoke-Check {
    param([string]$Area, [string]$Check, [scriptblock]$Body)
    try { & $Body }
    catch { Add-Finding $Area $Check 'WARN' ("could not complete: " + ($_.Exception.Message -split "`n")[0]) }
}

# ------------------------------------------------------------------ context
$needed = 'Az.Accounts', 'Az.Resources', 'Az.Network', 'Az.Compute', 'Az.KeyVault', 'Az.Storage',
          'Az.RecoveryServices', 'Az.OperationalInsights', 'Az.Monitor', 'Az.Security', 'Az.PolicyInsights'
$missing = @($needed | Where-Object { -not (Get-Module -ListAvailable -Name $_) })
if ($missing) { Write-Warning ("Az modules not installed; their checks will report WARN: " + ($missing -join ', ')) }

$ctx = Get-AzContext
if (-not $ctx) { throw 'No Az context. Run Connect-AzAccount first.' }
if ($TenantId -and $ctx.Tenant.Id -ne $TenantId) { throw "Signed in to tenant $($ctx.Tenant.Id); expected $TenantId." }
$null = Set-AzContext -Subscription $SubscriptionId
$ctx = Get-AzContext
$subScope = "/subscriptions/$SubscriptionId"
$scopeLabel = if ($ResourceGroupPrefix) { "resource groups $ResourceGroupPrefix*" } else { 'all resource groups' }

Write-Host ("`nAzure posture check v{0}  ·  {1}  ·  {2}  ·  read-only`n" -f $ToolVersion, $ctx.Subscription.Name, $scopeLabel) -ForegroundColor Cyan

$ResourceGroups = @(Get-AzResourceGroup | Where-Object { -not $ResourceGroupPrefix -or $_.ResourceGroupName -like "$ResourceGroupPrefix*" })
$RgNames = @($ResourceGroups | ForEach-Object ResourceGroupName)
function Test-InScope([string]$ResourceGroupName) { return ($RgNames -contains $ResourceGroupName) }

# ------------------------------------------------------------------ identity
Invoke-Check 'Identity' 'Standing Owner (subscription)' {
    $owners = @(Get-AzRoleAssignment -Scope $subScope -RoleDefinitionName 'Owner' | Where-Object Scope -eq $subScope)
    $guests = @($owners | Where-Object { Test-IsGuestPrincipal $_.SignInName })
    $users  = @($owners | Where-Object ObjectType -eq 'User')
    if ($guests) { Add-Finding 'Identity' 'Guest with standing Owner' 'FAIL' ("guest Owner: " + (($guests | ForEach-Object DisplayName) -join ', ')) @('AC-2', 'AC-6(5)') }
    if ($users.Count -gt 3) { Add-Finding 'Identity' 'Standing Owner (subscription)' 'WARN' "$($users.Count) user accounts hold standing Owner; move to just-in-time (PIM) or groups" @('AC-6', 'AC-6(5)') }
    elseif ($users.Count -gt 0) { Add-Finding 'Identity' 'Standing Owner (subscription)' 'WARN' "$($users.Count) user account(s) hold standing Owner: confirm each is intended" @('AC-6(5)') }
    else { Add-Finding 'Identity' 'Standing Owner (subscription)' 'PASS' 'no user account holds standing Owner at subscription scope' @('AC-6(5)') }
}
if ($ManagementGroupId) {
    Invoke-Check 'Identity' 'Standing Owner (management group)' {
        $mgScope = "/providers/Microsoft.Management/managementGroups/$ManagementGroupId"
        $owners = @(Get-AzRoleAssignment -Scope $mgScope -RoleDefinitionName 'Owner' | Where-Object Scope -eq $mgScope)
        $st = if ($owners) { 'WARN' } else { 'PASS' }
        Add-Finding 'Identity' 'Standing Owner (management group)' $st $(if ($owners) { "held by: " + (($owners | ForEach-Object DisplayName) -join ', ') } else { 'none at this scope' }) @('AC-6(5)') $ManagementGroupId
    }
}
Invoke-Check 'Identity' 'Role assignments to individual users' {
    $all = @(Get-AzRoleAssignment -Scope $subScope)
    $direct = @($all | Where-Object { $_.ObjectType -eq 'User' -and $_.Scope -eq $subScope })
    $groups = @($all | Where-Object { $_.ObjectType -eq 'Group' })
    $st = if ($direct.Count -gt $groups.Count -and $direct.Count -gt 2) { 'WARN' } else { 'PASS' }
    Add-Finding 'Identity' 'Role assignments to individual users' $st "$($direct.Count) direct user assignments at subscription scope, $($groups.Count) group assignments visible" @('AC-2', 'AC-6')
}

# ------------------------------------------------------------------ governance
Invoke-Check 'Governance' 'Policy compliance' {
    $states = @(Get-AzPolicyState -SubscriptionId $SubscriptionId -Filter "ComplianceState eq 'NonCompliant'" -Top 5000)
    $states = @($states | Where-Object { -not $ResourceGroupPrefix -or (Test-InScope "$(Get-PropValue $_ 'ResourceGroup')") })
    if (-not $states) { Add-Finding 'Governance' 'Policy compliance' 'PASS' 'no non-compliant policy states in scope' @('CM-2', 'CM-6'); return }
    $enforced = @($states | Where-Object { (Get-PolicyEffectClass "$(Get-PropValue $_ 'PolicyDefinitionAction')") -eq 'Enforced' })
    $audit    = @($states | Where-Object { (Get-PolicyEffectClass "$(Get-PropValue $_ 'PolicyDefinitionAction')") -eq 'Audit' })
    $resCount = { param($s) @($s | ForEach-Object { "$($_.ResourceId)" } | Sort-Object -Unique).Count }
    if ($enforced) {
        $where = ($enforced | Group-Object PolicyAssignmentName | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ', '
        Add-Finding 'Governance' 'Guardrail policies (deny/modify)' 'FAIL' "$(& $resCount $enforced) resource(s) non-compliant with enforced guardrails: $where" @('CM-2', 'CM-6', 'CM-7')
    }
    else { Add-Finding 'Governance' 'Guardrail policies (deny/modify)' 'PASS' 'every in-scope resource meets the enforced guardrails' @('CM-2', 'CM-6') }
    if ($audit) {
        $top = ($audit | Group-Object PolicyAssignmentName | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ', '
        Add-Finding 'Governance' 'Audit-only initiatives' 'INFO' "$(& $resCount $audit) resource(s) with audit findings (benchmark scoring, not drift): $top" @('CA-7', 'RA-5')
    }
}
Invoke-Check 'Governance' 'Delete locks' {
    if (-not $ResourceGroups) { Add-Finding 'Governance' 'Delete locks' 'WARN' 'no resource groups in scope'; return }
    $unlocked = @($ResourceGroups | Where-Object { -not @(Get-AzResourceLock -ResourceGroupName $_.ResourceGroupName -AtScope -ErrorAction SilentlyContinue | Where-Object { "$($_.Properties.level)" -in 'CanNotDelete', 'ReadOnly' }) })
    if ($unlocked) { Add-Finding 'Governance' 'Delete locks' 'WARN' ("no CanNotDelete lock: " + (($unlocked | ForEach-Object ResourceGroupName) -join ', ')) @('CM-3', 'CP-9') }
    else { Add-Finding 'Governance' 'Delete locks' 'PASS' "$($ResourceGroups.Count) resource group(s) locked" @('CM-3') }
}

# ------------------------------------------------------------------ network
Invoke-Check 'Network' 'NSG inbound from the internet' {
    $hits = 0
    foreach ($nsg in @(Get-AzNetworkSecurityGroup | Where-Object { Test-InScope $_.ResourceGroupName })) {
        foreach ($r in $nsg.SecurityRules) {
            $x = Get-NsgRuleExposure -Rule $r
            if ($x) {
                $hits++
                $why = if ($x.ManagementPorts) { "management port(s) $($x.ManagementPorts -join ',') open to the internet" } else { "port(s) $($x.Ports) open to the internet" }
                Add-Finding 'Network' 'NSG inbound from the internet' $x.Status $why @('SC-7', 'AC-17', 'CM-7') "$($nsg.Name)/$($r.Name)"
            }
        }
    }
    if ($hits -eq 0) { Add-Finding 'Network' 'NSG inbound from the internet' 'PASS' 'no Allow rule with an internet or any source' @('SC-7', 'CM-7') }
}
Invoke-Check 'Network' 'Public IPs on VM NICs' {
    $pips = @(Get-AzPublicIpAddress | Where-Object { Test-InScope $_.ResourceGroupName })
    $onNic = @($pips | Where-Object { "$(Get-PropValue (Get-PropValue $_ 'IpConfiguration') 'Id')" -match '/networkInterfaces/' })
    if ($onNic) { foreach ($p in $onNic) { Add-Finding 'Network' 'Public IPs on VM NICs' 'FAIL' "VM NIC has a public IP; use Bastion, a VPN or a gateway instead" @('SC-7', 'AC-17') $p.Name } }
    else { Add-Finding 'Network' 'Public IPs on VM NICs' 'PASS' "$($pips.Count) public IP(s), none attached to a VM NIC" @('SC-7') }
    $idle = @($pips | Where-Object { -not (Get-PropValue $_ 'IpConfiguration') -and -not (Get-PropValue $_ 'NatGateway') })
    if ($idle) { Add-Finding 'Network' 'Unattached public IPs' 'INFO' ("not attached to anything: " + (($idle | ForEach-Object Name) -join ', ')) @('CM-8') }
}
Invoke-Check 'Network' 'Network Watcher' {
    $regions = @(Get-AzVirtualNetwork | Where-Object { Test-InScope $_.ResourceGroupName } | ForEach-Object Location | Sort-Object -Unique)
    if (-not $regions) { Add-Finding 'Network' 'Network Watcher' 'INFO' 'no virtual networks in scope'; return }
    $watchers = @(Get-AzNetworkWatcher -ErrorAction SilentlyContinue | ForEach-Object Location)
    $gap = @($regions | Where-Object { $_ -notin $watchers })
    if ($gap) { Add-Finding 'Network' 'Network Watcher' 'WARN' ("no Network Watcher (so no flow logs) in: " + ($gap -join ', ')) @('AU-12', 'SI-4') }
    else { Add-Finding 'Network' 'Network Watcher' 'PASS' ("present in " + ($regions -join ', ')) @('SI-4') }
}

# ------------------------------------------------------------------ key vault
Invoke-Check 'Secrets' 'Key Vault posture' {
    $vaults = @(Get-AzKeyVault | Where-Object { Test-InScope $_.ResourceGroupName })
    if (-not $vaults) { Add-Finding 'Secrets' 'Key Vault posture' 'INFO' 'no Key Vaults in scope'; return }
    foreach ($item in $vaults) {
        $v = Get-AzKeyVault -VaultName $item.VaultName -ResourceGroupName $item.ResourceGroupName
        $problems = @()
        if (-not $v.EnableRbacAuthorization) { $problems += 'access policies instead of RBAC' }
        if (-not $v.EnablePurgeProtection)   { $problems += 'purge protection off' }
        $pna = "$(Get-PropValue $v 'PublicNetworkAccess')"
        $def = "$(Get-PropValue (Get-PropValue $v 'NetworkAcls') 'DefaultAction')"
        if ($pna -ne 'Disabled' -and $def -ne 'Deny') { $problems += 'reachable from any network' }
        $st = if ($problems -contains 'reachable from any network' -or $problems -contains 'purge protection off') { 'FAIL' } elseif ($problems) { 'WARN' } else { 'PASS' }
        Add-Finding 'Secrets' 'Key Vault posture' $st $(if ($problems) { $problems -join '; ' } else { "RBAC, purge protection, public access $pna, default action $def" }) @('SC-12', 'SC-28', 'AC-3', 'SC-7') $v.VaultName
        $diag = @(Get-AzDiagnosticSetting -ResourceId $v.ResourceId -ErrorAction SilentlyContinue)
        Add-Finding 'Secrets' 'Key Vault audit logging' $(if ($diag) { 'PASS' } else { 'FAIL' }) $(if ($diag) { "diagnostic setting: " + (($diag | ForEach-Object Name) -join ', ') } else { 'no diagnostic setting: secret reads are not recorded' }) @('AU-2', 'AU-12') $v.VaultName
    }
}

# ------------------------------------------------------------------ storage
Invoke-Check 'Storage' 'Storage account posture' {
    $accounts = @(Get-AzStorageAccount | Where-Object { Test-InScope $_.ResourceGroupName })
    if (-not $accounts) { Add-Finding 'Storage' 'Storage account posture' 'INFO' 'no storage accounts in scope'; return }
    foreach ($sa in $accounts) {
        $fail = @(); $warn = @()
        if (-not $sa.EnableHttpsTrafficOnly) { $fail += 'HTTP allowed' }
        if ("$($sa.MinimumTlsVersion)" -notin 'TLS1_2', 'TLS1_3') { $fail += "minimum TLS $($sa.MinimumTlsVersion)" }
        if ($sa.AllowBlobPublicAccess) { $fail += 'anonymous blob access allowed' }
        if ((Get-PropValue $sa 'AllowSharedKeyAccess') -ne $false) { $warn += 'shared key access on' }
        $pna = "$(Get-PropValue $sa 'PublicNetworkAccess')"
        $def = "$(Get-PropValue (Get-PropValue $sa 'NetworkRuleSet') 'DefaultAction')"
        if ($pna -ne 'Disabled' -and $def -ne 'Deny') { $warn += 'reachable from any network' }
        $st = if ($fail) { 'FAIL' } elseif ($warn) { 'WARN' } else { 'PASS' }
        $detail = if ($fail -or $warn) { (@($fail) + @($warn)) -join '; ' } else { "HTTPS only, TLS $($sa.MinimumTlsVersion), no anonymous access, network restricted" }
        Add-Finding 'Storage' 'Storage account posture' $st $detail @('SC-8', 'SC-28', 'AC-3', 'SC-7') $sa.StorageAccountName
    }
}

# ------------------------------------------------------------------ compute
Invoke-Check 'Compute' 'VM hardening' {
    $vms = @(Get-AzVM | Where-Object { Test-InScope $_.ResourceGroupName })
    if (-not $vms) { Add-Finding 'Compute' 'VM hardening' 'INFO' 'no VMs in scope'; return }
    foreach ($vm in $vms) {
        $sp = $vm.SecurityProfile
        $issues = @()
        if ("$(Get-PropValue $sp 'SecurityType')" -notin 'TrustedLaunch', 'ConfidentialVM') { $issues += 'not Trusted Launch' }
        elseif (-not (Get-PropValue (Get-PropValue $sp 'UefiSettings') 'SecureBootEnabled')) { $issues += 'secure boot off' }
        if (-not (Get-PropValue $sp 'EncryptionAtHost')) { $issues += 'encryption at host off' }
        if (-not (Get-PropValue $vm.Identity 'Type')) { $issues += 'no managed identity' }
        $linux = Get-PropValue $vm.OSProfile 'LinuxConfiguration'
        $win   = Get-PropValue $vm.OSProfile 'WindowsConfiguration'
        if ($linux -and -not (Get-PropValue $linux 'DisablePasswordAuthentication')) { $issues += 'SSH password login allowed' }
        $patch = Get-PropValue (Get-PropValue $(if ($linux) { $linux } else { $win }) 'PatchSettings') 'PatchMode'
        $assess = Get-PropValue (Get-PropValue $(if ($linux) { $linux } else { $win }) 'PatchSettings') 'AssessmentMode'
        if ("$assess" -ne 'AutomaticByPlatform') { $issues += 'periodic patch assessment off' }
        $st = if ($issues -contains 'SSH password login allowed' -or $issues -contains 'not Trusted Launch') { 'FAIL' } elseif ($issues) { 'WARN' } else { 'PASS' }
        Add-Finding 'Compute' 'VM hardening' $st $(if ($issues) { $issues -join '; ' } else { "Trusted Launch, encryption at host, managed identity, patch mode $patch" }) @('CM-6', 'SI-2', 'SC-28', 'IA-2') $vm.Name
    }
}

# ------------------------------------------------------------------ backup
Invoke-Check 'Backup' 'Recovery Services vaults' {
    $vaults = @(Get-AzRecoveryServicesVault | Where-Object { Test-InScope $_.ResourceGroupName })
    $vms = @(Get-AzVM | Where-Object { Test-InScope $_.ResourceGroupName })
    if (-not $vaults) {
        Add-Finding 'Backup' 'Recovery Services vaults' $(if ($vms) { 'FAIL' } else { 'INFO' }) $(if ($vms) { "$($vms.Count) VM(s) in scope and no vault" } else { 'no vaults and no VMs in scope' }) @('CP-9')
        return
    }
    $protected = @()
    foreach ($v in $vaults) {
        $bp = Get-AzRecoveryServicesBackupProperty -Vault $v
        $red = "$(Get-PropValue $bp 'BackupStorageRedundancy')"
        $crr = [bool](Get-PropValue $bp 'CrossRegionRestore')
        $imm = "$(Get-PropValue (Get-PropValue $v.Properties 'ImmutabilitySettings') 'ImmutabilityState')"
        if (-not $imm) { $imm = 'Disabled' }
        $vp = Get-AzRecoveryServicesVaultProperty -VaultId $v.ID -ErrorAction SilentlyContinue
        $soft = "$(Get-PropValue $vp 'SoftDeleteFeatureState')"
        $st = if ($red -ne 'GeoRedundant') { 'WARN' } elseif ($imm -eq 'Disabled') { 'WARN' } else { 'PASS' }
        Add-Finding 'Backup' 'Vault resilience' $st "redundancy $red, cross-region restore $crr, immutability $imm, soft delete $soft" @('CP-9', 'CP-6', 'CP-10') $v.Name
        foreach ($it in @(Get-AzRecoveryServicesBackupItem -VaultId $v.ID -BackupManagementType AzureVM -WorkloadType AzureVM -ErrorAction SilentlyContinue)) {
            $name = ("$($it.Name)" -split ';')[-1]
            $protected += $name.ToLowerInvariant()
            $age = Get-AgeHours (Get-PropValue $it 'LatestRecoveryPoint')
            $st = if ($null -eq $age) { 'WARN' } elseif ($age -le $MaxBackupAgeHours -and "$($it.LastBackupStatus)" -in 'Completed', 'CompletedWithWarnings') { 'PASS' } else { 'FAIL' }
            Add-Finding 'Backup' 'VM backup freshness' $st ("last run {0}; latest recovery point {1}" -f $it.LastBackupStatus, $(if ($null -ne $age) { "$age h ago" } else { 'none yet' })) @('CP-9', 'CP-10') $name
        }
    }
    $unprotected = @($vms | Where-Object { $_.Name.ToLowerInvariant() -notin $protected })
    if ($unprotected) { Add-Finding 'Backup' 'VMs without backup' 'FAIL' ("not protected by any in-scope vault: " + (($unprotected | ForEach-Object Name) -join ', ')) @('CP-9') }
}

# ------------------------------------------------------------------ logging
Invoke-Check 'Logging' 'Activity log export' {
    $d = @(Get-AzSubscriptionDiagnosticSetting -ErrorAction SilentlyContinue)
    if ($d) { Add-Finding 'Logging' 'Activity log export' 'PASS' ("diagnostic setting: " + (($d | ForEach-Object Name) -join ', ')) @('AU-2', 'AU-6', 'AU-12') }
    else { Add-Finding 'Logging' 'Activity log export' 'FAIL' 'activity log is not exported: control-plane history ends after 90 days' @('AU-2', 'AU-11', 'AU-12') }
}
Invoke-Check 'Logging' 'Log Analytics retention' {
    $ws = @(Get-AzOperationalInsightsWorkspace | Where-Object { Test-InScope $_.ResourceGroupName })
    if (-not $ws) { Add-Finding 'Logging' 'Log Analytics retention' 'WARN' 'no Log Analytics workspace in scope' @('AU-6'); return }
    foreach ($w in $ws) {
        $st = if ($w.RetentionInDays -ge $MinLogRetentionDays) { 'PASS' } else { 'WARN' }
        Add-Finding 'Logging' 'Log Analytics retention' $st "$($w.RetentionInDays) days (minimum set to $MinLogRetentionDays)" @('AU-11') $w.Name
    }
}

# ------------------------------------------------------------------ defender
Invoke-Check 'Threat protection' 'Defender for Cloud plans' {
    $plans = @(Get-AzSecurityPricing)
    $off = @($DefenderPlans | Where-Object { $n = $_; "$(($plans | Where-Object Name -eq $n).PricingTier)" -ne 'Standard' })
    if ($off) { Add-Finding 'Threat protection' 'Defender for Cloud plans' 'FAIL' ("not on: " + ($off -join ', ')) @('SI-4', 'RA-5') }
    else { Add-Finding 'Threat protection' 'Defender for Cloud plans' 'PASS' ("on: " + ($DefenderPlans -join ', ')) @('SI-4', 'RA-5') }
}
Invoke-Check 'Threat protection' 'Defender security contact' {
    $c = @(Get-AzSecurityContact -ErrorAction SilentlyContinue | Where-Object { Get-PropValue $_ 'Email', 'Emails' })
    if ($c) { Add-Finding 'Threat protection' 'Defender security contact' 'PASS' 'security contact set' @('IR-6', 'SI-4') }
    else { Add-Finding 'Threat protection' 'Defender security contact' 'FAIL' 'no security contact: Defender alerts reach nobody' @('IR-6', 'SI-4') }
}

# ------------------------------------------------------------------ alerting
Invoke-Check 'Alerting' 'Action groups and activity alerts' {
    $ags = @(); $ala = @()
    foreach ($rg in $RgNames) {
        $ags += @(Get-AzActionGroup -ResourceGroupName $rg -ErrorAction SilentlyContinue)
        $ala += @(Get-AzActivityLogAlert -ResourceGroupName $rg -ErrorAction SilentlyContinue)
    }
    $receivers = @($ags | ForEach-Object { @(Get-PropValue $_ 'EmailReceiver', 'EmailReceivers') } | Where-Object { $_ })
    $enabled = @($ala | Where-Object { "$(Get-PropValue $_ 'Enabled')" -match 'true|enabled' })
    $st = if (-not $receivers) { 'FAIL' } elseif ($enabled.Count -lt 5) { 'WARN' } else { 'PASS' }
    Add-Finding 'Alerting' 'Action groups and activity alerts' $st "$($ags.Count) action group(s), $($receivers.Count) email receiver(s), $($enabled.Count) enabled activity-log alert(s)" @('SI-4', 'AU-6', 'IR-6')
}

# ------------------------------------------------------------------ report
$Findings | Sort-Object @{ Expression = { @{ FAIL = 0; WARN = 1; PASS = 2; INFO = 3 }[$_.Status] } }, Area |
    Format-Table Status, Area, Check, Resource, Detail -AutoSize -Wrap | Out-String -Width 220 | Write-Host

$summary = Get-PostureVerdict -Findings $Findings
$color = if ($summary.Fail) { 'Red' } elseif ($summary.Warn) { 'Yellow' } else { 'Green' }
Write-Host ("{0}  ·  {1} pass, {2} warn, {3} fail" -f $summary.Verdict, $summary.Pass, $summary.Warn, $summary.Fail) -ForegroundColor $color

$runFolder = Join-Path $OutputPath "posture-$RunStamp"
$null = New-Item -ItemType Directory -Path $runFolder -Force
$context = @{ Run = $RunStamp; Subscription = $SubscriptionId; Scope = $scopeLabel; Version = $ToolVersion; Operator = $ctx.Account.Id }
ConvertTo-PostureMarkdown -Findings $Findings -Context $context | Set-Content -Path (Join-Path $runFolder 'report.md') -Encoding utf8
[ordered]@{ run = $RunStamp; tool = $ToolVersion; subscription = $SubscriptionId; scope = $scopeLabel; operator = $ctx.Account.Id; summary = $summary; findings = $Findings } |
    ConvertTo-Json -Depth 6 | Set-Content -Path (Join-Path $runFolder 'findings.json') -Encoding utf8
$manifest = Write-EvidenceManifest -Folder $runFolder -Context $context
Write-Host "Evidence: $runFolder (manifest $manifest)" -ForegroundColor Cyan

exit (Get-PostureExitCode -Findings $Findings -FailOn $FailOn)
