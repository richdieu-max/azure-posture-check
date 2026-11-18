<#
.SYNOPSIS
    SKELETON. Applies posture fixes one phase at a time, safest first, with
    before-and-after evidence. Plan-only unless you approve each change.

.DESCRIPTION
    Unlike the rest of this repository, this script CAN change Azure. It is
    built so that it does not do so by surprise:

      - Phase 'Report' (the default) only tests. Nothing changes.
      - Every change goes through ShouldProcess with ConfirmImpact High:
        PowerShell asks before each one. -WhatIf shows the plan and stops.
      - Each fix is tested BEFORE and AFTER. "Fixed" means the after-test passed,
        not that the command returned.
      - An exceptions register (exceptions.example.json) records fixes that would
        break the workload, the reason, the role that decided, and a review date.
        Excepted fixes are reported, never applied.
      - Some fixes return 'Manual': they are documented and tested, but the change
        itself is a decision for a person (removing access, replacing firewall rules).

    -Demo runs the engine against an in-memory fake state, with no Azure calls,
    so the plan/apply/verify loop can be seen and tested without a tenant.

.EXAMPLE
    ./Invoke-PhasedRemediation.skeleton.ps1 -Demo                         # report only
    ./Invoke-PhasedRemediation.skeleton.ps1 -Demo -Phase Safe -WhatIf     # the plan
    ./Invoke-PhasedRemediation.skeleton.ps1 -Demo -Phase Safe -Confirm:$false

.EXAMPLE
    Connect-AzAccount -Tenant <tenant-id>
    ./Invoke-PhasedRemediation.skeleton.ps1 -SubscriptionId <id> -Phase Report
    ./Invoke-PhasedRemediation.skeleton.ps1 -SubscriptionId <id> -Phase Safe -AlertEmail secops@example.com
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [ValidateSet('Report', 'Safe', 'Network', 'Identity', 'Advisory')]
    [string[]] $Phase = @('Report'),
    [string]   $SubscriptionId,
    [string]   $AlertEmail,
    [string]   $ExceptionsFile = (Join-Path $PSScriptRoot 'exceptions.example.json'),
    [string]   $OutputPath = './evidence',
    [switch]   $Demo
)

$ErrorActionPreference = 'Stop'
$ScriptVersion = '1.0.0-skeleton'
$PhaseOrder = @('Safe', 'Network', 'Identity', 'Advisory')

# ------------------------------------------------------------------ inputs
$catalog = @(. (Join-Path $PSScriptRoot 'fix-catalog.ps1'))
$exceptions = @()
if ($ExceptionsFile -and (Test-Path $ExceptionsFile)) {
    $exceptions = @((Get-Content -Raw $ExceptionsFile | ConvertFrom-Json).exceptions)
}

function Test-IsExcepted([string]$FixId, [string]$Resource = '*') {
    [bool]($exceptions | Where-Object { $_.fixId -eq $FixId -and ($_.resource -eq '*' -or $_.resource -eq $Resource -or $Resource -eq '*') })
}

$ctx = [pscustomobject]@{ SubscriptionId = $SubscriptionId; AlertEmail = $AlertEmail }
$ctx | Add-Member -MemberType ScriptMethod -Name IsExcepted -Value { param($f, $r) Test-IsExcepted $f $r }

if (-not $Demo) {
    if (-not $SubscriptionId) { throw 'Pass -SubscriptionId, or -Demo to run without Azure.' }
    Set-AzContext -Subscription $SubscriptionId | Out-Null
}

# Demo state: which fixes start compliant. Applying a fix flips it to compliant.
$demoState = @{ 'FX-S01' = $true; 'FX-S02' = $false; 'FX-S03' = $false; 'FX-N01' = $false; 'FX-N02' = $false; 'FX-N03' = $false; 'FX-I01' = $false; 'FX-A01' = $false }
$demoManual = @('FX-N02', 'FX-I01', 'FX-A01')

function Invoke-FixTest($Fix) {
    if ($Demo) { return [pscustomobject]@{ Compliant = [bool]$demoState[$Fix.Id]; Detail = 'demo state' } }
    try { & $Fix.Test $ctx } catch { [pscustomobject]@{ Compliant = $null; Detail = "test failed: $($_.Exception.Message)" } }
}

function Invoke-FixApply($Fix) {
    if ($Demo) {
        if ($demoManual -contains $Fix.Id) { return 'Manual' }
        $demoState[$Fix.Id] = $true; return 'Applied'
    }
    $r = & $Fix.Apply $ctx
    if ($r -eq 'Manual') { 'Manual' } else { 'Applied' }
}

# ------------------------------------------------------------------ run
$selected = if ($Phase -contains 'Report') { $catalog } else {
    @($catalog | Where-Object { $_.Phase -in $Phase } | Sort-Object { $PhaseOrder.IndexOf($_.Phase) }, Id)
}
$rows = New-Object System.Collections.Generic.List[object]

foreach ($fix in $selected) {
    $before = Invoke-FixTest $fix
    $status = $null; $after = $null

    if ($null -eq $before.Compliant) {
        $status = 'Could not check'
    } elseif ($before.Compliant) {
        $status = 'Already met'
    } elseif ($Phase -contains 'Report') {
        $status = 'Needs fix'
    } elseif (Test-IsExcepted $fix.Id) {
        $status = 'Excepted'
    } elseif ($PSCmdlet.ShouldProcess("$($fix.Id) $($fix.Title)", "Apply fix (disruption: $($fix.Disruption))")) {
        try {
            $outcome = Invoke-FixApply $fix
            if ($outcome -eq 'Manual') {
                $status = 'Needs manual change'
            } else {
                $after = Invoke-FixTest $fix
                $status = if ($after.Compliant) { 'Fixed' } else { 'Still failing' }
            }
        } catch {
            $status = 'Apply failed'; $after = [pscustomobject]@{ Compliant = $false; Detail = $_.Exception.Message }
        }
    } else {
        $status = 'Would fix'
    }

    $rows.Add([pscustomobject]@{
        Id = $fix.Id; Phase = $fix.Phase; Title = $fix.Title; Disruption = $fix.Disruption
        Status = $status; Before = $before.Detail; After = if ($after) { $after.Detail } else { '' }
        ConfirmFirst = $fix.ConfirmFirst; Rollback = $fix.Rollback
    })
}

$rows | Select-Object Id, Phase, Disruption, Status, Title | Format-Table -AutoSize | Out-String | Write-Host

# ------------------------------------------------------------------ evidence
$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss') + 'Z'
$dir = Join-Path $OutputPath "remediation-$stamp"
New-Item -ItemType Directory -Path $dir -Force -WhatIf:$false | Out-Null
$mode = if ($Demo) { 'demo' } else { 'live' }
$whatIfRun = [bool]$WhatIfPreference

$md = New-Object System.Text.StringBuilder
[void]$md.AppendLine("# Phased remediation ($mode)")
[void]$md.AppendLine('')
[void]$md.AppendLine("Phases: $($Phase -join ', ')  ")
[void]$md.AppendLine("WhatIf: $whatIfRun  ")
[void]$md.AppendLine("Run (UTC): $stamp")
[void]$md.AppendLine('')
[void]$md.AppendLine('| Fix | Phase | Disruption | Status | Before | After | Confirm first |')
[void]$md.AppendLine('|---|---|---|---|---|---|---|')
foreach ($r in $rows) { [void]$md.AppendLine("| $($r.Id) | $($r.Phase) | $($r.Disruption) | $($r.Status) | $($r.Before) | $($r.After) | $($r.ConfirmFirst) |") }
Set-Content -Path (Join-Path $dir 'remediation.md') -Value $md.ToString() -Encoding utf8 -WhatIf:$false
@{ tool = "Invoke-PhasedRemediation $ScriptVersion"; mode = $mode; phases = $Phase; whatIf = $whatIfRun; rows = $rows } |
    ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $dir 'remediation.json') -Encoding utf8 -WhatIf:$false

$manifest = Get-ChildItem $dir -File | Sort-Object Name | ForEach-Object {
    [ordered]@{ file = $_.Name; sha256 = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower() }
}
@{ tool = "Invoke-PhasedRemediation $ScriptVersion"; run = $stamp; files = @($manifest) } |
    ConvertTo-Json -Depth 4 | Set-Content -Path (Join-Path $dir 'MANIFEST.json') -Encoding utf8 -WhatIf:$false

Write-Host "Evidence: $dir"
