<#
.SYNOPSIS
    SKELETON. Turns Defender for Cloud recommendations into an ordered plan to
    raise the Secure Score without breaking the workload. Read-only.

.DESCRIPTION
    A Secure Score is easy to raise badly: switch off shared keys, close public
    access, enforce everything, and the application stops at 2 a.m. This script
    sorts every unhealthy recommendation on two axes:

      Impact      : score points recovered if fixed
      Disruption  : how likely the fix touches the running workload
                    (Safe / Network / Identity / Workload)

    and places each in a quadrant:

      Quick win   : high impact, low disruption    -> phase Safe, do first
      Plan it     : high impact, high disruption   -> needs the workload owner
      Fill-in     : low impact, low disruption     -> batch with quick wins
      Accept      : low impact, high disruption,
                    or listed in the exceptions register with a reason

    Output: plan.md and plan.json with the projected score after each step.

.EXAMPLE
    ./Get-SecureScorePlan.skeleton.ps1 -RecommendationsFile ./examples/secure-score-sample.json

.EXAMPLE
    Connect-AzAccount -Tenant <tenant-id>
    ./Get-SecureScorePlan.skeleton.ps1 -SubscriptionId <subscription-id>
#>
[CmdletBinding()]
param(
    [string] $SubscriptionId,
    [string] $RecommendationsFile,
    [string] $ExceptionsFile = (Join-Path $PSScriptRoot 'exceptions.example.json'),
    [double] $HighImpactPoints = 1.0,
    [string] $OutputPath = './evidence'
)

$ErrorActionPreference = 'Stop'
$ScriptVersion = '1.0.0-skeleton'

# How disruptive a fix tends to be, by keyword in the recommendation name.
# First match wins. Tune it for each workload; that is the point of the file.
$DisruptionMap = [ordered]@{
    'shared key|public network access|private link|firewall|network security group|internet-facing|management ports' = 'Network'
    'mfa|owner permissions|guest accounts|privileged'                                                              = 'Identity'
    'disk encryption|customer-managed key|tls|secure transfer|webhook|app service'                                 = 'Workload'
    '.*'                                                                                                            = 'Safe'
}

function Get-Disruption([string]$Name) {
    foreach ($k in $DisruptionMap.Keys) { if ($Name -match $k) { return $DisruptionMap[$k] } }
    'Safe'
}

# ------------------------------------------------------------------ collect
if ($RecommendationsFile) {
    $data = Get-Content -Raw $RecommendationsFile | ConvertFrom-Json
    $current = [double]$data.currentScore; $max = [double]$data.maxScore
    $recs = @($data.recommendations)
    $mode = 'offline'
} elseif ($SubscriptionId) {
    $sc = Get-AzSecuritySecureScore | Select-Object -First 1   # read-only
    $current = [double]$sc.CurrentScore; $max = [double]$sc.MaxScore
    # TODO (full build): join security controls to their unhealthy assessments
    # (Resource Graph: securityresources | where type == 'microsoft.security/assessments')
    # and spread each control's potential points over its recommendations.
    $recs = @()
    $mode = 'live'
} else {
    throw 'Pass -SubscriptionId (live) or -RecommendationsFile (offline).'
}

$exceptions = @()
if ($ExceptionsFile -and (Test-Path $ExceptionsFile)) {
    $exceptions = @((Get-Content -Raw $ExceptionsFile | ConvertFrom-Json).exceptions)
}

# ------------------------------------------------------------------ classify
$rows = foreach ($r in $recs) {
    $disruption = Get-Disruption $r.name
    $excepted = $exceptions | Where-Object { $r.fixId -and $_.fixId -eq $r.fixId } | Select-Object -First 1
    $high = [double]$r.points -ge $HighImpactPoints
    $quadrant = 'Accept'
    if ($excepted) { $quadrant = 'Accept' }
    elseif ($disruption -eq 'Safe') { $quadrant = if ($high) { 'Quick win' } else { 'Fill-in' } }
    elseif ($high) { $quadrant = 'Plan it' }
    [pscustomobject]@{
        Name = $r.name; Points = [double]$r.points; Unhealthy = $r.unhealthyResources
        Disruption = $disruption; Quadrant = $quadrant
        Note = if ($excepted) { "excepted: $($excepted.reason)" } else { '' }
    }
}
$rows = @($rows)

$order = @('Quick win', 'Fill-in', 'Plan it', 'Accept')
$plan = @($rows | Sort-Object @{ e = { $order.IndexOf($_.Quadrant) } }, @{ e = { $_.Points }; Descending = $true })

# Projected score after each quadrant is completed (Accept is never added).
$running = $current
$projection = foreach ($q in @($order | Where-Object { $_ -ne 'Accept' })) {
    $running += ($plan | Where-Object Quadrant -eq $q | Measure-Object Points -Sum).Sum
    [pscustomobject]@{ After = $q; Score = [math]::Round($running, 2); Percent = [math]::Round(100 * $running / $max, 1) }
}
$projection = @($projection)

$plan | Format-Table Quadrant, Points, Disruption, Name -AutoSize | Out-String | Write-Host
$projection | Format-Table -AutoSize | Out-String | Write-Host

# ------------------------------------------------------------------ write
$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss') + 'Z'
$dir = Join-Path $OutputPath "secure-score-plan-$stamp"
New-Item -ItemType Directory -Path $dir -Force | Out-Null
$md = New-Object System.Text.StringBuilder
[void]$md.AppendLine("# Secure Score plan ($mode)")
[void]$md.AppendLine('')
[void]$md.AppendLine(("Current: {0} of {1} ({2}%)" -f $current, $max, [math]::Round(100 * $current / $max, 1)))
[void]$md.AppendLine('')
[void]$md.AppendLine('| After | Projected | % |')
[void]$md.AppendLine('|---|---|---|')
foreach ($p in $projection) { [void]$md.AppendLine("| $($p.After) | $($p.Score) | $($p.Percent)% |") }
[void]$md.AppendLine('')
[void]$md.AppendLine('| Quadrant | Points | Disruption | Recommendation | Note |')
[void]$md.AppendLine('|---|---|---|---|---|')
foreach ($r in $plan) { [void]$md.AppendLine("| $($r.Quadrant) | $($r.Points) | $($r.Disruption) | $($r.Name) | $($r.Note) |") }
Set-Content -Path (Join-Path $dir 'plan.md') -Value $md.ToString() -Encoding utf8
@{ tool = "Get-SecureScorePlan $ScriptVersion"; mode = $mode; current = $current; max = $max; projection = $projection; plan = $plan } |
    ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $dir 'plan.json') -Encoding utf8
$manifest = Get-ChildItem $dir -File | Sort-Object Name | ForEach-Object {
    [ordered]@{ file = $_.Name; sha256 = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower() }
}
@{ tool = "Get-SecureScorePlan $ScriptVersion"; run = $stamp; files = @($manifest) } |
    ConvertTo-Json -Depth 4 | Set-Content -Path (Join-Path $dir 'MANIFEST.json') -Encoding utf8
Write-Host "Evidence: $dir"
