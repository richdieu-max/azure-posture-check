#Requires -Version 7.2
<#
    PostureCheck.Helpers.psm1
    Pure helper functions for Invoke-AzurePostureCheck.ps1. Nothing in this module calls Azure,
    so every function here can be unit tested without a subscription.
#>

Set-StrictMode -Off

# Read a property by any of several names and return $null when none exist.
# Az objects change shape between module versions; this keeps the checks from breaking.
function Get-PropValue {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)] $InputObject,
        [Parameter(Position = 1, Mandatory)] [string[]] $Name
    )
    if ($null -eq $InputObject) { return $null }
    foreach ($n in $Name) {
        if ($InputObject -is [System.Collections.IDictionary]) {
            if ($InputObject.Contains($n) -and $null -ne $InputObject[$n]) { return $InputObject[$n] }
            continue
        }
        $p = $InputObject.PSObject.Properties[$n]
        if ($p -and $null -ne $p.Value) { return $p.Value }
    }
    return $null
}

# Last segment of an Azure resource ID.
function Get-ResourceLeaf {
    [CmdletBinding()]
    param([Parameter(Position = 0)] [string] $ResourceId)
    if ([string]::IsNullOrWhiteSpace($ResourceId)) { return '' }
    return ($ResourceId.TrimEnd('/') -split '/')[-1]
}

# One row of the report.
function New-Finding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Area,
        [Parameter(Mandatory)] [string] $Check,
        [Parameter(Mandatory)] [ValidateSet('PASS', 'WARN', 'FAIL', 'INFO')] [string] $Status,
        [string] $Detail = '',
        [string[]] $Controls = @(),
        [string] $Resource = ''
    )
    [pscustomobject]@{
        Area     = $Area
        Check    = $Check
        Status   = $Status
        Resource = $Resource
        Detail   = $Detail
        Controls = ($Controls -join ', ')
    }
}

# One-line verdict from a list of findings.
function Get-PostureVerdict {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Findings)
    $fail = @($Findings | Where-Object Status -eq 'FAIL').Count
    $warn = @($Findings | Where-Object Status -eq 'WARN').Count
    $pass = @($Findings | Where-Object Status -eq 'PASS').Count
    $verdict = if ($fail -gt 0) { 'ATTENTION NEEDED' } elseif ($warn -gt 0) { 'HEALTHY, WITH OPEN ITEMS' } else { 'ALL GOOD' }
    [pscustomobject]@{ Verdict = $verdict; Pass = $pass; Warn = $warn; Fail = $fail }
}

# Process exit code for CI use. FailOn = None | Fail | Warn.
function Get-PostureExitCode {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Findings,
        [ValidateSet('None', 'Fail', 'Warn')] [string] $FailOn = 'None'
    )
    $s = Get-PostureVerdict -Findings $Findings
    switch ($FailOn) {
        'Fail' { if ($s.Fail -gt 0) { return 1 } }
        'Warn' { if ($s.Fail -gt 0 -or $s.Warn -gt 0) { return 1 } }
    }
    return 0
}

# Sources that mean "anyone on the internet".
function Test-IsInternetSource {
    [CmdletBinding()]
    param([Parameter(Position = 0)] [string[]] $Prefix)
    foreach ($p in @($Prefix)) {
        if ("$p".Trim() -in @('*', 'Internet', '0.0.0.0/0', '0.0.0.0', 'Any', '::/0')) { return $true }
    }
    return $false
}

# Expand an NSG port field ("22", "20-25", "*", "22,3389") and test whether it covers a port.
function Test-PortInRange {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)] [AllowEmptyCollection()] [string[]] $PortRange,
        [Parameter(Mandatory, Position = 1)] [int] $Port
    )
    foreach ($entry in @($PortRange)) {
        foreach ($part in ("$entry" -split ',')) {
            $t = $part.Trim()
            if ($t -eq '*') { return $true }
            if ($t -match '^(\d+)-(\d+)$') {
                if ($Port -ge [int]$Matches[1] -and $Port -le [int]$Matches[2]) { return $true }
            }
            elseif ($t -match '^\d+$' -and [int]$t -eq $Port) { return $true }
        }
    }
    return $false
}

# Classify an inbound NSG rule. Returns $null when the rule is not an internet-facing allow.
# FAIL when it exposes a management port, WARN for any other port.
function Get-NsgRuleExposure {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Rule,
        [int[]] $ManagementPorts = @(22, 3389, 5985, 5986)
    )
    $direction = "$(Get-PropValue $Rule 'Direction')"
    $access    = "$(Get-PropValue $Rule 'Access')"
    if ($direction -ne 'Inbound' -or $access -ne 'Allow') { return $null }
    $src = @(Get-PropValue $Rule 'SourceAddressPrefix', 'SourceAddressPrefixes')
    if (-not (Test-IsInternetSource $src)) { return $null }
    $ports = @(Get-PropValue $Rule 'DestinationPortRange', 'DestinationPortRanges')
    $hitMgmt = @($ManagementPorts | Where-Object { Test-PortInRange -PortRange $ports -Port $_ })
    [pscustomobject]@{
        Status          = $(if ($hitMgmt) { 'FAIL' } else { 'WARN' })
        ManagementPorts = $hitMgmt
        Ports           = ($ports -join ',')
    }
}

# Is a policy effect one that blocks or changes resources (a guardrail), or audit only?
function Get-PolicyEffectClass {
    [CmdletBinding()]
    param([Parameter(Position = 0)] [string] $Effect)
    if ("$Effect".ToLowerInvariant() -in @('deny', 'denyaction', 'modify', 'append', 'deployifnotexists')) { return 'Enforced' }
    return 'Audit'
}

# Hours since a timestamp, or $null.
function Get-AgeHours {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)] $Timestamp,
        [datetime] $Now = [datetime]::UtcNow
    )
    if ($null -eq $Timestamp -or "$Timestamp" -eq '') { return $null }
    $t = ([datetime]$Timestamp).ToUniversalTime()
    return [int][math]::Floor(($Now - $t).TotalHours)
}

# A guest account signs in as user_domain#EXT#@tenant.onmicrosoft.com.
function Test-IsGuestPrincipal {
    [CmdletBinding()]
    param([Parameter(Position = 0)] [string] $SignInName)
    return ("$SignInName" -match '#EXT#')
}

# Markdown report text.
function ConvertTo-PostureMarkdown {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Findings,
        [Parameter(Mandatory)] [hashtable] $Context
    )
    $s = Get-PostureVerdict -Findings $Findings
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('# Azure posture check')
    [void]$sb.AppendLine()
    [void]$sb.AppendLine(('Run {0} UTC | subscription `{1}` | scope `{2}` | tool v{3} | read-only' -f $Context.Run, $Context.Subscription, $Context.Scope, $Context.Version))
    [void]$sb.AppendLine()
    [void]$sb.AppendLine(('**{0}**: {1} pass, {2} warn, {3} fail' -f $s.Verdict, $s.Pass, $s.Warn, $s.Fail))
    foreach ($area in ($Findings | ForEach-Object Area | Select-Object -Unique)) {
        [void]$sb.AppendLine()
        [void]$sb.AppendLine("## $area")
        [void]$sb.AppendLine()
        [void]$sb.AppendLine('| Status | Check | Resource | Detail | Controls |')
        [void]$sb.AppendLine('|---|---|---|---|---|')
        foreach ($f in ($Findings | Where-Object Area -eq $area)) {
            $cells = @($f.Status, $f.Check, $f.Resource, $f.Detail, $f.Controls) | ForEach-Object { "$_" -replace '\|', '\|' -replace "`r?`n", ' ' }
            [void]$sb.AppendLine('| ' + ($cells -join ' | ') + ' |')
        }
    }
    return $sb.ToString()
}

# SHA-256 manifest so the evidence folder can show it was not edited after the run.
function Write-EvidenceManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Folder,
        [Parameter(Mandatory)] [hashtable] $Context
    )
    $files = Get-ChildItem -Path $Folder -File | Where-Object Name -ne 'MANIFEST.json' | Sort-Object Name
    $manifest = [ordered]@{
        generatedAt = (Get-Date).ToUniversalTime().ToString('o')
        tool        = "Invoke-AzurePostureCheck v$($Context.Version)"
        operator    = $Context.Operator
        files       = @($files | ForEach-Object { [ordered]@{ name = $_.Name; bytes = $_.Length; sha256 = (Get-FileHash -Path $_.FullName -Algorithm SHA256).Hash } })
    }
    $path = Join-Path $Folder 'MANIFEST.json'
    $manifest | ConvertTo-Json -Depth 5 | Set-Content -Path $path -Encoding utf8
    return $path
}

Export-ModuleMember -Function Get-PropValue, Get-ResourceLeaf, New-Finding, Get-PostureVerdict, Get-PostureExitCode,
    Test-IsInternetSource, Test-PortInRange, Get-NsgRuleExposure, Get-PolicyEffectClass, Get-AgeHours,
    Test-IsGuestPrincipal, ConvertTo-PostureMarkdown, Write-EvidenceManifest
