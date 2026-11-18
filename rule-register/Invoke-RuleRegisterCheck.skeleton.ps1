<#
.SYNOPSIS
    SKELETON. Grades a governance rule register against a tenant. Read-only.

.DESCRIPTION
    azure-posture-check asks "is this subscription hardened?" with a fixed set of
    checks. This script asks a different question: "is the tenant still obeying
    OUR rules?" The rules live in a JSON register (rules.example.json), one row
    per rule, each with its own severity and framework references. The script:

      1. loads the register
      2. collects state  (live: Resource Graph + Graph; offline: a saved state file)
      3. grades every rule: Pass / Fail / Not applicable / Could not check
      4. writes report.md, results.json, results.csv and a SHA-256 MANIFEST.json

    Collection and grading are separate on purpose: the state file of a run is
    itself evidence, and any run can be re-graded later against a newer register.

.EXAMPLE
    ./Invoke-RuleRegisterCheck.skeleton.ps1 -StateFile ./examples/sample-state.json

.EXAMPLE
    Connect-AzAccount -Tenant <tenant-id>
    ./Invoke-RuleRegisterCheck.skeleton.ps1 -SubscriptionId <subscription-id> -SaveState
#>
[CmdletBinding()]
param(
    [string] $RegisterFile = (Join-Path $PSScriptRoot 'rules.example.json'),
    [string] $SubscriptionId,
    [string] $StateFile,
    [string] $OutputPath = './evidence',
    [switch] $SaveState,
    [ValidateSet('None', 'Fail')] [string] $FailOn = 'None'
)

$ErrorActionPreference = 'Stop'
$ScriptVersion = '1.0.0-skeleton'
Import-Module (Join-Path $PSScriptRoot 'RuleRegister.psm1') -Force

# ------------------------------------------------------------------ 1. register
$register = Get-Content -Raw -Path $RegisterFile | ConvertFrom-Json
$rules = @($register.rules)
Write-Host "Register: $($register.register) v$($register.version), $($rules.Count) rules"

# ------------------------------------------------------------------ 2. state
function Get-LiveState {
    <# Read-only collection. Resource Graph for Azure resources and role
       assignments; Graph for Entra settings (left as TODO in the skeleton,
       so those rules report "Could not check" rather than a guess). #>
    param([string]$SubscriptionId, [object[]]$Rules)

    $types = @($Rules | Where-Object { $_.check.resourceType -and $_.check.resourceType -ne 'roleAssignment' } |
        ForEach-Object { $_.check.resourceType.ToLowerInvariant() } | Sort-Object -Unique)
    $typeList = ($types | ForEach-Object { "'$_'" }) -join ','
    $query = "resources | where type in~ ($typeList) | project name, type, properties, tags"
    $resources = @(Search-AzGraph -Query $query -Subscription $SubscriptionId -First 1000)

    $roles = @(Get-AzRoleAssignment -Scope "/subscriptions/$SubscriptionId" |
        Where-Object { $_.Scope -eq "/subscriptions/$SubscriptionId" -and $_.ObjectType -eq 'User' } |
        ForEach-Object { [pscustomobject]@{ name = $_.DisplayName; type = 'roleAssignment'; role = $_.RoleDefinitionName } })

    $settings = [ordered]@{
        entra = [ordered]@{}   # TODO: Graph policies/authorizationPolicy, break-glass naming convention
        azure = [ordered]@{}   # TODO: Get-AzDiagnosticSetting -SubscriptionId for the activity log export
    }
    [pscustomobject]@{ settings = [pscustomobject]$settings; resources = @($resources) + $roles }
}

if ($StateFile) {
    $state = Get-Content -Raw -Path $StateFile | ConvertFrom-Json
    $mode = "offline ($([IO.Path]::GetFileName($StateFile)))"
} elseif ($SubscriptionId) {
    $state = Get-LiveState -SubscriptionId $SubscriptionId -Rules $rules
    $mode = 'live'
} else {
    throw 'Pass -SubscriptionId (live) or -StateFile (offline).'
}

# ------------------------------------------------------------------ 3. grade
$results = @(foreach ($r in $rules) { Invoke-RuleEvaluation -Rule $r -State $state })
$summary = Get-RegisterSummary -Results $results
$results | Select-Object RuleId, Status, Severity, Title, Detail | Format-Table -AutoSize | Out-String | Write-Host

# ------------------------------------------------------------------ 4. write
$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss') + 'Z'
$dir = Join-Path $OutputPath "rule-register-$stamp"
New-Item -ItemType Directory -Path $dir -Force | Out-Null

$md = New-Object System.Text.StringBuilder
[void]$md.AppendLine('# Rule register check')
[void]$md.AppendLine('')
[void]$md.AppendLine("Register: $($register.register) v$($register.version)  ")
[void]$md.AppendLine("Mode: $mode  ")
[void]$md.AppendLine("Run (UTC): $stamp  ")
[void]$md.AppendLine("Score: $($summary.ScorePercent)% ($($summary.Pass) pass, $($summary.Fail) fail, $($summary.NotApplicable) not applicable, $($summary.CouldNotCheck) could not check)")
[void]$md.AppendLine('')
[void]$md.AppendLine('| Rule | Status | Severity | Title | Detail | Frameworks |')
[void]$md.AppendLine('|---|---|---|---|---|---|')
foreach ($x in ($results | Sort-Object @{ e = { @('Fail', 'Could not check', 'Pass', 'Not applicable').IndexOf($_.Status) } }, RuleId)) {
    $detail = $x.Detail
    if ($x.Failing.Count) { $detail += ': ' + ($x.Failing -join ', ') }
    [void]$md.AppendLine("| $($x.RuleId) | $($x.Status) | $($x.Severity) | $($x.Title) | $($detail -replace '\|', '/') | $($x.Frameworks) |")
}
Set-Content -Path (Join-Path $dir 'report.md') -Value $md.ToString() -Encoding utf8
@{ tool = "Invoke-RuleRegisterCheck $ScriptVersion"; mode = $mode; summary = $summary; results = $results } |
    ConvertTo-Json -Depth 6 | Set-Content -Path (Join-Path $dir 'results.json') -Encoding utf8
$results | Select-Object RuleId, Status, Severity, Scope, Title, Detail, @{ n = 'Failing'; e = { $_.Failing -join '; ' } }, Frameworks |
    Export-Csv -Path (Join-Path $dir 'results.csv') -NoTypeInformation -Encoding utf8
if ($SaveState -and -not $StateFile) {
    $state | ConvertTo-Json -Depth 20 | Set-Content -Path (Join-Path $dir 'state.json') -Encoding utf8
}

$manifest = Get-ChildItem $dir -File | Sort-Object Name | ForEach-Object {
    [ordered]@{ file = $_.Name; sha256 = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower() }
}
@{ tool = "Invoke-RuleRegisterCheck $ScriptVersion"; run = $stamp; files = @($manifest) } |
    ConvertTo-Json -Depth 4 | Set-Content -Path (Join-Path $dir 'MANIFEST.json') -Encoding utf8

Write-Host ("Score {0}%  |  {1} pass, {2} fail  |  evidence: {3}" -f $summary.ScorePercent, $summary.Pass, $summary.Fail, $dir)
if ($FailOn -eq 'Fail' -and $summary.Fail -gt 0) { exit 1 }
