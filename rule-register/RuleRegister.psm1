<#
    RuleRegister.psm1  (SKELETON)
    Pure functions behind Invoke-RuleRegisterCheck. No Azure or Graph calls here,
    so every decision can be unit tested (tests/RuleRegister.Tests.ps1).

    A rule register is your own governance rules written down as data:
    "every Key Vault has purge protection", "no more than two public IPs",
    "guests cannot invite guests". The grader reads the register, reads the
    tenant state, and grades each rule. Adding a rule means adding a JSON row,
    not writing code.
#>

function Get-PathValue {
    <# Reads a dotted path from nested objects or hashtables.
       Numeric segments index into arrays: properties.ipConfigurations.0.properties.publicIPAddress
       Returns $null when any segment is missing. #>
    [CmdletBinding()]
    param($InputObject, [string]$Path)

    $cur = $InputObject
    foreach ($seg in ($Path -split '\.')) {
        if ($null -eq $cur) { return $null }
        if ($seg -match '^\d+$') {
            $arr = @($cur)
            $i = [int]$seg
            if ($i -ge $arr.Count) { return $null }
            $cur = $arr[$i]
        } elseif ($cur -is [System.Collections.IDictionary]) {
            $key = @($cur.Keys) | Where-Object { "$_" -ieq $seg } | Select-Object -First 1
            if ($null -eq $key) { return $null }
            $cur = $cur[$key]
        } else {
            $prop = $cur.PSObject.Properties | Where-Object { $_.Name -ieq $seg } | Select-Object -First 1
            if ($null -eq $prop) { return $null }
            $cur = $prop.Value
        }
    }
    , $cur
}

function Test-Condition {
    <# Compares an actual value with the rule's expectation.
       Operators: eq, ne, in, notin, exists, notexists, gte, lte, contains. #>
    [CmdletBinding()]
    param($Actual, [Parameter(Mandatory)][string]$Operator, $Expected)

    $present = -not ($null -eq $Actual -or ($Actual -is [string] -and $Actual -eq ''))
    switch ($Operator.ToLowerInvariant()) {
        'exists'    { return $present }
        'notexists' { return -not $present }
        'eq'        { return $present -and ("$Actual" -ieq "$Expected") }
        'ne'        { return -not ($present -and ("$Actual" -ieq "$Expected")) }
        'in'        { return $present -and (@($Expected | ForEach-Object { "$_".ToLowerInvariant() }) -contains "$Actual".ToLowerInvariant()) }
        'notin'     { return -not ($present -and (@($Expected | ForEach-Object { "$_".ToLowerInvariant() }) -contains "$Actual".ToLowerInvariant())) }
        'gte'       { return $present -and ([double]$Actual -ge [double]$Expected) }
        'lte'       { return $present -and ([double]$Actual -le [double]$Expected) }
        'contains'  { return $present -and ("$Actual" -ilike "*$Expected*") }
        default     { throw "Unknown operator '$Operator'" }
    }
}

function Get-MatchingResource {
    <# Resources of one type, optionally narrowed by a 'where' condition. #>
    [CmdletBinding()]
    param($State, [string]$Type, $Where)

    $all = @($State.resources | Where-Object { "$($_.type)" -ieq $Type })
    if ($Where) {
        $all = @($all | Where-Object { Test-Condition -Actual (Get-PathValue $_ $Where.path) -Operator $Where.operator -Expected $Where.value })
    }
    , $all
}

function New-RuleResult {
    param($Rule, [string]$Status, [string]$Detail, [string[]]$Failing = @())
    [pscustomobject]@{
        RuleId     = $Rule.id
        Title      = $Rule.title
        Scope      = $Rule.scope
        Severity   = $Rule.severity
        Status     = $Status
        Detail     = $Detail
        Failing    = @($Failing)
        Frameworks = (@($Rule.frameworks) -join '; ')
    }
}

function Invoke-RuleEvaluation {
    <# Grades one rule against the collected state.
       Status: Pass, Fail, Not applicable, Could not check. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Rule, [Parameter(Mandatory)]$State)

    $c = $Rule.check
    try {
        switch ($c.type) {
            'resource' {
                $targets = Get-MatchingResource -State $State -Type $c.resourceType -Where $c.where
                if ($targets.Count -eq 0) { return New-RuleResult $Rule 'Not applicable' "no $($c.resourceType) in scope" }
                $bad = @($targets | Where-Object { -not (Test-Condition -Actual (Get-PathValue $_ $c.path) -Operator $c.operator -Expected $c.value) })
                if ($bad.Count -eq 0) { return New-RuleResult $Rule 'Pass' "$($targets.Count) of $($targets.Count) compliant" }
                return New-RuleResult $Rule 'Fail' "$($bad.Count) of $($targets.Count) non-compliant" (@($bad | ForEach-Object name))
            }
            'resourceCount' {
                $n = (Get-MatchingResource -State $State -Type $c.resourceType -Where $c.where).Count
                $okMin = ($null -eq $c.min) -or ($n -ge [int]$c.min)
                $okMax = ($null -eq $c.max) -or ($n -le [int]$c.max)
                $status = if ($okMin -and $okMax) { 'Pass' } else { 'Fail' }
                return New-RuleResult $Rule $status "found $n (allowed: $(if ($null -ne $c.min) { "min $($c.min) " })$(if ($null -ne $c.max) { "max $($c.max)" }))"
            }
            'setting' {
                $actual = Get-PathValue $State.settings $c.path
                if ($null -eq $actual) { return New-RuleResult $Rule 'Could not check' "setting '$($c.path)' not collected" }
                $ok = Test-Condition -Actual $actual -Operator $c.operator -Expected $c.value
                return New-RuleResult $Rule $(if ($ok) { 'Pass' } else { 'Fail' }) "actual: $actual"
            }
            default { return New-RuleResult $Rule 'Could not check' "unknown check type '$($c.type)'" }
        }
    } catch {
        return New-RuleResult $Rule 'Could not check' $_.Exception.Message
    }
}

function Get-RegisterSummary {
    <# Counts by status, and a score where Pass = 1 and Fail = 0. Not applicable and
       Could not check are left out, so a missing permission cannot move the score. #>
    [CmdletBinding()]
    param([object[]]$Results)

    $graded = @($Results | Where-Object { $_.Status -in 'Pass', 'Fail' })
    $pass = @($graded | Where-Object Status -eq 'Pass').Count
    [pscustomobject]@{
        Total          = @($Results).Count
        Pass           = $pass
        Fail           = @($graded | Where-Object Status -eq 'Fail').Count
        NotApplicable  = @($Results | Where-Object Status -eq 'Not applicable').Count
        CouldNotCheck  = @($Results | Where-Object Status -eq 'Could not check').Count
        ScorePercent   = if ($graded.Count) { [math]::Round(100 * $pass / $graded.Count, 1) } else { $null }
    }
}

Export-ModuleMember -Function Get-PathValue, Test-Condition, Get-MatchingResource, Invoke-RuleEvaluation, Get-RegisterSummary
