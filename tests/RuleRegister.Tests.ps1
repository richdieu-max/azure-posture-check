#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'rule-register' 'RuleRegister.psm1') -Force
    $script:root = Join-Path $PSScriptRoot '..' 'rule-register'
}

Describe 'Get-PathValue' {
    It 'reads nested properties case-insensitively' {
        $o = [pscustomobject]@{ properties = [pscustomobject]@{ EnablePurgeProtection = $true } }
        Get-PathValue $o 'properties.enablePurgeProtection' | Should -BeTrue
    }
    It 'indexes arrays with numeric segments' {
        $o = [pscustomobject]@{ list = @([pscustomobject]@{ v = 'first' }, [pscustomobject]@{ v = 'second' }) }
        Get-PathValue $o 'list.1.v' | Should -Be 'second'
        Get-PathValue $o 'list.5.v' | Should -BeNullOrEmpty
    }
    It 'reads hashtables' {
        Get-PathValue @{ a = @{ b = 3 } } 'a.b' | Should -Be 3
    }
    It 'returns null for a missing segment' {
        Get-PathValue ([pscustomobject]@{ a = 1 }) 'a.b.c' | Should -BeNullOrEmpty
    }
}

Describe 'Test-Condition' {
    It 'eq compares case-insensitively and handles booleans' {
        Test-Condition 'Disabled' 'eq' 'disabled' | Should -BeTrue
        Test-Condition $false 'eq' $false | Should -BeTrue
        Test-Condition $true 'eq' $false | Should -BeFalse
    }
    It 'eq fails when the value is missing' {
        Test-Condition $null 'eq' 'x' | Should -BeFalse
    }
    It 'in and notin use lists' {
        Test-Condition 'Locked' 'in' @('Unlocked', 'Locked') | Should -BeTrue
        Test-Condition 'Disabled' 'in' @('Unlocked', 'Locked') | Should -BeFalse
        Test-Condition 'Disabled' 'notin' @('Unlocked', 'Locked') | Should -BeTrue
    }
    It 'exists and notexists treat empty strings as absent' {
        Test-Condition '' 'exists' $null | Should -BeFalse
        Test-Condition $null 'notexists' $null | Should -BeTrue
        Test-Condition 'x' 'notexists' $null | Should -BeFalse
    }
    It 'gte and lte compare numbers' {
        Test-Condition 2 'gte' 2 | Should -BeTrue
        Test-Condition 1 'gte' 2 | Should -BeFalse
        Test-Condition 3 'lte' 2 | Should -BeFalse
    }
    It 'throws on an unknown operator' {
        { Test-Condition 1 'between' 2 } | Should -Throw
    }
}

Describe 'Invoke-RuleEvaluation' {
    BeforeAll {
        $script:state = [pscustomobject]@{
            settings  = [pscustomobject]@{ entra = [pscustomobject]@{ userConsentToApps = 'enabled' } }
            resources = @(
                [pscustomobject]@{ name = 'kv-a'; type = 'Microsoft.KeyVault/vaults'; properties = [pscustomobject]@{ publicNetworkAccess = 'Disabled' } }
                [pscustomobject]@{ name = 'kv-b'; type = 'Microsoft.KeyVault/vaults'; properties = [pscustomobject]@{ publicNetworkAccess = 'Enabled' } }
                [pscustomobject]@{ name = 'pip-1'; type = 'Microsoft.Network/publicIPAddresses'; properties = [pscustomobject]@{} }
            )
        }
        function New-TestRule($check) { [pscustomobject]@{ id = 'T'; title = 't'; scope = 'Azure'; severity = 'High'; frameworks = @('x'); check = [pscustomobject]$check } }
    }
    It 'fails a resource rule and names the failing resources' {
        $r = Invoke-RuleEvaluation -Rule (New-TestRule @{ type = 'resource'; resourceType = 'microsoft.keyvault/vaults'; path = 'properties.publicNetworkAccess'; operator = 'eq'; value = 'Disabled' }) -State $state
        $r.Status | Should -Be 'Fail'
        ($r.Failing -join ',') | Should -Be 'kv-b'
    }
    It 'reports Not applicable when no resource of the type exists' {
        $r = Invoke-RuleEvaluation -Rule (New-TestRule @{ type = 'resource'; resourceType = 'microsoft.compute/virtualmachines'; path = 'x'; operator = 'exists' }) -State $state
        $r.Status | Should -Be 'Not applicable'
    }
    It 'counts resources against a maximum' {
        (Invoke-RuleEvaluation -Rule (New-TestRule @{ type = 'resourceCount'; resourceType = 'microsoft.network/publicipaddresses'; max = 2 }) -State $state).Status | Should -Be 'Pass'
        (Invoke-RuleEvaluation -Rule (New-TestRule @{ type = 'resourceCount'; resourceType = 'microsoft.network/publicipaddresses'; max = 0 }) -State $state).Status | Should -Be 'Fail'
    }
    It 'grades settings, and reports Could not check when a setting was not collected' {
        (Invoke-RuleEvaluation -Rule (New-TestRule @{ type = 'setting'; path = 'entra.userConsentToApps'; operator = 'eq'; value = 'disabled' }) -State $state).Status | Should -Be 'Fail'
        (Invoke-RuleEvaluation -Rule (New-TestRule @{ type = 'setting'; path = 'entra.missing'; operator = 'eq'; value = 'x' }) -State $state).Status | Should -Be 'Could not check'
    }
    It 'reports Could not check for an unknown check type instead of throwing' {
        (Invoke-RuleEvaluation -Rule (New-TestRule @{ type = 'nope' }) -State $state).Status | Should -Be 'Could not check'
    }
}

Describe 'Example register against the example state' {
    It 'grades 9 pass and 4 fail' {
        $rules = (Get-Content -Raw (Join-Path $root 'rules.example.json') | ConvertFrom-Json).rules
        $st = Get-Content -Raw (Join-Path $root 'examples' 'sample-state.json') | ConvertFrom-Json
        $results = @(foreach ($r in $rules) { Invoke-RuleEvaluation -Rule $r -State $st })
        $sum = Get-RegisterSummary -Results $results
        $sum.Pass | Should -Be 9
        $sum.Fail | Should -Be 4
        ((@($results | Where-Object Status -eq 'Fail' | ForEach-Object RuleId) | Sort-Object) -join ',') | Should -Be 'R-BK-01,R-ID-01,R-ID-04,R-KV-02'
    }
}
