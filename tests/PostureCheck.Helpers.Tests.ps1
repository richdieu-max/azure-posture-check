#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'src' 'PostureCheck.Helpers.psm1') -Force
}

Describe 'Get-PropValue' {
    It 'returns the first property that has a value' {
        $o = [pscustomobject]@{ A = $null; B = 'b' }
        Get-PropValue $o 'A', 'B' | Should -Be 'b'
    }
    It 'returns null for a missing property or a null object' {
        Get-PropValue ([pscustomobject]@{ A = 1 }) 'Z' | Should -BeNullOrEmpty
        Get-PropValue $null 'A' | Should -BeNullOrEmpty
    }
    It 'reads hashtables' {
        Get-PropValue @{ Mode = 'Prevention' } 'Mode' | Should -Be 'Prevention'
    }
}

Describe 'Get-ResourceLeaf' {
    It 'returns the last segment of a resource ID' {
        Get-ResourceLeaf '/subscriptions/x/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg-app' | Should -Be 'nsg-app'
    }
    It 'handles empty input' { Get-ResourceLeaf '' | Should -Be '' }
}

Describe 'Test-PortInRange' {
    It 'matches single ports, ranges, lists and wildcards' {
        Test-PortInRange '22' 22 | Should -BeTrue
        Test-PortInRange '20-25' 22 | Should -BeTrue
        Test-PortInRange '80,443' 443 | Should -BeTrue
        Test-PortInRange '*' 3389 | Should -BeTrue
    }
    It 'does not match ports outside the range' {
        Test-PortInRange '443' 22 | Should -BeFalse
        Test-PortInRange '1000-2000' 3389 | Should -BeFalse
    }
}

Describe 'Get-NsgRuleExposure' {
    It 'fails an internet allow on a management port' {
        $r = [pscustomobject]@{ Direction = 'Inbound'; Access = 'Allow'; SourceAddressPrefix = 'Internet'; DestinationPortRange = '3389' }
        (Get-NsgRuleExposure -Rule $r).Status | Should -Be 'FAIL'
    }
    It 'warns on an internet allow on another port' {
        $r = [pscustomobject]@{ Direction = 'Inbound'; Access = 'Allow'; SourceAddressPrefix = '*'; DestinationPortRange = '443' }
        (Get-NsgRuleExposure -Rule $r).Status | Should -Be 'WARN'
    }
    It 'ignores private sources, deny rules and outbound rules' {
        Get-NsgRuleExposure -Rule ([pscustomobject]@{ Direction = 'Inbound'; Access = 'Allow'; SourceAddressPrefix = 'VirtualNetwork'; DestinationPortRange = '22' }) | Should -BeNullOrEmpty
        Get-NsgRuleExposure -Rule ([pscustomobject]@{ Direction = 'Inbound'; Access = 'Deny'; SourceAddressPrefix = '*'; DestinationPortRange = '*' }) | Should -BeNullOrEmpty
        Get-NsgRuleExposure -Rule ([pscustomobject]@{ Direction = 'Outbound'; Access = 'Allow'; SourceAddressPrefix = '*'; DestinationPortRange = '443' }) | Should -BeNullOrEmpty
    }
}

Describe 'Get-PolicyEffectClass' {
    It 'classes guardrail effects as Enforced' {
        'deny', 'Modify', 'DeployIfNotExists', 'append', 'denyAction' | ForEach-Object { Get-PolicyEffectClass $_ | Should -Be 'Enforced' }
    }
    It 'classes everything else as Audit' {
        'audit', 'AuditIfNotExists', '' | ForEach-Object { Get-PolicyEffectClass $_ | Should -Be 'Audit' }
    }
}

Describe 'Get-AgeHours' {
    It 'computes whole hours' {
        $now = [datetime]'2026-01-02T12:00:00Z'
        Get-AgeHours ([datetime]'2026-01-02T02:30:00Z') -Now $now | Should -Be 9
    }
    It 'returns null for no timestamp' { Get-AgeHours $null | Should -BeNullOrEmpty }
}

Describe 'Test-IsGuestPrincipal' {
    It 'recognises guest sign-in names' {
        Test-IsGuestPrincipal 'someone_example.com#EXT#@tenant.onmicrosoft.com' | Should -BeTrue
        Test-IsGuestPrincipal 'admin@contoso.example' | Should -BeFalse
    }
}

Describe 'Verdict and exit code' {
    BeforeAll {
        $pass = New-Finding -Area A -Check c1 -Status PASS
        $warn = New-Finding -Area A -Check c2 -Status WARN
        $fail = New-Finding -Area B -Check c3 -Status FAIL
    }
    It 'reports the worst state' {
        (Get-PostureVerdict -Findings @($pass)).Verdict | Should -Be 'ALL GOOD'
        (Get-PostureVerdict -Findings @($pass, $warn)).Verdict | Should -Be 'HEALTHY, WITH OPEN ITEMS'
        (Get-PostureVerdict -Findings @($pass, $warn, $fail)).Verdict | Should -Be 'ATTENTION NEEDED'
    }
    It 'follows the FailOn policy' {
        Get-PostureExitCode -Findings @($warn) -FailOn None | Should -Be 0
        Get-PostureExitCode -Findings @($warn) -FailOn Fail | Should -Be 0
        Get-PostureExitCode -Findings @($warn) -FailOn Warn | Should -Be 1
        Get-PostureExitCode -Findings @($fail) -FailOn Fail | Should -Be 1
    }
}

Describe 'ConvertTo-PostureMarkdown' {
    It 'writes one table per area and escapes pipes' {
        $f = @(
            (New-Finding -Area Network -Check 'NSG' -Status FAIL -Detail 'a|b' -Controls 'SC-7'),
            (New-Finding -Area Logging -Check 'Export' -Status PASS)
        )
        $md = ConvertTo-PostureMarkdown -Findings $f -Context @{ Run = 'r'; Subscription = 's'; Scope = 'all'; Version = '1.0.0' }
        $md | Should -Match '## Network'
        $md | Should -Match '## Logging'
        $md | Should -Match 'a\\\|b'
        $md | Should -Match 'ATTENTION NEEDED'
    }
}

Describe 'Write-EvidenceManifest' {
    It 'hashes every file in the folder' {
        $dir = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid())
        New-Item -ItemType Directory -Path $dir | Out-Null
        Set-Content -Path (Join-Path $dir 'report.md') -Value 'hello'
        $path = Write-EvidenceManifest -Folder $dir -Context @{ Version = '1.0.0'; Operator = 'tester' }
        $m = Get-Content $path -Raw | ConvertFrom-Json
        $m.files.Count | Should -Be 1
        $m.files[0].sha256 | Should -Be (Get-FileHash (Join-Path $dir 'report.md') -Algorithm SHA256).Hash
        Remove-Item $dir -Recurse -Force
    }
}
