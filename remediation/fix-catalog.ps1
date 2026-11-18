<#
    fix-catalog.ps1  (SKELETON)
    The fixes Invoke-PhasedRemediation knows about. Dot-sourced; returns an array.

    Every fix has the same shape:
      Id, Phase, Title       what and when
      Disruption             Low / Medium / High: chance it affects the running workload
      ConfirmFirst           what to confirm with the workload owner before applying
      Test   { param($Ctx) } returns [pscustomobject]@{ Compliant = <bool>; Detail = <string> }
      Apply  { param($Ctx) } makes the change, or returns 'Manual' when the change
                             must be made by hand (documented, not automated)
      Rollback               how to undo, in words

    Phases run in order of rising risk:
      Report   : nothing changes, every fix is only tested
      Safe     : additive settings the workload cannot notice
      Network  : changes that can block traffic if an exception was missed
      Identity : changes that can lock a person or a process out
      Advisory : fixes pulled forward because of a specific threat advisory
#>

@(
    # ------------------------------------------------------------- Safe
    [pscustomobject]@{
        Id = 'FX-S01'; Phase = 'Safe'; Disruption = 'Low'
        Title = 'Defender for Cloud alerts reach a shared mailbox'
        ConfirmFirst = 'The mailbox is monitored.'
        Test = {
            param($Ctx)
            $c = Get-AzSecurityContact | Select-Object -First 1
            [pscustomobject]@{ Compliant = [bool]($c -and $c.Email); Detail = "contact: $(if ($c) { $c.Email } else { 'none' })" }
        }
        Apply = {
            param($Ctx)
            Set-AzSecurityContact -Name 'default' -Email $Ctx.AlertEmail -AlertAdmin -NotifyOnAlert | Out-Null
        }
        Rollback = 'Remove-AzSecurityContact -Name default'
    }
    [pscustomobject]@{
        Id = 'FX-S02'; Phase = 'Safe'; Disruption = 'Low'
        Title = 'VMs assess missing patches automatically'
        ConfirmFirst = 'Assessment only; installing patches stays on the maintenance schedule.'
        Test = {
            param($Ctx)
            $bad = @(Get-AzVM | Where-Object { $_.OSProfile.LinuxConfiguration.PatchSettings.AssessmentMode -ne 'AutomaticByPlatform' } | ForEach-Object Name)
            [pscustomobject]@{ Compliant = ($bad.Count -eq 0); Detail = if ($bad) { 'not set: ' + ($bad -join ', ') } else { 'all VMs' } }
        }
        Apply = {
            param($Ctx)
            foreach ($vm in (Get-AzVM | Where-Object { $_.OSProfile.LinuxConfiguration.PatchSettings.AssessmentMode -ne 'AutomaticByPlatform' })) {
                $vm.OSProfile.LinuxConfiguration.PatchSettings.AssessmentMode = 'AutomaticByPlatform'
                Update-AzVM -ResourceGroupName $vm.ResourceGroupName -VM $vm | Out-Null
            }
        }
        Rollback = 'Set AssessmentMode back to ImageDefault on the VM.'
    }
    [pscustomobject]@{
        Id = 'FX-S03'; Phase = 'Safe'; Disruption = 'Low'
        Title = 'Machine configuration (guest configuration) extension installed'
        ConfirmFirst = 'The extension only reports; it does not change the guest unless a policy says so.'
        Test = {
            param($Ctx)
            $bad = @(Get-AzVM | Where-Object { -not (Get-AzVMExtension -ResourceGroupName $_.ResourceGroupName -VMName $_.Name -Name 'AzurePolicyforLinux' -ErrorAction SilentlyContinue) } | ForEach-Object Name)
            [pscustomobject]@{ Compliant = ($bad.Count -eq 0); Detail = if ($bad) { 'missing on: ' + ($bad -join ', ') } else { 'all VMs' } }
        }
        Apply = {
            param($Ctx)
            foreach ($vm in Get-AzVM) {
                Set-AzVMExtension -ResourceGroupName $vm.ResourceGroupName -VMName $vm.Name -Location $vm.Location `
                    -Name 'AzurePolicyforLinux' -Publisher 'Microsoft.GuestConfiguration' -ExtensionType 'ConfigurationForLinux' `
                    -TypeHandlerVersion '1.0' -EnableAutomaticUpgrade $true | Out-Null
            }
        }
        Rollback = 'Remove-AzVMExtension -Name AzurePolicyforLinux'
    }

    # ------------------------------------------------------------- Network
    [pscustomobject]@{
        Id = 'FX-N01'; Phase = 'Network'; Disruption = 'Medium'
        Title = 'WAF policies run in Prevention mode'
        ConfirmFirst = 'Detection-mode logs show no legitimate request would be blocked (webhook paths need Allow rules first).'
        Test = {
            param($Ctx)
            $bad = @(Get-AzApplicationGatewayFirewallPolicy | Where-Object { $_.PolicySettings.Mode -ne 'Prevention' } | ForEach-Object Name)
            [pscustomobject]@{ Compliant = ($bad.Count -eq 0); Detail = if ($bad) { 'Detection: ' + ($bad -join ', ') } else { 'all Prevention' } }
        }
        Apply = {
            param($Ctx)
            foreach ($p in (Get-AzApplicationGatewayFirewallPolicy | Where-Object { $_.PolicySettings.Mode -ne 'Prevention' })) {
                $p.PolicySettings.Mode = 'Prevention'
                Set-AzApplicationGatewayFirewallPolicy -InputObject $p | Out-Null
            }
        }
        Rollback = 'Set the policy mode back to Detection.'
    }
    [pscustomobject]@{
        Id = 'FX-N02'; Phase = 'Network'; Disruption = 'High'
        Title = 'Outbound HTTPS limited to an allow-list (no 443 to any host)'
        ConfirmFirst = 'The full list of outbound destinations the workload calls (payment, email, update mirrors).'
        Test = {
            param($Ctx)
            $open = @(Get-AzNetworkSecurityGroup | ForEach-Object {
                $n = $_.Name
                $_.SecurityRules | Where-Object { $_.Direction -eq 'Outbound' -and $_.Access -eq 'Allow' -and
                    (@($_.DestinationPortRange) -contains '443') -and (@($_.DestinationAddressPrefix) | Where-Object { $_ -in '*', 'Internet' }) } |
                    ForEach-Object { "$n/$($_.Name)" }
            })
            [pscustomobject]@{ Compliant = ($open.Count -eq 0); Detail = if ($open) { 'open: ' + ($open -join ', ') } else { 'none open' } }
        }
        Apply = { param($Ctx) 'Manual' }   # needs the agreed allow-list; see landing-zone-stamp spoke.bicep
        Rollback = 'Re-add the previous rule from the evidence of the run before.'
    }
    [pscustomobject]@{
        Id = 'FX-N03'; Phase = 'Network'; Disruption = 'High'
        Title = 'Storage accounts not reachable from public networks'
        ConfirmFirst = 'Nothing outside the VNet (release uploads, exports, a vendor) writes to the account.'
        Test = {
            param($Ctx)
            $bad = @(Get-AzStorageAccount | Where-Object { $_.PublicNetworkAccess -ne 'Disabled' } | ForEach-Object StorageAccountName)
            [pscustomobject]@{ Compliant = ($bad.Count -eq 0); Detail = if ($bad) { 'public: ' + ($bad -join ', ') } else { 'all private' } }
        }
        Apply = {
            param($Ctx)
            foreach ($s in (Get-AzStorageAccount | Where-Object { $_.PublicNetworkAccess -ne 'Disabled' })) {
                if ($Ctx.IsExcepted('FX-N03', $s.StorageAccountName)) { continue }
                Set-AzStorageAccount -ResourceGroupName $s.ResourceGroupName -Name $s.StorageAccountName -PublicNetworkAccess Disabled | Out-Null
            }
        }
        Rollback = 'Set-AzStorageAccount -PublicNetworkAccess Enabled'
    }

    # ------------------------------------------------------------- Identity
    [pscustomobject]@{
        Id = 'FX-I01'; Phase = 'Identity'; Disruption = 'High'
        Title = 'No standing Owner held by individual users'
        ConfirmFirst = 'A group or just-in-time path exists for each person who needs Owner.'
        Test = {
            param($Ctx)
            $owners = @(Get-AzRoleAssignment -Scope "/subscriptions/$($Ctx.SubscriptionId)" -RoleDefinitionName Owner |
                Where-Object { $_.ObjectType -eq 'User' -and $_.Scope -eq "/subscriptions/$($Ctx.SubscriptionId)" } | ForEach-Object DisplayName)
            [pscustomobject]@{ Compliant = ($owners.Count -eq 0); Detail = if ($owners) { 'users: ' + $owners.Count } else { 'none' } }
        }
        Apply = { param($Ctx) 'Manual' }   # removing access is a decision, not a script step
        Rollback = 'Re-assign the role from the evidence of the run before.'
    }

    # ------------------------------------------------------------- Advisory
    [pscustomobject]@{
        Id = 'FX-A01'; Phase = 'Advisory'; Disruption = 'Medium'
        Title = 'Alert on new role assignments at subscription scope'
        ConfirmFirst = 'Who receives the alert, and that the build pipeline is excluded or expected.'
        Test = {
            param($Ctx)
            $rule = Get-AzActivityLogAlert | Where-Object { $_.ConditionAllOf.Equal -contains 'Microsoft.Authorization/roleAssignments/write' }
            [pscustomobject]@{ Compliant = [bool]$rule; Detail = if ($rule) { $rule[0].Name } else { 'no alert' } }
        }
        Apply = { param($Ctx) 'Manual' }   # deploy from security-assessment-toolkit/logging/kql, then fire-test it
        Rollback = 'Delete the alert rule.'
    }
)
