<#
.SYNOPSIS
     Skeleton ("bones") of Get-TenantHardeningReport.ps1 v3.
     Same architecture as the full script, with one example check per data source,
     so a new check can be added by copying a block. Read-only: every call is a GET
     or a Resource Graph query. Nothing in the tenant is changed.

.HOW THE FULL SCRIPT IS BUILT ON THIS
     1. Parameters and run identity        (what to assess, where to write, run ID + UTC stamp)
     2. Helpers                             (ARM GET, Resource Graph, Graph REST, device-code sign-in)
     3. Framework map + issue keys          (domain -> CIS / CSF / 800-53 / ISO / HIPAA / PCI / STRIDE)
     4. Add-Finding                         (the ONE way a check records a result)
     5. Azure collection                    (per subscription, then per resource type)
     6. Entra ID collection                 (Graph, delegated read-only scopes)
     7. Merge + calibrate                   (same problem from several sources = one finding)
     8. Score                               (Pass 1, Warn 0.5, Fail 0; N/A and Unknown excluded)
     9. Write                               (HTML, tracker CSV, evidence JSON, SHA-256 manifest)

.EXAMPLE
     Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
     .\Get-TenantHardeningReport.skeleton.ps1 -TenantId <tenant-guid>
#>
[CmdletBinding()]
param(
     [Parameter(Mandatory)] [string] $TenantId,
     [string[]] $SubscriptionId,
     [string]   $OutputPath = (Join-Path $HOME 'TenantHealth'),
     [int]      $StaleDays = 90,
     [switch]   $SkipAzure,
     [switch]   $SkipGraph,
     [switch]   $Interactive           # pop-up sign-in instead of device code
)

# ============================================================== 1. run identity
$ScriptVersion = '3.0.1-skeleton'
$ErrorActionPreference = 'Stop'
trap { Write-Host "`nERROR at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)" -ForegroundColor Red; break }
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}
$RunStartUtc = (Get-Date).ToUniversalTime()
$RunId = [guid]::NewGuid().ToString()                         # ties the four output files together
$stamp = $RunStartUtc.ToString('yyyyMMdd-HHmm') + 'Z'
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

# ============================================================== 2. helpers
function Ensure-Module([string]$Name) {
     if (-not (Get-Module -ListAvailable -Name $Name)) { Install-Module $Name -Scope CurrentUser -Force -AllowClobber }
     Import-Module $Name -ErrorAction Stop
}
function Step([string]$m) { Write-Host " - $m" -ForegroundColor Gray }
function UtcIso([datetime]$d) { $d.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }

# Every data source logs OK / Failed / Skipped, so a gap is never silent
$SourceLog = New-Object System.Collections.Generic.List[object]
function Log-Source([string]$Source, [string]$Status, [string]$Detail = '') {
    $SourceLog.Add([pscustomobject]@{ 'Data source'=$Source; Status=$Status; Detail=$Detail })
    if ($Status -ne 'OK') { Write-Warning " $Source - $Status $Detail" }
}

# --- Azure Resource Manager (management plane) via the signed-in Az context
function Invoke-ArmGet([string]$Path) {
    $r = Invoke-AzRestMethod -Path $Path -Method GET
    if ($r.StatusCode -ge 400) { throw "ARM $($r.StatusCode): $($r.Content)" }
    $r.Content | ConvertFrom-Json
}

# --- Azure Resource Graph: one KQL query across every subscription in scope, paged
function Invoke-Arg([string]$Query, [string[]]$Subs) {
    $all = @(); $skip = $null
    do {
        $opts = @{ resultFormat = 'objectArray'; '$top' = 1000 }
        if ($skip) { $opts['$skipToken'] = $skip }
        $body = @{ subscriptions = @($Subs); query = $Query; options = $opts } | ConvertTo-Json -Depth 6
        $r = Invoke-AzRestMethod -Path '/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01' -Method POST -Payload $body
        if ($r.StatusCode -ge 400) { throw "Resource Graph $($r.StatusCode): $($r.Content)" }
        $j = $r.Content | ConvertFrom-Json
        if ($j.data) { $all += $j.data }
        $skip = $j.'$skipToken'
    } while ($skip)
    $all
}

# --- Microsoft Graph via plain REST. No Microsoft.Graph module, so no assembly clash with Az.Accounts on PS 5.1
$script:GraphToken = $null
$GraphClientId = '14d82eec-204b-4c2f-b7e8-296a70dab67e'    # "Microsoft Graph Command Line Tools", Microsoft's own public client
function Invoke-Graph([string]$Uri) {
    try { Invoke-RestMethod -Method GET -Uri $Uri -Headers @{ Authorization = "Bearer $script:GraphToken" } -ErrorAction Stop }
    catch { throw "Graph: $($_.Exception.Message)" }
}
function Get-GraphAll([string]$Uri, [int]$MaxPages = 50) {         # follows @odata.nextLink
    $out = @(); $page = 0
    while ($Uri -and $page -lt $MaxPages) {
        $r = Invoke-Graph $Uri
        if ($null -ne $r.value) { $out += $r.value } else { return $r }
        $Uri = $r.'@odata.nextLink'; $page++
    }
    $out
}
function Get-GraphTokenDeviceCode([string[]]$Scopes) {             # OAuth 2.0 device authorization grant
    $scope = (($Scopes | ForEach-Object { "https://graph.microsoft.com/$_" }) -join ' ') + ' offline_access'
     $base = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0"
     $dc = Invoke-RestMethod -Method POST -Uri "$base/devicecode" -Body @{ client_id = $GraphClientId; scope = $scope }
     Write-Host " $($dc.message)" -ForegroundColor Yellow           # "go to https://microsoft.com/devicelogin and enter XXXXXXXX"
     $deadline = (Get-Date).AddSeconds([int]$dc.expires_in); $wait = [Math]::Max([int]$dc.interval, 5)
     while ((Get-Date) -lt $deadline) {
         Start-Sleep -Seconds $wait
         try {
              $t = Invoke-RestMethod -Method POST -Uri "$base/token" -Body @{ grant_type = 'urn:ietf:params:oauth:grant-type:device_code'; client_id = $GraphClientId; device_code = $dc.device_code }
              return $t.access_token
         } catch {
              $err = try { ($_.ErrorDetails.Message | ConvertFrom-Json).error } catch { '' }
              if ($err -eq 'authorization_pending') { continue }
              if ($err -eq 'slow_down') { $wait += 5; continue }
              throw "Device code sign-in failed: $err"
         }
     }
     throw 'Device code expired before sign-in completed.'
}

# ============================================================== 3. framework map + issue keys
# One row per security domain. Every finding inherits the row for its domain.
$Map = @{
   Identity          = @{ CIS='Identity & Access';    CSF='PR.AA-01, PR.AA-03'; NIST='IA-2, IA-5, AC-2'; ISO='A.5.16, A.5.17, A.8.5'; HIPAA='164.312(d), 164.308(a)(5)(ii)(D)'; PCI='8.2-8.4'; STRIDE='Spoofing' }
   Privileged        = @{ CIS='Identity & Access';    CSF='PR.AA-05';           NIST='AC-2, AC-5, AC-6(5)'; ISO='A.5.3, A.8.2';           HIPAA='164.308(a)(4)';                    PCI='7.2';      STRIDE='Elevation of Privilege' }
   Network           = @{ CIS='Networking';           CSF='PR.IR-01';           NIST='SC-7, AC-17'; ISO='A.8.20, A.8.22';         HIPAA='164.312(e)(1)';                    PCI='1.3, 1.4'; STRIDE='Spoofing / Elevation of Privilege' }
   Compute           = @{ CIS='Virtual Machines';     CSF='PR.PS-01, PR.DS-01'; NIST='CM-6, SC-28'; ISO='A.8.9, A.8.24';          HIPAA='164.312(a)(2)(iv)';                PCI='2.2, 3.5'; STRIDE='Tampering / Information Disclosure' }
   Logging           = @{ CIS='Logging & Monitoring'; CSF='DE.CM-01, PR.PS-04'; NIST='AU-2, AU-6, AU-11'; ISO='A.8.15, A.8.16';         HIPAA='164.312(b)';                       PCI='10.2, 10.5'; STRIDE='Repudiation' }
   ThreatProtection = @{ CIS='Microsoft Defender';    CSF='DE.CM-09, ID.RA-01'; NIST='SI-3, SI-4, RA-5'; ISO='A.8.7, A.8.8, A.8.16'; HIPAA='164.308(a)(1)(ii)(A)';               PCI='5.2, 6.3, 11.3'; STRIDE='Tampering' }
   Governance        = @{ CIS='Microsoft Defender';   CSF='GV.RR-02, RS.CO-02'; NIST='IR-6, PM-5'; ISO='A.5.24, A.6.8';          HIPAA='164.308(a)(6)';                    PCI='12.10';    STRIDE='Repudiation' }
}
$DomainLabel = @{ Identity='Identity & MFA'; Privileged='Privileged access'; Network='Network exposure'; Compute='VM hardening & encryption'
                    Logging='Logging & audit'; ThreatProtection='Threat protection (Defender)'; Governance='Governance & incident response' }

# Issue keys: findings with the same key + subscription + resource group are ONE problem (the merge step uses this)
$IssueDefs = [ordered]@{
   MgmtPorts = @{ Rx='management ports|network ports should be restricted|just-in-time|exposes .*(SSH|RDP)'; Title='Admin ports (SSH / RDP) reachable from the Internet'; Domain='Network' }
   DiskEnc     = @{ Rx='encryption at host|EncryptionAtHost'; Title='VM disks / host caches not fully encrypted';           Domain='Compute' }
   SecContact = @{ Rx='security contact'; Title='No security contact email configured';                Domain='Governance' }
}
function Get-IssueKey([string]$t) { foreach ($k in $IssueDefs.Keys) { if ($t -match $IssueDefs[$k].Rx) { return $k } }; $null }

# ============================================================== 4. Add-Finding: the only way a check records a result
$Findings = New-Object System.Collections.Generic.List[object]
function Add-Finding {
     param([string]$Result,         # Pass | Warn | Fail | N/A | Unknown
            [string]$Severity,      # High | Medium | Low | Info
            [string]$Domain, [string]$Subscription, [string]$Resource,
            [string]$Finding, [string]$Why, [string]$Fix,
            [string]$Source = 'Custom check', [string]$RGroup = '', [string]$Caution = '', [string]$Key)
     if (-not $Key) { $Key = Get-IssueKey $Finding }
     if ($Key -and $IssueDefs.Contains($Key)) { $Domain = $IssueDefs[$Key].Domain }
     $m = $Map[$Domain]
     $Findings.Add([pscustomobject]@{
          Result=$Result; Severity=$Severity; Domain=$DomainLabel[$Domain]; DomainKey=$Domain; Subscription=$Subscription
          RG=$RGroup; Resource=$Resource; Finding=$Finding; Detail=''; Why=$Why; Fix=$Fix; Caution=$Caution; Source=$Source; Key=$Key
          CIS=$m.CIS; CSF=$m.CSF; NIST=$m.NIST; ISO=$m.ISO; HIPAA=$m.HIPAA; PCI=$m.PCI; STRIDE=$m.STRIDE })
}

# ============================================================== 5. Azure
$subIds = @(); $AzAccount = ''; $GraphAccount = ''; $GraphAuth = 'not used'
if (-not $SkipAzure) {
     Ensure-Module Az.Accounts
     $ctx = Get-AzContext
     if ($ctx) { try { Get-AzAccessToken -ErrorAction Stop | Out-Null } catch { $ctx = $null } }    # saved context but expired token
     if (-not $ctx -or $ctx.Tenant.Id -ne $TenantId) {                                              # wrong tenant: sign in again
          $a = @{ TenantId = $TenantId }
          if (-not $Interactive) { $a.UseDeviceAuthentication = $true }
          Connect-AzAccount @a | Out-Null
          $ctx = Get-AzContext
     }
     $AzAccount = "$($ctx.Account.Id)"; Step "Signed in as $AzAccount"

     $subs = @(Get-AzSubscription -TenantId $TenantId | Where-Object { "$($_.State)" -eq 'Enabled' })
     if ($SubscriptionId) { $subs = @($subs | Where-Object { $_.Id -in $SubscriptionId }) }
     $subIds = @($subs | ForEach-Object { $_.Id })
     $subName = @{}; foreach ($s in $subs) { $subName[$s.Id] = $s.Name }
     function SN($id) { if ($subName[$id]) { "$($subName[$id]) ($($id.Substring(0,8)))" } else { $id } }
     Step "Subscriptions in scope: $($subIds.Count)"

     # ---- example A: one ARM call per subscription (security contact)
     foreach ($sid in $subIds) {
         $sn = SN $sid
         try {
             $sc = Invoke-ArmGet "/subscriptions/$sid/providers/Microsoft.Security/securityContacts?api-version=2020-01-01-preview"
             $emails = @($sc.value | ForEach-Object { $_.properties.emails } | Where-Object { $_ })
             if ($emails) { Add-Finding Pass Info Governance $sn $sn "Security contact set ($($emails -join ', '))" '' '' -Key SecContact }
             else { Add-Finding Fail Low Governance $sn $sn 'No security contact email configured' 'High-severity Defender alerts go nowhere.' "Defender for Cloud > Environment settings > $sn > Email notifications" -Key SecContact }
         } catch { Log-Source "Security contact ($sn)" 'Failed' $_.Exception.Message }
     }
     Log-Source 'Subscriptions' 'OK' "$($subIds.Count) subscription(s)"

     if ($subIds.Count) {
         # ---- example B: Defender for Cloud assessments through Resource Graph (the biggest single source)
         try {
             $q = @'
securityresources
| where type == 'microsoft.security/assessments'
| extend code = tostring(properties.status.code)
| where code in ('Healthy','Unhealthy')
| project subscriptionId, displayName = tostring(properties.displayName), code,
           resId = tostring(properties.resourceDetails.Id), sev = tostring(properties.metadata.severity)
'@
             $assess = @(Invoke-Arg $q $subIds)
             foreach ($a in $assess) {
                 $res = ($a.resId -split '/')[-1]; if (-not $res) { $res = SN $a.subscriptionId }
                 $rg = if ($a.resId -match '/resourceGroups/([^/]+)') { $Matches[1].ToLower() } else { '' }
                 if ($a.code -eq 'Healthy') { Add-Finding Pass Info Compute (SN $a.subscriptionId) $res $a.displayName '' '' 'Defender for Cloud' -RGroup $rg }
                 else { Add-Finding Fail $(if ($a.sev) { $a.sev } else { 'Medium' }) Compute (SN $a.subscriptionId) $res $a.displayName 'See Defender for Cloud recommendation.' 'See Defender for Cloud > Recommendations.' 'Defender for Cloud' -RGroup $rg }
             }
             Log-Source 'Defender recommendations' 'OK' "$($assess.Count) assessments"
         } catch { Log-Source 'Defender recommendations' 'Failed' $_.Exception.Message }

         # ---- example C: a custom Resource Graph check (NSG rules open to the Internet on admin ports)
         try {
             $q = @'
resources
| where type =~ 'microsoft.network/networksecuritygroups'
| mv-expand rule = properties.securityRules
| where tostring(rule.properties.direction) =~ 'Inbound' and tostring(rule.properties.access) =~ 'Allow'
| extend src = tostring(rule.properties.sourceAddressPrefix)
| where src in~ ('*','Internet','0.0.0.0/0','Any')
| project subscriptionId, nsg = name, resourceGroup, rule = tostring(rule.name), port = tostring(rule.properties.destinationPortRange)
'@
             foreach ($n in (Invoke-Arg $q $subIds)) {
                 if ($n.port -in '22','3389','*') {
                      Add-Finding Fail High Network (SN $n.subscriptionId) $n.nsg "Inbound rule '$($n.rule)' on $($n.nsg) exposes $($n.port) to the Internet" `
                          'Admin ports open to the whole Internet are brute-forced constantly.' "Restrict the source, or use Bastion / just-in-time access." `
                          -RGroup ("$($n.resourceGroup)".ToLower()) -Caution 'Can cut off remote access. Add the replacement rule first.'
                 }
             }
             Log-Source 'Network security groups' 'OK'
         } catch { Log-Source 'Network security groups' 'Failed' $_.Exception.Message }
     }
} else { Log-Source 'Azure' 'Skipped' '-SkipAzure' }

# ============================================================== 6. Entra ID (Graph)
$graphOk = $false
if (-not $SkipGraph) {
     $scopes = 'Policy.Read.All','Directory.Read.All','RoleManagement.Read.Directory','AuditLog.Read.All','User.Read.All'
    try { $script:GraphToken = Get-GraphTokenDeviceCode $scopes; $graphOk = $true; $GraphAuth = 'Device code (delegated, read-only)' }
    catch { Log-Source 'Graph sign-in (device code)' 'Failed' $_.Exception.Message }
}
if ($graphOk) {
    $G = 'https://graph.microsoft.com/v1.0'; $T = 'Entra ID tenant'
    function CouldNot($dom, $what, $msg, $need) { Add-Finding 'Unknown' Info $dom $T $what "Could not check: $what" "$msg - status unknown, NOT confirmed as a problem." "Needs: $need" -Key 'Unknown' }

    # ---- example D: Conditional Access + Security Defaults (policy-level identity checks)
    try {
        $secDefaults = [bool](Get-GraphAll "$G/policies/identitySecurityDefaultsEnforcementPolicy").isEnabled
        $ca = @(Get-GraphAll "$G/identity/conditionalAccess/policies" | Where-Object state -eq 'enabled')
        $mfaAll = @($ca | Where-Object { $_.conditions.users.includeUsers -contains 'All' -and $_.conditions.applications.includeApplications -contains 'All' -and $_.grantControls.builtInControls -contains 'mfa' })
        if ($secDefaults -or $mfaAll) { Add-Finding Pass Info Identity $T $T 'MFA required for all users, all apps' '' '' }
        else { Add-Finding Fail High Identity $T $T 'MFA is not required for all users' 'Anyone outside the scoped policies can sign in with a password only.' "Conditional Access template 'Require MFA for all users' (report-only first)." -Caution 'Exclude break-glass and service accounts; review report-only for 1-2 weeks.' }
        Log-Source 'Conditional Access' 'OK' "$($ca.Count) enabled policies"
    } catch { Log-Source 'Conditional Access' 'Failed' $_.Exception.Message; CouldNot 'Identity' 'Conditional Access' $_.Exception.Message 'Policy.Read.All' }

    # ---- example E: a check that needs a licence (sign-in logs) and degrades to "Could not check"
    try {
        $since = (Get-Date).ToUniversalTime().AddDays(-7).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $f = [uri]::EscapeDataString("createdDateTime ge $since and clientAppUsed eq 'Authenticated SMTP'")
        $hits = @(Get-GraphAll "$G/auditLogs/signIns?`$filter=$f&`$top=200&`$select=userPrincipalName,status,ipAddress" -MaxPages 3)
        if ($hits.Count) { Add-Finding Warn Medium Identity $T "$($hits.Count) sign-ins" "Legacy authentication (SMTP AUTH) used in the last 7 days" 'These sign-ins bypass MFA and stop working when legacy auth is blocked.' 'Identify the apps, move them to OAuth or a relay, then block legacy auth.' }
        else { Add-Finding Pass Info Identity $T $T 'No legacy-authentication sign-ins in the last 7 days' '' '' }
        Log-Source 'Sign-in logs (legacy auth)' 'OK' "$($hits.Count) sign-ins"
    } catch { Log-Source 'Sign-in logs (legacy auth)' 'Failed' $_.Exception.Message; CouldNot 'Identity' 'Legacy-auth sign-ins' $_.Exception.Message 'Entra ID P1 + AuditLog.Read.All' }

    # ---- example F: privileged roles (Global Administrator = 62e90394-69f5-4237-9190-012177145e10)
    try {
        $ga = @(Get-GraphAll "$G/roleManagement/directory/roleAssignments?`$filter=roleDefinitionId eq '62e90394-69f5-4237-9190-012177145e10'&`$expand=principal")
        $n = @($ga | ForEach-Object { $_.principalId } | Select-Object -Unique).Count
        if ($n -ge 2 -and $n -le 4) { Add-Finding Pass Info Privileged $T $T "$n Global Administrators" '' '' }
        else { Add-Finding Fail High Privileged $T $T "$n permanent Global Administrators (Microsoft: fewer than five, at least two)" 'Every standing Global Admin is a full-control account an attacker can target.' 'Move day-to-day work to narrower roles; make the rest PIM-eligible.' }
        Log-Source 'Global Administrators' 'OK' "$n active"
    } catch { Log-Source 'Global Administrators' 'Failed' $_.Exception.Message; CouldNot 'Privileged' 'Global Administrators' $_.Exception.Message 'RoleManagement.Read.Directory' }
} elseif (-not $SkipGraph) { Write-Warning 'Entra ID checks skipped - report will contain Azure findings only.' }

# ============================================================== 7. merge + calibrate
$rank = @{ High=0; Medium=1; Low=2; Info=3 }
$all = @($Findings | ForEach-Object { $_ })
$merged = New-Object System.Collections.Generic.List[object]
$keyed = @($all | Where-Object { $_.Key -and $IssueDefs.Contains($_.Key) })
foreach ($f in @($all | Where-Object { -not ($_.Key -and $IssueDefs.Contains($_.Key)) })) { $merged.Add($f) }
foreach ($g in ($keyed | Group-Object { "$($_.Key)|$($_.Subscription)|$($_.RG)" })) {     # NOTE: merging by resource group
    $items = @($g.Group)                                                                      # unions resources in that group;
    $bad   = @($items | Where-Object { $_.Result -in 'Fail','Warn' } | Sort-Object @{e= {$rank[$_.Severity]}})   # change the key to
    $good = @($items | Where-Object { $_.Result -eq 'Pass' })                                # "...|$($_.Resource)" for per-resource rows
    $o = $(if ($bad) { $bad[0] } else { $good[0] }).PSObject.Copy()
    $o.Resource = (@($items | ForEach-Object Resource | Where-Object { $_ } | Select-Object -Unique) -join ', ')
     $o.Source    = (@($items | ForEach-Object Source | Select-Object -Unique) -join ' + ')
     if ($bad) {
         $o.Result = $(if (@($bad | Where-Object Result -eq 'Fail').Count) { 'Fail' } else { 'Warn' }); $o.Severity = $bad[0].Severity
         $o.Finding = $IssueDefs[$items[0].Key].Title
         $o.Detail = (@($bad | ForEach-Object Finding | Select-Object -Unique) -join "`n")
         if ($good) { $o.Detail += "`nAlready in place: " + (@($good | ForEach-Object Finding | Select-Object -Unique) -join '; ') }
     }
     $merged.Add($o)
}
$Findings = $merged

# ============================================================== 8. score
$fails     = @($Findings | Where-Object { $_.Result -in 'Fail','Warn' } | Sort-Object @{e= {$rank[$_.Severity]}}, Domain, Finding)
$passes = @($Findings | Where-Object { $_.Result -eq 'Pass' })
$naRows = @($Findings | Where-Object { $_.Result -eq 'N/A' })
$unknown = @($Findings | Where-Object { $_.Result -eq 'Unknown' })
function Get-Pct($rows) {
     $rows = @(foreach ($x in $rows) { if ($null -ne $x) { $x } })                  # PS 5.1: avoid List[object] truthiness errors
     $scored = @($rows | Where-Object { $_.Result -in 'Pass','Warn','Fail' })
     if (-not $scored.Count) { return $null }
     $pts = 0.0; foreach ($r in $scored) { if ($r.Result -eq 'Pass') { $pts += 1 } elseif ($r.Result -eq 'Warn') { $pts += 0.5 } }
     [math]::Round(100 * $pts / $scored.Count, 1)
}
function Get-Health($p) { if ($null -eq $p) { 'No data' } elseif ($p -ge 80) { 'Green' } elseif ($p -ge 60) { 'Amber' } else { 'Red' } }
$DomainScore = @(foreach ($k in $Map.Keys) {
     $rows = @($Findings | Where-Object { $_.DomainKey -eq $k }); $p = Get-Pct $rows
     [pscustomobject]@{ Domain=$DomainLabel[$k]; Checks=$rows.Count; 'Pass %'=$p; Health=(Get-Health $p) }
}) | Sort-Object 'Pass %'
Write-Host ("`nOpen findings: {0} (passed {1}; N/A {2}; could not check {3})" -f $fails.Count, $passes.Count, $naRows.Count, $unknown.Count) -ForegroundColor Cyan
$DomainScore | Format-Table -AutoSize

# ============================================================== 9. write (HTML + tracker CSV + evidence JSON + SHA-256 manifest)
$base = Join-Path $OutputPath "TenantHardening-$stamp"
$i = 0
$tracker = @(foreach ($f in $fails) { $i++
     [pscustomobject]@{ 'Finding ID'=('F{0:000}' -f $i); Severity=$f.Severity; Result=$f.Result; Domain=$f.Domain; Subscription=$f.Subscription; Resource=$f.Resource
         Finding=$f.Finding; Detail=$f.Detail; Why=$f.Why; Fix=$f.Fix; Caution=$f.Caution; Source=$f.Source
         CIS=$f.CIS; CSF=$f.CSF; NIST=$f.NIST; ISO=$f.ISO; HIPAA=$f.HIPAA; PCI=$f.PCI; STRIDE=$f.STRIDE
         'Run ID'=$RunId; Owner=''; 'Target date'=''; Status='Open'; 'Change ticket'=''; 'Verified by'=''; 'Verified date (UTC)'='' } })
$tracker | Export-Csv "$base-remediation-tracker.csv" -NoTypeInformation -Encoding UTF8

$RunEndUtc = (Get-Date).ToUniversalTime()
$RunRecord = [ordered]@{
     'Run ID'=$RunId; 'Script'="Get-TenantHardeningReport v$ScriptVersion"
     'Script SHA-256'=$(try { (Get-FileHash -Algorithm SHA256 -Path $PSCommandPath).Hash } catch { 'unavailable' })
     'Tenant'=$TenantId; 'Azure account'=$AzAccount; 'Graph sign-in method'=$GraphAuth
     'Run on computer / user'="$env:COMPUTERNAME / $env:USERNAME"; 'PowerShell'="$($PSVersionTable.PSVersion)"
     'Started (UTC)'=(UtcIso $RunStartUtc); 'Finished (UTC)'=(UtcIso $RunEndUtc); 'Mode'='Read-only (no tenant changes)' }
[ordered]@{ runRecord=$RunRecord; dataSources=@($SourceLog | ForEach-Object { $_ }); findings=@($Findings | ForEach-Object { $_ }) } |
     ConvertTo-Json -Depth 6 | Out-File "$base-evidence.json" -Encoding utf8

function Enc($s) { [System.Net.WebUtility]::HtmlEncode([string]$s) -replace "`n", '<br>' }
function New-Table($Rows, [string[]]$Cols) {
     $Rows = @(foreach ($x in $Rows) { if ($null -ne $x) { $x } })        # unwrap List[object] first ("Argument types do not match" otherwise)
     if (-not $Rows.Count) { return '<p>None found.</p>' }
     $h = ($Cols | ForEach-Object { "<th>$(Enc $_)</th>" }) -join ''
     $b = ($Rows | ForEach-Object { $r = $_; '<tr>' + (($Cols | ForEach-Object { "<td>$(Enc $r.$_)</td>" }) -join '') + '</tr>' }) -join "`n"
     "<table><thead><tr>$h</tr></thead><tbody>$b</tbody></table>"
}
$html = @"
<!doctype html><html><head><meta charset="utf-8"><title>Tenant Hardening Report</title>
<style>body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#1b2430}table{border-collapse:collapse;width:100%;font-size:12px;margin:8px 0 18px}
th{background:#0f4c9a;color:#fff;text-align:left;padding:5px}td{padding:5px;border-bottom:1px solid #d7dde5;vertical-align:top}h2{color:#0f4c9a}</style></head><body>
<h1>Tenant Hardening Report</h1>
<p>Tenant $TenantId | Run $RunId | Generated $(UtcIso $RunEndUtc) | Script v$ScriptVersion | Read-only</p>
<h2>1. Open findings ($($fails.Count))</h2>$(New-Table $tracker @('Finding ID','Severity','Domain','Subscription','Resource','Finding','Detail','Why','Fix','Caution','Source'))
<h2>2. Domain scorecard</h2>$(New-Table $DomainScore @('Domain','Checks','Pass %','Health'))
<h2>3. Could not check ($($unknown.Count))</h2>$(New-Table $unknown @('Domain','Resource','Finding','Why','Fix'))
<h2>4. Run record</h2>$(New-Table @($RunRecord.GetEnumerator() | ForEach-Object { [pscustomobject]@{ Field=$_.Key; Value=$_.Value } }) @('Field','Value'))
<h2>5. Data sources</h2>$(New-Table $SourceLog @('Data source','Status','Detail'))
</body></html>
"@
$html | Out-File "$base.html" -Encoding utf8

$outs = @("$base.html", "$base-remediation-tracker.csv", "$base-evidence.json")
$manifest = @("# Tenant Hardening Report - SHA-256 manifest", "# Run ID: $RunId", "# Generated (UTC): $(UtcIso $RunEndUtc)", '')
foreach ($o in $outs) { $manifest += "$((Get-FileHash -Algorithm SHA256 -Path $o).Hash) $(Split-Path $o -Leaf)" }
$manifest | Out-File "$base-SHA256.txt" -Encoding ascii
Write-Host "`nReport:    $base.html`nTracker: $base-remediation-tracker.csv`nEvidence: $base-evidence.json`nManifest: $base-SHA256.txt" -ForegroundColor Green
