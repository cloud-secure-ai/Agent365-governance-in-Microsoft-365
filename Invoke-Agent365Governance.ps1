<#
.SYNOPSIS
    Reviews AI agent governance in a Microsoft 365 tenant and deploys a starter set of
    Conditional Access policies for agents - in report-only mode by default.

.DESCRIPTION
    Companion script to "Part 6: moving AI agent governance from Defender into Agent 365"
    on cloud-secure.ai.

    The script runs in two stages:

    1. Review (read-only)
       - Inventories every Entra agent identity and groups it by blueprint
       - Flags agent identities with no owner, and any with granted permissions
       - Finds legacy Copilot Studio agents that still run as plain service principals
       - Lists existing Conditional Access policies that target agents
       - Writes everything to CSV files and a summary report

    2. Apply (skipped with -ReviewOnly)
       - CA-AGT-001  Block agents from unapproved blueprints
                     (excludes every blueprint found today, so only NEW blueprints are blocked)
       - CA-AGT-002  Block high-risk agent identities
       - CA-AGT-003  Block high-risk agent users
       - CA-WID-001/002 for ordinary service principals, only when -WorkloadServicePrincipalIds
         is supplied (needs Microsoft Entra Workload ID Premium, which is NOT in Microsoft 365 E7)

    Every policy is created in report-only mode unless -EnforcePolicies is used. Existing
    policies with the same name are left untouched, so the script is safe to run again.

    Agent 365 settings in the Microsoft 365 admin center (Agent and plugin access, User access,
    Policy templates, the Requests queue) have no documented API at the time of writing. The
    script lists them as manual steps in the summary.

.PARAMETER TenantId
    The tenant ID (GUID) or primary domain to connect to. You are prompted for it if omitted.

.PARAMETER ReviewOnly
    Run the review stage only. Nothing is created or changed, and only read scopes are requested.

.PARAMETER EnforcePolicies
    Create the policies switched On instead of report-only. Not recommended for a first run.

.PARAMETER ApprovedBlueprintAppIds
    Blueprint application IDs to exclude from CA-AGT-001. If omitted, every blueprint that
    currently has agent identities in the tenant is treated as approved.

.PARAMETER WorkloadServicePrincipalIds
    Object IDs of single-tenant service principals to protect with the CA-WID policies.
    Requires Microsoft Entra Workload ID Premium.

.PARAMETER TrustedNamedLocationIds
    Named location IDs that CA-WID-001 allows. Required for CA-WID-001; without it only
    CA-WID-002 (risk-based) is created.

.PARAMETER PolicyPrefix
    Prefix for agent policy names. Default: CA-AGT

.PARAMETER OutputPath
    Folder for the CSV files and summary. Default: .\Agent365Governance-<date>

.EXAMPLE
    .\Invoke-Agent365Governance.ps1
    Prompts for the tenant ID, reviews the tenant and creates CA-AGT-001 to 003 in report-only mode.

.EXAMPLE
    .\Invoke-Agent365Governance.ps1 -TenantId contoso.onmicrosoft.com -ReviewOnly
    Review only - nothing is changed.

.EXAMPLE
    .\Invoke-Agent365Governance.ps1 -TenantId contoso.onmicrosoft.com -WhatIf
    Shows which policies would be created without creating them.

.NOTES
    Author:   Seán O'Farrell
    Website:  https://cloud-secure.ai/
    Version:  1.0.0
    Requires: PowerShell 7.2 or later, Microsoft.Graph.Authentication module
    The agent Conditional Access properties are Microsoft Graph beta APIs and may change.
#>

#Requires -Version 7.2

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory, HelpMessage = 'Tenant ID (GUID) or primary domain, e.g. contoso.onmicrosoft.com')]
    [ValidateNotNullOrEmpty()]
    [string]$TenantId,

    [switch]$ReviewOnly,

    [switch]$EnforcePolicies,

    [string[]]$ApprovedBlueprintAppIds,

    [string[]]$WorkloadServicePrincipalIds,

    [string[]]$TrustedNamedLocationIds,

    [ValidatePattern('^[A-Za-z0-9\-_]{2,20}$')]
    [string]$PolicyPrefix = 'CA-AGT',

    [string]$OutputPath = (Join-Path -Path (Get-Location) -ChildPath ("Agent365Governance-{0:yyyyMMdd-HHmm}" -f (Get-Date)))
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Counters and helpers ------------------------------------------------------------------

$script:Summary = [ordered]@{
    AgentIdentities          = 0
    Blueprints               = 0
    AgentsWithoutOwners      = 0
    AgentsWithPermissions    = 0
    LegacyServicePrincipals  = 0
    ExistingAgentPolicies    = 0
    PoliciesCreated          = 0
    PoliciesSkippedExisting  = 0
    PoliciesFailed           = 0
    Warnings                 = 0
}

function Write-Step    { param([string]$Message) Write-Host "`n🔷 $Message" -ForegroundColor Cyan }
function Write-Ok      { param([string]$Message) Write-Host "   ✅ $Message" -ForegroundColor Green }
function Write-Info    { param([string]$Message) Write-Host "   ℹ️  $Message" -ForegroundColor Gray }
function Write-Skip    { param([string]$Message) Write-Host "   ⏭️  $Message" -ForegroundColor DarkYellow }
function Write-Warn    {
    param([string]$Message)
    $script:Summary.Warnings++
    Write-Host "   ⚠️  $Message" -ForegroundColor Yellow
}

function Invoke-GraphPaged {
    <#
        Calls a Microsoft Graph GET endpoint and follows @odata.nextLink until all pages are read.
    #>
    param(
        [Parameter(Mandatory)][string]$Uri,
        [hashtable]$Headers = @{}
    )
    $results = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    while ($next) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $next -Headers $Headers -OutputType PSObject -ErrorAction Stop
        if ($page.PSObject.Properties.Name -contains 'value') {
            foreach ($item in $page.value) { $results.Add($item) }
        }
        else {
            $results.Add($page)
        }
        $next = if ($page.PSObject.Properties.Name -contains '@odata.nextLink') { $page.'@odata.nextLink' } else { $null }
    }
    return $results
}

function Get-ItemCount {
    param($Value)
    return @($Value | Where-Object { $null -ne $_ }).Count
}

function Get-PropertyValue {
    param($Object, [string]$Name)
    if ($null -ne $Object -and $Object.PSObject.Properties.Name -contains $Name) { return $Object.$Name }
    return $null
}

#endregion

#region Connect ---------------------------------------------------------------------------------

Write-Host ''
Write-Host '🛡️  Agent 365 governance - cloud-secure.ai' -ForegroundColor White
Write-Host '   Part 6 of the Microsoft Defender AI agent runtime protection series' -ForegroundColor Gray

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    throw "The Microsoft.Graph.Authentication module is required. Install it with: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser"
}
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

$readScopes  = @('Application.Read.All', 'Directory.Read.All', 'Policy.Read.All')
$writeScopes = @('Policy.Read.All', 'Policy.ReadWrite.ConditionalAccess')
$scopes = if ($ReviewOnly) { $readScopes } else { $readScopes + $writeScopes | Select-Object -Unique }

Write-Step "Connecting to tenant $TenantId"
try {
    Connect-MgGraph -TenantId $TenantId -Scopes $scopes -NoWelcome -ErrorAction Stop
    $ctx = Get-MgContext
    Write-Ok "Signed in as $($ctx.Account)"
    Write-Info "Scopes: $($scopes -join ', ')"
}
catch {
    throw "Could not connect to Microsoft Graph: $($_.Exception.Message)"
}

if (-not (Test-Path -Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force -WhatIf:$false | Out-Null
}
Write-Info "Output folder: $OutputPath"

#endregion

#region Stage 1: review ---------------------------------------------------------------------------

Write-Step 'Inventorying Entra agent identities'

$agentSelect = 'id,displayName,agentIdentityBlueprintId,createdDateTime,accountEnabled'
$agents = $null
foreach ($version in 'v1.0', 'beta') {
    try {
        $agents = Invoke-GraphPaged -Uri "https://graph.microsoft.com/$version/servicePrincipals/microsoft.graph.agentIdentity?`$select=$agentSelect&`$top=100"
        Write-Info "Agent identities read from the Graph $version endpoint"
        break
    }
    catch {
        Write-Info "Graph $version agent identity endpoint unavailable: $($_.Exception.Message)"
    }
}
if ($null -eq $agents) {
    Write-Warn 'Could not read agent identities. Check the account can read applications in this tenant.'
    $agents = @()
}
$script:Summary.AgentIdentities = Get-ItemCount $agents
Write-Ok "$($script:Summary.AgentIdentities) agent identities found"

# Blueprints: resolve each distinct blueprint appId to its blueprint principal in this tenant
Write-Step 'Resolving agent identity blueprints'
$blueprintRows = [System.Collections.Generic.List[object]]::new()
$blueprintGroups = @($agents) | Where-Object { $_.agentIdentityBlueprintId } | Group-Object -Property agentIdentityBlueprintId
foreach ($group in $blueprintGroups) {
    $appId = $group.Name
    $principal = $null
    try {
        $principal = Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$appId'&`$select=id,appId,displayName,appOwnerOrganizationId" | Select-Object -First 1
    }
    catch {
        Write-Warn "Could not resolve blueprint $appId - $($_.Exception.Message)"
    }
    $publishedHere = if ($principal -and $principal.appOwnerOrganizationId -eq $ctx.TenantId) { 'This tenant' } elseif ($principal) { 'Another tenant' } else { 'Unknown' }
    $blueprintRows.Add([pscustomobject]@{
        BlueprintName        = if ($principal) { $principal.displayName } else { '(not found)' }
        BlueprintAppId       = $appId
        BlueprintPrincipalId = if ($principal) { $principal.id } else { $null }
        PublishedIn          = $publishedHere
        AgentIdentities      = $group.Count
    })
}
$script:Summary.Blueprints = $blueprintRows.Count
foreach ($bp in $blueprintRows | Sort-Object AgentIdentities -Descending) {
    Write-Info ("{0} - {1} agent(s), published in {2}" -f $bp.BlueprintName, $bp.AgentIdentities, $bp.PublishedIn.ToLower())
}

# Per-agent ownership and permissions
Write-Step 'Checking owners and granted permissions for each agent identity'
$agentRows = [System.Collections.Generic.List[object]]::new()
$blueprintNames = @{}
foreach ($bp in $blueprintRows) { $blueprintNames[$bp.BlueprintAppId] = $bp.BlueprintName }

$i = 0
foreach ($agent in @($agents)) {
    $i++
    Write-Progress -Activity 'Reviewing agent identities' -Status $agent.displayName -PercentComplete (($i / [math]::Max(1, @($agents).Count)) * 100)

    $ownerCount = $null; $delegatedGrants = $null; $appRoles = $null
    try {
        $ownerCount      = Get-ItemCount (Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($agent.id)/owners?`$select=id")
        $delegatedGrants = @(Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($agent.id)/oauth2PermissionGrants")
        $appRoles        = @(Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($agent.id)/appRoleAssignments")
    }
    catch {
        Write-Warn "Could not read owners or permissions for $($agent.displayName) - $($_.Exception.Message)"
    }

    $scopesGranted = ($delegatedGrants | ForEach-Object { $_.scope }) -join ' '
    $hasPermissions = (((Get-ItemCount $delegatedGrants) + (Get-ItemCount $appRoles)) -gt 0)
    if ($ownerCount -eq 0) { $script:Summary.AgentsWithoutOwners++ }
    if ($hasPermissions)   { $script:Summary.AgentsWithPermissions++ }

    $agentRows.Add([pscustomobject]@{
        DisplayName          = $agent.displayName
        ObjectId             = $agent.id
        Enabled              = $agent.accountEnabled
        Created              = $agent.createdDateTime
        Blueprint            = if ($agent.agentIdentityBlueprintId -and $blueprintNames.ContainsKey($agent.agentIdentityBlueprintId)) { $blueprintNames[$agent.agentIdentityBlueprintId] } else { $null }
        BlueprintAppId       = $agent.agentIdentityBlueprintId
        Owners               = $ownerCount
        DelegatedGrants      = Get-ItemCount $delegatedGrants
        DelegatedScopes      = $scopesGranted.Trim()
        AppRoleAssignments   = Get-ItemCount $appRoles
        Finding              = (@(
                                   if ($ownerCount -eq 0) { 'No owner' }
                                   if ($hasPermissions)   { 'Has granted permissions - review' }
                               ) -join '; ')
    })
}
Write-Progress -Activity 'Reviewing agent identities' -Completed
Write-Ok "$($script:Summary.AgentsWithoutOwners) agent identities have no owner"
Write-Ok "$($script:Summary.AgentsWithPermissions) agent identities hold granted permissions"
Write-Info 'Sponsors cannot be read with a delegated sign-in - check them in Entra > Agents > Agent identities > Owners and sponsors'

# Legacy Copilot Studio service principals
Write-Step 'Finding legacy Copilot Studio agents running as plain service principals'
$legacyRows = [System.Collections.Generic.List[object]]::new()
$agentTags = @('AgenticApp', 'AIAgentBuilder', 'AgenticInstance')
try {
    $allSps = Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$select=id,appId,displayName,tags,servicePrincipalType,createdDateTime&`$top=999"
    $agentIds = @{}
    foreach ($a in @($agents)) { $agentIds[$a.id] = $true }
    foreach ($sp in $allSps) {
        if ($agentIds.ContainsKey($sp.id)) { continue }
        $tags = @(Get-PropertyValue -Object $sp -Name 'tags')
        $pva  = $tags | Where-Object { $_ -like 'power-virtual-agents-*' }
        if (($tags | Where-Object { $_ -in $agentTags }) -or $pva) {
            $legacyRows.Add([pscustomobject]@{
                DisplayName      = $sp.displayName
                ObjectId         = $sp.id
                AppId            = $sp.appId
                Created          = Get-PropertyValue -Object $sp -Name 'createdDateTime'
                CopilotStudioTag = ($pva -join ' ')
            })
        }
    }
}
catch {
    Write-Warn "Could not list service principals - $($_.Exception.Message)"
}
$script:Summary.LegacyServicePrincipals = $legacyRows.Count
Write-Ok "$($legacyRows.Count) legacy agent service principals found - these are not covered by agent Conditional Access"

# Existing agent Conditional Access policies (beta - agent properties are not in v1.0 yet)
Write-Step 'Reading Conditional Access policies that target agents'
$existingPolicies = @()
$policyRows = [System.Collections.Generic.List[object]]::new()
try {
    $existingPolicies = Invoke-GraphPaged -Uri 'https://graph.microsoft.com/beta/identity/conditionalAccess/policies'
    foreach ($p in $existingPolicies) {
        $clientApps = Get-PropertyValue -Object $p.conditions -Name 'clientApplications'
        $users      = Get-PropertyValue -Object $p.conditions -Name 'users'
        $includesAgents = (Get-ItemCount (Get-PropertyValue -Object $clientApps -Name 'includeAgentIdServicePrincipals')) -gt 0
        $agentFilter    = Get-PropertyValue -Object (Get-PropertyValue -Object $clientApps -Name 'agentIdServicePrincipalFilter') -Name 'rule'
        $agentUsers     = @(Get-PropertyValue -Object $users -Name 'includeUsers') -contains 'AllAgentIdUsers'
        if ($includesAgents -or $agentFilter -or $agentUsers) {
            $policyRows.Add([pscustomobject]@{
                DisplayName = $p.displayName
                State       = $p.state
                Targets     = (@(
                                  if ($includesAgents -or $agentFilter) { 'Agent identities' }
                                  if ($agentUsers) { 'Agent users' }
                              ) -join ', ')
                AgentRisk   = Get-PropertyValue -Object $p.conditions -Name 'agentIdRiskLevels'
                Controls    = (@(Get-PropertyValue -Object $p.grantControls -Name 'builtInControls') -join ', ')
            })
        }
    }
}
catch {
    Write-Warn "Could not read Conditional Access policies - $($_.Exception.Message)"
}
$script:Summary.ExistingAgentPolicies = $policyRows.Count
foreach ($row in $policyRows) { Write-Info "$($row.DisplayName) - $($row.State)" }
if ($policyRows.Count -eq 0) { Write-Info 'No Conditional Access policies target agents yet' }

#endregion

#region Stage 2: apply ----------------------------------------------------------------------------

function New-AgentPolicy {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][hashtable]$Body
    )
    if ($existingPolicies | Where-Object { $_.displayName -eq $Name }) {
        Write-Skip "$Name already exists - left unchanged"
        $script:Summary.PoliciesSkippedExisting++
        return
    }
    if ($PSCmdlet.ShouldProcess($Name, 'Create Conditional Access policy')) {
        try {
            $json = $Body | ConvertTo-Json -Depth 10
            Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/beta/identity/conditionalAccess/policies' -Body $json -ContentType 'application/json' -ErrorAction Stop | Out-Null
            Write-Ok "Created $Name ($($Body.state))"
            $script:Summary.PoliciesCreated++
        }
        catch {
            $script:Summary.PoliciesFailed++
            Write-Warn "Could not create $Name - $($_.Exception.Message)"
        }
    }
}

if ($ReviewOnly) {
    Write-Step 'Review only - no policies created'
}
else {
    $state = if ($EnforcePolicies) { 'enabled' } else { 'enabledForReportingButNotEnforced' }
    Write-Step ("Creating agent Conditional Access policies ({0})" -f $(if ($EnforcePolicies) { 'ENFORCED' } else { 'report-only' }))

    # Work out which blueprint principals CA-AGT-001 should exclude
    $approved = if ($ApprovedBlueprintAppIds) {
        $blueprintRows | Where-Object { $_.BlueprintAppId -in $ApprovedBlueprintAppIds }
    }
    else {
        Write-Info 'No -ApprovedBlueprintAppIds given - treating every blueprint in use today as approved'
        $blueprintRows
    }
    $excludeIds = @($approved | Where-Object { $_.BlueprintPrincipalId } | ForEach-Object { $_.BlueprintPrincipalId })

    $grantBlock = @{ operator = 'OR'; builtInControls = @('block') }

    if ($excludeIds.Count -eq 0) {
        Write-Warn "No approved blueprints resolved - $PolicyPrefix-001 would block every agent identity, so it was not created"
    }
    else {
        New-AgentPolicy -Name "$PolicyPrefix-001 Block agents from unapproved blueprints" -Body @{
            displayName   = "$PolicyPrefix-001 Block agents from unapproved blueprints"
            state         = $state
            conditions    = @{
                clientAppTypes     = @('all')
                applications       = @{ includeApplications = @('All') }
                clientApplications = @{
                    includeAgentIdServicePrincipals = @('All')
                    excludeAgentIdServicePrincipals = $excludeIds
                }
            }
            grantControls = $grantBlock
        }
    }

    New-AgentPolicy -Name "$PolicyPrefix-002 Block high-risk agent identities" -Body @{
        displayName   = "$PolicyPrefix-002 Block high-risk agent identities"
        state         = $state
        conditions    = @{
            clientAppTypes     = @('all')
            applications       = @{ includeApplications = @('All') }
            clientApplications = @{ includeAgentIdServicePrincipals = @('All') }
            agentIdRiskLevels  = 'high'
        }
        grantControls = $grantBlock
    }

    New-AgentPolicy -Name "$PolicyPrefix-003 Block high-risk agent users" -Body @{
        displayName   = "$PolicyPrefix-003 Block high-risk agent users"
        state         = $state
        conditions    = @{
            clientAppTypes    = @('all')
            applications      = @{ includeApplications = @('All') }
            users             = @{ includeUsers = @('AllAgentIdUsers') }
            agentIdRiskLevels = 'high'
        }
        grantControls = $grantBlock
    }

    # Optional: ordinary service principals (Workload ID Premium)
    if ($WorkloadServicePrincipalIds) {
        Write-Step 'Creating workload identity policies (requires Microsoft Entra Workload ID Premium)'
        if ($TrustedNamedLocationIds) {
            New-AgentPolicy -Name 'CA-WID-001 Block service principals outside trusted locations' -Body @{
                displayName   = 'CA-WID-001 Block service principals outside trusted locations'
                state         = $state
                conditions    = @{
                    clientAppTypes     = @('all')
                    applications       = @{ includeApplications = @('All') }
                    clientApplications = @{ includeServicePrincipals = $WorkloadServicePrincipalIds }
                    locations          = @{ includeLocations = @('All'); excludeLocations = $TrustedNamedLocationIds }
                }
                grantControls = $grantBlock
            }
        }
        else {
            Write-Skip 'CA-WID-001 skipped - supply -TrustedNamedLocationIds to create it'
        }
        New-AgentPolicy -Name 'CA-WID-002 Block risky service principals' -Body @{
            displayName   = 'CA-WID-002 Block risky service principals'
            state         = $state
            conditions    = @{
                clientAppTypes             = @('all')
                applications               = @{ includeApplications = @('All') }
                clientApplications         = @{ includeServicePrincipals = $WorkloadServicePrincipalIds }
                servicePrincipalRiskLevels = @('high')
            }
            grantControls = $grantBlock
        }
    }
}

#endregion

#region Output ------------------------------------------------------------------------------------

Write-Step 'Writing results'
$files = [ordered]@{
    'AgentIdentities.csv'         = $agentRows
    'Blueprints.csv'              = $blueprintRows
    'LegacyServicePrincipals.csv' = $legacyRows
    'AgentConditionalAccess.csv'  = $policyRows
}
foreach ($file in $files.GetEnumerator()) {
    $path = Join-Path -Path $OutputPath -ChildPath $file.Key
    @($file.Value) | Export-Csv -Path $path -NoTypeInformation -Encoding utf8 -WhatIf:$false
    Write-Ok "$($file.Key) ($(@($file.Value).Count) rows)"
}

$manualSteps = @(
    'Microsoft 365 admin center > Agents > Settings > Agent and plugin access - choose which agent types users can install; prefer certified external publishers only',
    'Microsoft 365 admin center > Agents > Settings > User access - limit agents to a pilot group while controls go in',
    'Microsoft 365 admin center > Agents > Settings > Policy template - create a template for agents with and without their own identity',
    'Microsoft 365 admin center > Agents > All agents > Requests - make sure new agents are approved before users get them',
    'Microsoft 365 admin center > Agents > All agents - assign owners to ownerless agents; block what nobody will own',
    'Entra > Agents > Agent identities > Owners and sponsors - add sponsors (not readable by this script)',
    'Entra > Enterprise apps > Consent and permissions - restrict user consent (Privileged Role Administrator)',
    'Entra > ID Governance > Access packages - move standing agent permissions into packages with approval and expiry',
    "Review the report-only results for 48 hours, then switch $PolicyPrefix-001 to 003 On"
)

$report = @"
Agent 365 governance review - cloud-secure.ai
Tenant:  $($ctx.TenantId)
Account: $($ctx.Account)
Run:     $(Get-Date -Format 'yyyy-MM-dd HH:mm')

SUMMARY
$(($script:Summary.GetEnumerator() | ForEach-Object { '{0,-26} {1}' -f $_.Key, $_.Value }) -join [Environment]::NewLine)

NOTE
Entra only lists agents with an Entra agent identity. Compare the agent identity total above
with the registry total in Microsoft 365 admin center > Agents > Overview - the difference is
the number of agents that Entra controls cannot see.

MANUAL STEPS (no documented API yet)
$(($manualSteps | ForEach-Object { "- $_" }) -join [Environment]::NewLine)
"@
$reportPath = Join-Path -Path $OutputPath -ChildPath 'Summary.txt'
$report | Set-Content -Path $reportPath -Encoding utf8 -WhatIf:$false
Write-Ok 'Summary.txt'

Write-Host ''
Write-Host '📊 Summary' -ForegroundColor White
foreach ($item in $script:Summary.GetEnumerator()) {
    Write-Host ('   {0,-26} {1}' -f $item.Key, $item.Value)
}
Write-Host ''
Write-Host '📝 Manual steps in the Microsoft 365 and Entra admin centers:' -ForegroundColor White
$manualSteps | ForEach-Object { Write-Host "   - $_" -ForegroundColor Gray }
Write-Host ''
Write-Host "📁 Results: $OutputPath" -ForegroundColor White

Disconnect-MgGraph | Out-Null

#endregion
