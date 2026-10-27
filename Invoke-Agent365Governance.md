# Agent 365 Governance

Review AI agent governance in a Microsoft 365 tenant, and deploy a starter set of Conditional Access policies for Entra agent identities - in report-only mode by default.

Companion script to **Part 6: moving AI agent governance from Defender into Agent 365** on [cloud-secure.ai](https://cloud-secure.ai/), part of the Microsoft Defender AI agent runtime protection series.

> **Status:** the agent Conditional Access properties used here are Microsoft Graph **beta** APIs. They may change before general availability. Test in a non-production tenant first.

## What it does

Run it, enter your tenant ID when prompted, and sign in.

### 1. Review (read-only)

| Check | Output |
| --- | --- |
| Every Entra agent identity, grouped by blueprint | `AgentIdentities.csv`, `Blueprints.csv` |
| Agent identities with no owner | `AgentIdentities.csv` (Finding column) |
| Agent identities holding delegated grants or app role assignments | `AgentIdentities.csv` |
| Legacy Copilot Studio agents still running as plain service principals | `LegacyServicePrincipals.csv` |
| Existing Conditional Access policies that target agents | `AgentConditionalAccess.csv` |
| Totals, and the manual steps below | `Summary.txt` |

### 2. Apply (skipped with `-ReviewOnly`)

| Policy | Targets | Condition | Control |
| --- | --- | --- | --- |
| CA-AGT-001 Block agents from unapproved blueprints | All agent identities, excluding approved blueprint principals | None | Block |
| CA-AGT-002 Block high-risk agent identities | All agent identities | Agent risk: high | Block |
| CA-AGT-003 Block high-risk agent users | All agent users | Agent risk: high | Block |
| CA-WID-001 Block service principals outside trusted locations *(optional)* | Service principals you list | Any location except your named locations | Block |
| CA-WID-002 Block risky service principals *(optional)* | Service principals you list | Service principal risk: high | Block |

- Policies are created in **report-only** mode unless you use `-EnforcePolicies`.
- A policy that already exists with the same name is **left unchanged**, so the script is safe to run again.
- If you do not name approved blueprints, CA-AGT-001 treats **every blueprint in use today as approved**. The policy then blocks only agents from blueprints that appear later.
- The CA-WID policies are created only when you pass `-WorkloadServicePrincipalIds`.

## What it does not do

Microsoft has not published an API for the Agent 365 settings in the Microsoft 365 admin center. Do these by hand - the blog post has a screenshot of each:

1. **Agents > Settings > Agent and plugin access** - choose which agent types users can install; prefer certified external publishers only.
2. **Agents > Settings > User access** - limit agents to a pilot group while controls go in.
3. **Agents > Settings > Policy template** - create templates for agents with and without their own identity.
4. **Agents > All agents > Requests** - make sure new agents are approved before users get them.
5. **Agents > All agents** - assign owners to ownerless agents, and block what nobody will own.
6. **Entra > Agents > Agent identities > Owners and sponsors** - add sponsors. The script cannot read sponsors, because Microsoft Graph supports that only with application permissions.
7. **Entra > Enterprise apps > Consent and permissions** - restrict user consent.
8. **Entra > ID Governance > Access packages** - move standing agent permissions into packages with approval and expiry.

The script also does not delete, disable or change any existing agent, blueprint or policy.

## Requirements

- PowerShell 7.2 or later
- The `Microsoft.Graph.Authentication` module:

  ```powershell
  Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
  ```

## Roles and permissions

The script signs in interactively with delegated permissions - there is no app registration or secret to manage.

| Run | Microsoft Graph scopes requested | Least privileged Entra role |
| --- | --- | --- |
| `-ReviewOnly` | `Application.Read.All`, `Directory.Read.All`, `Policy.Read.All` | Global Reader |
| Default (review and create policies) | The above, plus `Policy.ReadWrite.ConditionalAccess` | Conditional Access Administrator, plus Global Reader for the review |
| With `-WorkloadServicePrincipalIds` | As default | Conditional Access Administrator |

**First run in a tenant:** if Microsoft Graph PowerShell has not been consented for these scopes before, an administrator must grant consent once. Granting tenant-wide consent to Microsoft Graph permissions needs a Privileged Role Administrator or Global Administrator.

## Licensing

| Feature | Licence |
| --- | --- |
| Agent identity inventory | Included with Microsoft Entra |
| CA-AGT-001 (agent Conditional Access) | Microsoft 365 E7, or Microsoft Agent 365 plus Entra ID P1 or Microsoft 365 E3 |
| CA-AGT-002 and 003 (agent risk) | As above, plus Entra ID P2 or Microsoft 365 E5 |
| CA-WID-001 and 002 (service principals) | Microsoft Entra Workload ID Premium - **not included in Microsoft 365 E7** |

Without the right licence, policy creation fails with an error and the script carries on with the next step.

## Parameters

| Parameter | Required | Description |
| --- | --- | --- |
| `-TenantId` | Yes - prompted if omitted | Tenant ID (GUID) or primary domain, such as `contoso.onmicrosoft.com` |
| `-ReviewOnly` | No | Review only. Nothing is created and only read scopes are requested |
| `-EnforcePolicies` | No | Create the policies switched On instead of report-only. Not recommended for a first run |
| `-ApprovedBlueprintAppIds` | No | Blueprint application IDs to exclude from CA-AGT-001. Default: every blueprint in use today |
| `-WorkloadServicePrincipalIds` | No | Object IDs of single-tenant service principals for CA-WID-001 and 002 |
| `-TrustedNamedLocationIds` | No | Named location IDs that CA-WID-001 allows. Without it, only CA-WID-002 is created |
| `-PolicyPrefix` | No | Prefix for the agent policy names. Default: `CA-AGT` |
| `-OutputPath` | No | Folder for the results. Default: `.\Agent365Governance-<date>` |
| `-WhatIf` | No | Show which policies would be created, without creating them |

## Examples

Review only - nothing changes:

```powershell
.\Invoke-Agent365Governance.ps1 -ReviewOnly
```

Review, and create the three agent policies in report-only mode (you are prompted for the tenant ID):

```powershell
.\Invoke-Agent365Governance.ps1
```

See what would be created first:

```powershell
.\Invoke-Agent365Governance.ps1 -TenantId contoso.onmicrosoft.com -WhatIf
```

Approve only the Copilot Studio blueprint, so agents from any other blueprint are blocked:

```powershell
.\Invoke-Agent365Governance.ps1 -TenantId contoso.onmicrosoft.com -ApprovedBlueprintAppIds '25664c89-cea5-4ab6-b924-a54fd8a19ae0'
```

Also protect two service principals (needs Workload ID Premium):

```powershell
.\Invoke-Agent365Governance.ps1 -TenantId contoso.onmicrosoft.com `
    -WorkloadServicePrincipalIds '<service principal object ID>', '<service principal object ID>' `
    -TrustedNamedLocationIds '<named location ID>'
```

## After running

1. Open `Summary.txt` and compare the agent identity total with the registry total in **Microsoft 365 admin center > Agents > Overview**. The difference is the number of agents that Entra controls cannot see.
2. Work through the owners and permissions findings in `AgentIdentities.csv`.
3. Plan the migration of anything in `LegacyServicePrincipals.csv`.
4. Leave the policies in report-only for at least 48 hours, and review the results in **Entra > Agents > Sign-in logs**.
5. Switch the policies On when you are happy, and work through the manual steps above.

## Notes

- Agent Conditional Access properties (`includeAgentIdServicePrincipals`, `excludeAgentIdServicePrincipals`, `agentIdRiskLevels`, `AllAgentIdUsers`) are read and written through the Microsoft Graph beta endpoint.
- CA-AGT-001 excludes blueprint **principals** in your tenant. Check the exclusions in the portal after the first run.
- The script reads every service principal in the tenant to find legacy agents. In very large tenants this can take a few minutes.

## Author

Seán O'Farrell - [cloud-secure.ai](https://cloud-secure.ai/)

Provided as-is, without warranty. Review the code and test in a non-production tenant before use.
