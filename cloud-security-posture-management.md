# Cloud Security Posture Management (CSPM) Architecture

## Executive Summary

This document defines a comprehensive Cloud Security Posture Management strategy for enterprise Azure environments using Microsoft Defender for Cloud, Azure Policy, and Microsoft Sentinel. CSPM enables continuous assessment, monitoring, and remediation of security configurations across all Azure resources.

**Key Objectives:**
- Achieve 75+ Microsoft Secure Score (out of 100)
- Reduce remediation time from discovery to closure < 30 days
- Maintain 95%+ compliance with CIS, NIST, ISO 27001 standards
- Enable data-driven security investment decisions

**Target Audience:** Security architects, compliance officers, SOC managers, cloud engineers

---

## Table of Contents

1. [CSPM Overview](#cspm-overview)
2. [Microsoft Defender for Cloud](#microsoft-defender-for-cloud)
3. [Azure Policy Framework](#azure-policy-framework)
4. [Security Score Strategy](#security-score-strategy)
5. [Defender Plans & Workload Coverage](#defender-plans--workload-coverage)
6. [Alert Triage & SIEM Integration](#alert-triage--siem-integration)
7. [Vulnerability Management](#vulnerability-management)
8. [Compliance Reporting](#compliance-reporting)
9. [KPIs & Dashboards](#kpis--dashboards)
10. [Automation & Remediation](#automation--remediation)

---

## CSPM Overview

### What is Cloud Security Posture Management?

CSPM is a category of security tools that assess cloud infrastructure against compliance frameworks and best practices, then automate remediation. Unlike CWPP (Cloud Workload Protection Platform), CSPM focuses on **configuration** rather than **runtime threats**.

**CSPM vs. Other Tools:**

| Tool | Focus | Detection | Frequency | Action |
|------|-------|-----------|-----------|--------|
| CSPM | Configuration drift | Policy violation | Continuous | Remediate config |
| CWPP | Runtime threats | Process behavior | Real-time | Alert/block threat |
| SIEM | Correlation | Event logs | Real-time | Incident response |
| SOAR | Orchestration | Multiple sources | Automated | Execution workflow |

**CSPM Architecture:**
```
┌─────────────────────────────────────────────────────┐
│         Azure Subscriptions / Resources             │
├─────────────────────────────────────────────────────┤
│
├─→ Resource Configuration Scanner (Continuous)
│   ├─ Reads current state: VM settings, firewall rules, RBAC
│   ├─ Compares against: CIS benchmark, NIST 800-53, ISO 27001
│   ├─ Identifies: Drift, misconfiguration, non-compliance
│   └─ Remediation: Automated or manual
│
├─→ Compliance Monitoring (Continuous)
│   ├─ Tracks policy violations
│   ├─ Aggregates: Subscription, resource group, resource level
│   ├─ Reports: Regulatory compliance status
│   └─ Evidence: Audit trails for auditors
│
├─→ Vulnerability Assessment (Daily/Weekly)
│   ├─ Scans: OS vulnerabilities, weak configurations
│   ├─ Prioritizes: By CVSS score, blast radius
│   ├─ Tracks: Remediation progress
│   └─ Integrates: Patch management systems
│
└─→ Security Score Calculation (Real-time)
    ├─ Aggregates all controls
    ├─ Shows: Current posture vs. maximum possible
    ├─ Identifies: Highest-impact improvements
    └─ Benchmarks: Industry comparison
```

---

## Microsoft Defender for Cloud

### Platform Overview

Microsoft Defender for Cloud (MDC) is Azure's native CSPM + CWPP solution. It combines:
- **Configuration assessment** (CSPM) → Detect misconfigurations
- **Threat detection** (CWPP) → Detect active threats
- **Compliance monitoring** → Track regulatory compliance
- **Secure Score** → Visibility and prioritization

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│      MICROSOFT DEFENDER FOR CLOUD CONSOLE              │
│      (Azure Portal: Security Center)                   │
├─────────────────────────────────────────────────────────┤
│
├── Security Posture Management
│   ├─ Secure Score: Overall risk assessment (0-100)
│   ├─ Compliance: Track frameworks (CIS, NIST, ISO 27001)
│   ├─ Governance: Asset inventory, classification
│   └─ Risk management: Prioritized recommendations
│
├── Cloud Security Explorer
│   ├─ Query: Complex threat scenarios
│   ├─ Example: "VMs with public IPs AND no NSG rules"
│   ├─ Scope: All resources, historical data
│   └─ Output: Risk paths, blast radius
│
├── Defender Plans (Optional paid features)
│   ├─ Servers: Behavioral threat detection, EDR
│   ├─ Databases: SQL injection, anomalies
│   ├─ Storage: Malware scanning, anomalous access
│   ├─ Containers: K8s threat detection, registry scanning
│   └─ App Service: Web app vulnerability scanning
│
├── Integration Points
│   ├─ Azure Policy: Enforce recommendations
│   ├─ Log Analytics: Store findings, custom queries
│   ├─ Sentinel: Correlation and incident response
│   ├─ GitHub/DevOps: IaC scanning, supply chain
│   └─ Third-party: Sync findings to SIEM
│
└── Automation
    ├─ Playbooks: Logic Apps-based remediation
    ├─ Continuous export: Push findings to workspace
    └─ Webhooks: Real-time alert delivery
```

### Deployment Configuration

**Subscription Enablement:**

```powershell
# Enable Defender for Cloud on subscription
az security auto-provisioning-setting update \
  --auto-provision "On"

# Enable specific Defender plans
az security pricing create \
  --name VirtualMachines \
  --pricing-tier Standard

az security pricing create \
  --name SqlServers \
  --pricing-tier Standard

az security pricing create \
  --name StorageAccounts \
  --pricing-tier Standard

az security pricing create \
  --name AppServices \
  --pricing-tier Standard

az security pricing create \
  --name KeyVaults \
  --pricing-tier Standard
```

**Cost Calculation (Monthly Estimate):**

| Resource | Unit | Price | Qty | Monthly Cost |
|----------|------|-------|-----|--------------|
| VMs (Servers plan) | per VM | $15 | 50 | $750 |
| SQL Databases | per DB | $15 | 10 | $150 |
| Storage (malware scanning) | per GB | $0.50 | 100 | $50 |
| Containers (K8s, registry) | per cluster | $20 | 5 | $100 |
| App Service plans | per ASP | $10 | 20 | $200 |
| **Total Monthly** | | | | **$1,250** |

---

## Azure Policy Framework

### What is Azure Policy?

Azure Policy enforces organizational standards and assesses compliance. Policies define rules that resources must follow; non-compliant resources are flagged and optionally auto-remediated.

### Policy Architecture

```
┌─────────────────────────────────────────────────────────┐
│ AZURE POLICY DEFINITION (Rule)                          │
│                                                          │
│ Example: "All VMs must have antimalware"                │
│ ├─ Condition: ResourceType == "VirtualMachine"          │
│ ├─ Rule: extensions[name] contains "Antimalware"        │
│ └─ Effect: Audit (report) or Deny (block)               │
├─────────────────────────────────────────────────────────┤
│
│ POLICY ASSIGNMENT (Scope & Parameters)                 │
│ ├─ Scope: Subscription → Management Group → Tenant      │
│ ├─ Parameters: Acceptable SKUs, regions, tags          │
│ └─ Enforcement: Applied to new + existing resources    │
│
│ REMEDIATION TASK (Fix non-compliance)                  │
│ ├─ Trigger: Manual or scheduled                        │
│ ├─ Action: Run DeployIfNotExists, Modify               │
│ └─ Result: Compliant resources, audit trail            │
│
└─────────────────────────────────────────────────────────┘
```

### Policy Initiatives (Built-in)

**Initiative: CIS Microsoft Azure Foundations Benchmark v1.4.0**

| Domain | Policy | Effect | Scope |
|--------|--------|--------|-------|
| **Identity** | MFA on subscriptions with write | Audit | All subscriptions |
| | Password expiration disabled | Audit | All accounts |
| | Legacy authentication | Audit | Sign-in logs |
| **Network** | Public IP exposure | Deny | VMs, SQL |
| | Storage public access | Audit | Storage accounts |
| | SQL Server firewall rules | Audit | SQL servers |
| **Data** | Encryption enabled | Audit | Databases, disks |
| | TDE enabled | Deny | SQL databases |
| | Firewall enabled | Audit | All services |
| **Monitoring** | Diagnostic logs enabled | Audit | Key Vault, etc |
| | Activity log retention | Audit | Subscriptions |
| | Log Analytics agent | DeployIfNotExists | VMs |

**Initiative: NIST 800-53 SC-7 (Boundary Protection)**

| Policy | Requirement | Azure Implementation |
|--------|-------------|---------------------|
| Deny public storage | No public blob access | Set storage account access to Private |
| Restrict SQL access | Only app tier access | NSG rules + SQL firewall |
| Enable firewall | All services protected | Azure Firewall + WAF |
| Segment network | Subnets isolated | NSGs with explicit allow rules |
| DDoS enabled | Layer 3-4 protected | Azure DDoS Standard assignment |

**Initiative: ISO 27001 A.14 (System & Comms Security)**

| Policy | ISO Control | Implementation |
|--------|-------------|-----------------|
| Encryption in transit | A.14.1.1 | TLS 1.2+ on all endpoints |
| Encryption at rest | A.14.1.2 | CMK + AES-256 on all data |
| Key management | A.14.1.3 | HSM-backed Key Vault |
| Access control | A.14.1.4 | RBAC + PIM + MFA |

### Custom Policy Example

**Requirement:** All storage accounts must have blob versioning enabled

```json
{
  "name": "Require-Blob-Versioning-on-Storage-Accounts",
  "displayName": "Ensure blob versioning is enabled on storage accounts",
  "policyType": "Custom",
  "description": "Blob versioning prevents accidental or malicious deletion",
  "metadata": {
    "category": "Storage",
    "version": "1.0.0"
  },
  "parameters": {},
  "policyRule": {
    "if": {
      "allOf": [
        {
          "field": "type",
          "equals": "Microsoft.Storage/storageAccounts"
        }
      ]
    },
    "then": {
      "effect": "auditIfNotExists",
      "details": {
        "type": "Microsoft.Storage/storageAccounts/blobServices/containerProperties",
        "existenceCondition": {
          "field": "Microsoft.Storage/storageAccounts/blobServices/isVersioningEnabled",
          "equals": "true"
        }
      }
    }
  }
}
```

**Deployment:**
```powershell
# Create custom policy definition
New-AzPolicyDefinition `
  -Name "Require-Blob-Versioning" `
  -DisplayName "Require blob versioning" `
  -PolicyRule $policyRule

# Assign to subscription
New-AzPolicyAssignment `
  -Name "storage-versioning-enforcement" `
  -PolicyDefinition $policyDef `
  -Scope "/subscriptions/{subscriptionId}"

# View compliance status
Get-AzPolicyStateSummary -ResourceGroupName "prod-storage-rg"
```

---

## Security Score Strategy

### Understanding Secure Score

**Metric:** Cumulative score (0-100) reflecting overall security posture

```
Secure Score = (Completed Controls / Total Possible Controls) × 100

Example:
├─ Total Possible Controls: 50
├─ Completed Controls: 38
├─ Secure Score: (38/50) × 100 = 76/100
```

### Score Breakdown by Domain

| Domain | Controls | Weight | Importance |
|--------|----------|--------|-----------|
| Access & Identity | 12 | 25% | Critical (most breaches start here) |
| Data & Storage | 10 | 20% | Critical (regulatory requirement) |
| Networking | 8 | 15% | High (lateral movement prevention) |
| Applications | 6 | 12% | High (attack surface) |
| Monitoring & Response | 8 | 15% | Medium (detection speed) |
| Best Practices | 6 | 13% | Medium (operational excellence) |

### Target Scores & Timeline

**Baseline Assessment (Month 1):**
```
Typical greenfield environment: 45-50/100

Common gaps:
├─ No MFA: -10 points
├─ Public storage blobs: -8 points
├─ No encryption: -12 points
├─ Missing NSGs: -10 points
├─ No monitoring: -8 points
└─ (Varies by environment)
```

**Improvement Roadmap:**

| Milestone | Target | Timeline | Effort | Key Actions |
|-----------|--------|----------|--------|-------------|
| M1 | 50 | Month 1 | 10 hours | Enable MFA, basic NSGs |
| M2 | 60 | Month 2 | 20 hours | Encryption, RBAC, monitoring |
| M3 | 70 | Month 3 | 25 hours | Sentinel, custom policies |
| M4 | 75 | Month 4 | 20 hours | Compliance, advanced rules |
| M5 | 80 | Month 5 | 15 hours | Optimization, hardening |

### Score Improvement Actions (Prioritized)

**High-Impact (10+ points each):**

| Action | Points | Effort | ROI |
|--------|--------|--------|-----|
| Enable MFA on all accounts | +15 | 4 hours | Very High |
| Remove public IP exposure | +12 | 3 hours | Very High |
| Enable encryption for all data | +10 | 8 hours | Very High |
| Implement firewall rules | +10 | 6 hours | Very High |

**Medium-Impact (5-10 points each):**

| Action | Points | Effort | ROI |
|--------|--------|--------|-----|
| Enable audit logging | +8 | 2 hours | High |
| Configure NSGs | +7 | 4 hours | High |
| Set up PIM | +6 | 3 hours | High |
| Enable Key Vault soft delete | +5 | 1 hour | Very High |

**Low-Impact (<5 points each):**

| Action | Points | Effort | ROI |
|--------|--------|--------|-----|
| Enable diagnostic logging | +3 | 1 hour | Medium |
| Tag all resources | +2 | 2 hours | Low |
| Review access reviews | +3 | 1 hour | High |

### Dashboard: Real-time Score Tracking

```
┌─────────────────────────────────────────────────────────┐
│ SECURE SCORE DASHBOARD                                  │
├─────────────────────────────────────────────────────────┤
│
│ Overall Score: 76/100 (↑ 5 points this week)           │
│
│ ┌─────────────────────────────────────────────────────┐ │
│ │ Access & Identity: 20/25 (80%)   ████████░░         │ │
│ │ Data & Storage:    15/20 (75%)   ███████░░░         │ │
│ │ Networking:        12/15 (80%)   ████████░░         │ │
│ │ Applications:      10/12 (83%)    ████████░░         │ │
│ │ Monitoring:        11/15 (73%)    ███████░░░         │ │
│ │ Best Practices:    8/13  (62%)    ██████░░░░░        │ │
│ │                                                       │ │
│ │ Top Pending Controls (by impact):                    │ │
│ │ 1. Enable Conditional Access: +8 points (3h effort) │ │
│ │ 2. Configure SQL firewall: +6 points (2h effort)    │ │
│ │ 3. Enable Key Vault purge protection: +4 pts (1h)   │ │
│ │ 4. Require TLS 1.2 minimum: +3 points (2h effort)   │ │
│ │                                                       │ │
│ └─────────────────────────────────────────────────────┘ │
│
│ Comparison:
│ • Your score: 76/100
│ • Industry avg (similar size): 65/100  ↑ Better
│ • Microsoft best practice: 85/100     ↓ Gap to close
│
│ Improvement Rate: +2.5 points/week (on track for 85+)
│
└─────────────────────────────────────────────────────────┘
```

---

## Defender Plans & Workload Coverage

### Plan-by-Plan Deployment

#### 1. Servers Plan (for VMs & Arc machines)

**Coverage:**
- Azure VMs (Windows, Linux)
- On-premises servers (via Azure Arc)
- Multi-cloud VMs (AWS, GCP via Arc)

**Capabilities:**

| Capability | Details | Frequency |
|-----------|---------|-----------|
| Vulnerability scanning | OS patches, weak configs | Continuous (agent-based) or weekly (agentless) |
| Threat detection | EDR signals, behavior analysis | Real-time |
| Recommendations | Security baselines, CIS benchmark | Daily |
| Compliance assessment | CIS, NIST, PCI-DSS | Daily |

**Deployment:**

```powershell
# Enable Servers plan
az security pricing create \
  --name VirtualMachines \
  --pricing-tier Standard

# Auto-deploy Log Analytics agent (if enabled)
az security auto-provisioning-setting update \
  --auto-provision "On"
  --name "LogAnalyticsAgentForVMs"

# Verify agent deployment
az vm extension list \
  --resource-group "prod-servers-rg" \
  --vm-name "prod-vm-001"

# Output: MicrosoftMonitoringAgent installed
```

**Vulnerability Severity Distribution (Example):**
```
Total VMs scanned: 50
Vulnerability findings:

Critical (CVSS 9.0+):      3 findings
├─ Remote Code Execution (RCE):    2 VMs affected
└─ Privilege Escalation:            1 VM affected

High (CVSS 7.0-8.9):      12 findings
├─ Authentication bypass:           5 VMs
└─ Information disclosure:          7 VMs

Medium (CVSS 4.0-6.9):    28 findings
├─ Denial of Service:              15 VMs
└─ Configuration issues:           13 VMs

Remediation SLA:
├─ Critical: Patch within 7 days
├─ High:     Patch within 30 days
└─ Medium:   Patch within 60 days
```

#### 2. SQL Server Plan

**Coverage:**
- Azure SQL Database
- SQL Server on Azure VMs
- SQL Server on-premises (Arc-enabled)
- PostgreSQL, MySQL, MariaDB

**Threat Detection Examples:**

| Threat | Detection Method | Response |
|--------|------------------|----------|
| SQL Injection | Query pattern analysis | Alert + block (if enabled) |
| Unusual access pattern | Behavioral baseline | Alert for review |
| Brute-force attack | Failed login spike | Alert + temp IP block |
| Anomalous database activity | Time-of-day/user analysis | Alert + audit trail |

**Deployment:**

```powershell
# Enable SQL Server protection
az security pricing create \
  --name SqlServers \
  --pricing-tier Standard

# Configure threat detection on SQL Database
az sql server threat-policy update \
  --name prod-sql-server \
  --resource-group prod-db-rg \
  --state Enabled \
  --storage-key {storage-account-key} \
  --storage-account prod-audit-storage \
  --retention-days 30

# Verify policy
az sql server threat-policy show \
  --name prod-sql-server \
  --resource-group prod-db-rg
```

**Vulnerability Example:**
```
Finding: SQL Server is missing critical security patches

Details:
├─ Current Version: SQL Server 2019 build 15.0.2000.5
├─ Latest Available: SQL Server 2019 build 15.0.4700.1
├─ Missing Patches: 3 critical, 12 important, 8 moderate
├─ CVSS Scores: Up to 9.8 (remote code execution)
└─ Affected: All databases on this instance

Remediation:
1. Test patches in dev/test environment
2. Schedule maintenance window
3. Apply latest cumulative update
4. Verify: SELECT @@VERSION (check build number)
5. Run DBCC CHECKDB (data integrity check)
6. Monitor: Performance impact, user login issues
```

#### 3. Storage Plan

**Coverage:**
- Azure Blob Storage
- Azure Files
- Azure Data Lake Storage

**Threat Detection:**

| Threat | Detection | Latency |
|--------|-----------|---------|
| Malware uploads | Antimalware engine | Real-time |
| Suspicious access patterns | Behavioral analysis | 5 min |
| Ransomware indicators | File encryption patterns | Real-time |
| Data exfiltration | Volume/frequency anomaly | 5 min |

**Deployment:**

```powershell
# Enable Storage protection (includes malware scanning)
az security pricing create \
  --name StorageAccounts \
  --pricing-tier Standard

# Create managed identity for scanning
az identity create \
  --name storage-scanner-identity \
  --resource-group prod-security-rg

# Grant Blob Data Reader role
az role assignment create \
  --assignee {managed-identity-id} \
  --role "Storage Blob Data Reader" \
  --scope "/subscriptions/{subscriptionId}/resourceGroups/prod-storage-rg"

# Verify malware scanning active
az security assessment list \
  --subscription-id {subscriptionId} \
  --filter "displayName eq 'Enable malware scanning on blobs'"
```

**Malware Scanning Configuration:**

```json
{
  "resourceType": "Microsoft.Storage/storageAccounts",
  "properties": {
    "malwareScanningEnabled": true,
    "scanOnUpload": true,
    "scanOnDownload": false,
    "quarantineLocation": "/malware-quarantine/",
    "notificationEmail": "security-team@company.com",
    "retentionDays": 90
  }
}
```

#### 4. Containers Plan (K8s & Registry)

**Coverage:**
- Azure Kubernetes Service (AKS)
- Azure Container Registry (ACR)
- Container images (scanning)

**Capabilities:**

| Capability | Details |
|-----------|---------|
| Runtime threat detection | Suspicious K8s API calls, shell access |
| Image vulnerability scanning | OS packages, app dependencies |
| Pod compliance | CIS K8s benchmarks, pod security standards |
| Registry scanning | Continuous scan of uploaded images |

**Deployment:**

```powershell
# Enable Containers plan
az security pricing create \
  --name Containers \
  --pricing-tier Standard

# Enable runtime threat detection on AKS cluster
az aks update \
  --name prod-aks-cluster \
  --resource-group prod-aks-rg \
  --enable-defender

# Verify deployment
az aks show \
  --name prod-aks-cluster \
  --resource-group prod-aks-rg \
  --query securityProfile.defender
```

**Image Scan Results (Example):**
```
Image: myapp:1.0.0
Scan Status: Complete (2 min 15 sec)
Vulnerabilities Found: 12

Critical (CVSS 9.0+):   0
High (CVSS 7.0+):      3
  ├─ nginx 1.14.0: CVE-2019-9511 (Buffer Overflow)
  ├─ openssl 1.0.2: CVE-2019-1551 (Timing side-channel)
  └─ libc: (glibc update available)

Medium (CVSS 4.0+):    6
Low (< CVSS 4.0):      3

Recommendations:
1. Update nginx to 1.21+ (latest stable)
2. Update openssl to 1.1.1 or 3.0
3. Apply security patches to base image (Alpine 3.14 → 3.16)
4. Scan dependencies.txt for Python package vulnerabilities

Action: Remediate and rescan (should reach 0 critical/high)
```

#### 5. App Service Plan

**Coverage:**
- Azure App Service (Web apps)
- Function Apps
- Logic Apps (basic checks)

**Capabilities:**

| Capability | Details |
|-----------|---------|
| Web vulnerability scanning | OWASP Top 10, custom payloads |
| Dependency scanning | NuGet, npm, pip packages |
| Configuration assessment | TLS version, auth enabled, HTTPS |
| Compliance checks | API auth, encryption, logging |

**Deployment:**

```powershell
# Enable App Service protection
az security pricing create \
  --name AppServices \
  --pricing-tier Standard

# View App Service security recommendations
az security assessment list \
  --filter "displayName contains 'App Service'"

# Example: Enforce HTTPS only
az appservice web config set \
  --name prod-api \
  --resource-group prod-apps-rg \
  --https-only true

# Enable authentication (Azure Entra ID)
az appservice auth update \
  --name prod-api \
  --resource-group prod-apps-rg \
  --enabled true \
  --action LoginWithAzureIdentity
```

---

## Alert Triage & SIEM Integration

### Alert Severity Framework

**Severity Levels:**

| Severity | Response Time | Action | Example |
|----------|---------------|--------|---------|
| Critical | < 15 min | Immediate investigation | RCE vulnerability, data breach signal |
| High | < 2 hours | Urgent review | Privilege escalation, unusual access |
| Medium | < 24 hours | Standard review | Configuration drift, weak password |
| Low | < 1 week | Backlog | Informational, best practice |

### Defender Alerts → Sentinel Pipeline

**Architecture:**
```
┌──────────────────────────────┐
│ Microsoft Defender for Cloud │
│ (Threat detected)            │
└──────────────┬───────────────┘
               │
               ├─→ Alert stored in Defender console
               │
               ├─→ Continuous Export (if enabled)
               │
┌──────────────▼───────────────┐
│ Log Analytics Workspace      │
│ (SecurityAlert table)        │
└──────────────┬───────────────┘
               │
               ├─→ Sentinel Analytics rules (KQL queries)
               │   └─→ Match alert against threat scenarios
               │
               ├─→ Grouping/Deduplication
               │   └─→ 5+ same alerts on same resource = 1 incident
               │
┌──────────────▼───────────────┐
│ Sentinel Incidents           │
│ (Grouped alerts, severity)   │
└──────────────┬───────────────┘
               │
               ├─→ Enrichment (context: user, device, asset)
               ├─→ Prioritization (risk scoring)
               └─→ Assignment (to analyst)
```

**Continuous Export Configuration:**

```powershell
# Enable continuous export of Defender alerts to Sentinel
az security auto-export create \
  --name "ExportDefenderAlertsToSentinel" \
  --description "Push all Defender alerts to Log Analytics" \
  --resource-types "SecurityAlert" \
  --scope "/subscriptions/{subscriptionId}" \
  --destination-workspace-id "/subscriptions/{subscriptionId}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{workspace}"

# Verify export is running
az security auto-export show --name "ExportDefenderAlertsToSentinel"
```

### Alert Triage Workflow

**Daily Triage (08:00 - 09:00 AM):**

```
Step 1: Open Sentinel Incidents
├─ Filter: Severity = Critical OR High
├─ Sort: Created date (newest first)
└─ View: Last 24 hours only

Step 2: For each incident:
├─ Click incident → Review details
├─ Check: Alert description, affected resource
├─ Verify: Is this normal behavior? (context matters)
│
├─ Decision Tree:
│
│  Is this a TRUE POSITIVE?
│  │
│  ├─ YES (Known attack/unusual activity):
│  │   ├─ Severity assignment
│  │   ├─ Create/link to ticket
│  │   ├─ Assign to incident responder
│  │   ├─ Document findings in incident
│  │   └─ Status: "In Progress" (responder takes over)
│  │
│  ├─ NO (Expected activity/known good):
│  │   ├─ Add comment: "Expected X, scheduled Y, owner Z"
│  │   ├─ Update recommendation (if applicable)
│  │   ├─ Create suppression rule (to prevent future alert)
│  │   └─ Status: "Closed as benign" + comment
│  │
│  └─ UNKNOWN (Need more context):
│      ├─ Add comment: "Additional investigation needed"
│      ├─ Assign to L2 analyst
│      ├─ Set status: "In Progress"
│      └─ Priority: Based on severity

Step 3: Analytics Rule Tuning
├─ Rule firing too often? (false positives > 20%)
│   └─ Adjust threshold, add exceptions
├─ Rule missing real threats? (true positives < 5%)
│   └─ Broaden scope, lower threshold
└─ Document changes in rule version history

Step 4: Weekly Summary
├─ Total incidents: X
├─ True positives: Y (% of total)
├─ False positive rate: Z%
├─ Mean response time: T minutes
├─ Trend analysis: Up/down/stable
└─ Tuning opportunities
```

**Sample Alert Rule (KQL):**

```kusto
// Alert: Privilege Escalation via Role Assignment
// Severity: High
// Description: User assigned to Global Administrator role outside business hours

SecurityAlert
| where AlertName == "Suspicious role assignment"
| where TimeGenerated > ago(24h)
| extend AssignedRole = tostring(parse_json(Entities)[0].DisplayName)
| extend AssignedUser = tostring(parse_json(Entities)[1].DisplayName)
| extend AssignedTime = TimeGenerated
| where AssignedRole == "Global Administrator"
| where hour(AssignedTime) < 8 or hour(AssignedTime) > 18
| summarize count() by AssignedUser, AssignedRole
| where count_ >= 1
| project AlertTime=AssignedTime, User=AssignedUser, Role=AssignedRole, Severity="High"

// Alert action: Send email to SOC manager, create incident
```

### Integration with External SIEM

**Use Case:** If customer uses Splunk/ELK instead of Sentinel

**Method 1: Log Analytics REST API**

```bash
# Query Log Analytics for alerts from past hour
curl -X POST \
  https://api.loganalytics.io/v1/workspaces/{workspace-id}/query \
  -H "Authorization: Bearer {access-token}" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "SecurityAlert | where TimeGenerated > ago(1h) | where Severity in (\"High\", \"Critical\")"
  }' \
  | jq '.tables[0].rows' \
  | /opt/splunk/bin/splunk add oneshot -
```

**Method 2: Continuous Export to Event Hub**

```powershell
# Export Defender alerts to Event Hub (for Splunk ingestion)
az security auto-export create \
  --name "ExportDefenderToEventHub" \
  --resource-types "SecurityAlert" \
  --destination-event-hub "/subscriptions/{subscriptionId}/resourceGroups/{rg}/providers/Microsoft.EventHub/namespaces/{ns}/eventhubs/{hub}"

# Splunk HEC input listens to Event Hub via Azure Add-on
```

---

## Vulnerability Management

### End-to-End Vulnerability Workflow

```
┌────────────────────────────────────────────────────────┐
│ VULNERABILITY DISCOVERY                                │
│ (Defender for Cloud scanning)                          │
├────────────────────────────────────────────────────────┤
│
│ Daily Scan Results:
│ • OS-level: Windows patches, kernel vulnerabilities
│ • App-level: Java, Python, .NET library vulnerabilities
│ • Config: Weak TLS cipher suites, exposed credentials
│ • Web apps: SQL injection, XSS, path traversal
│
│ Data stored in Defender console + exported to Sentinel
│
└────────────────────┬─────────────────────────────────┘
                     │
                     ▼
┌────────────────────────────────────────────────────────┐
│ PRIORITIZATION (Risk Assessment)                       │
├────────────────────────────────────────────────────────┤
│
│ Scoring Factors:
│ ┌────────────────────────────────────────────────────┐
│ │ CVSS Score (0-10)                                  │
│ │ ├─ 9.0-10.0: Remote code execution → CRITICAL    │
│ │ ├─ 7.0-8.9: Privilege escalation → HIGH          │
│ │ ├─ 4.0-6.9: Information disclosure → MEDIUM      │
│ │ └─ <4.0: Low impact → LOW                        │
│ │                                                    │
│ │ Exploitability (Is there a public exploit?)       │
│ │ ├─ Proof-of-concept available → +50% severity    │
│ │ └─ No known exploit → baseline CVSS score        │
│ │                                                    │
│ │ Asset Criticality (How important is this asset?)  │
│ │ ├─ Production database → +25% severity           │
│ │ ├─ Development VM → -25% severity                │
│ │ └─ Non-critical service → baseline               │
│ │                                                    │
│ │ Exposure (Can the asset be attacked from network?)│
│ │ ├─ Public IP → +25% severity                     │
│ │ ├─ Private IP, no lateral move → -25%           │
│ │ └─ Air-gapped → -50%                            │
│ │                                                    │
│ │ Network Segmentation (Is asset isolated?)        │
│ │ ├─ NSG restricts inbound → -15% severity        │
│ │ ├─ Firewall protects → -20% severity            │
│ │ └─ Open to internet → baseline                   │
│ └────────────────────────────────────────────────────┘
│
│ Result: Risk Score (1-100) derived from factors above
│
└────────────────────┬─────────────────────────────────┘
                     │
                     ▼
┌────────────────────────────────────────────────────────┐
│ REMEDIATION PLANNING                                   │
├────────────────────────────────────────────────────────┤
│
│ For each vulnerability, determine:
│
│ ┌────────────────────────────────────────────────────┐
│ │ Remediation Method                                 │
│ │ ├─ Patch: Apply security update (recommended)     │
│ │ ├─ Workaround: Temporary mitigation               │
│ │ ├─ Mitigate: Network control (firewall rule)      │
│ │ ├─ Accept: Residual risk (documented)             │
│ │ └─ Defer: Postpone (with timeline)               │
│ │                                                    │
│ │ SLA (Service Level Agreement)                      │
│ │ ├─ CRITICAL (CVSS 9.0+): Patch within 7 days    │
│ │ ├─ HIGH (CVSS 7.0-8.9): Patch within 30 days    │
│ │ ├─ MEDIUM (CVSS 4.0-6.9): Patch within 60 days  │
│ │ └─ LOW (CVSS <4.0): Patch within 90 days        │
│ │                                                    │
│ │ Change Management                                  │
│ │ ├─ Test environment: Patch first, validate       │
│ │ ├─ Staging: Apply to pre-prod, monitor 1 week   │
│ │ ├─ Production: Schedule maintenance window       │
│ │ └─ Verification: Confirm patch applied + effective
│ └────────────────────────────────────────────────────┘
│
└────────────────────┬─────────────────────────────────┘
                     │
                     ▼
┌────────────────────────────────────────────────────────┐
│ REMEDIATION EXECUTION                                  │
├────────────────────────────────────────────────────────┤
│
│ Automated Methods:
│ • Windows Update: Group Policy → Microsoft Update
│ • Azure Update Management: Patch orchestration
│ • Runbooks: PowerShell scripts for custom patches
│ • Container images: Rebuild with patched base image
│
│ Manual Methods:
│ • RDP/SSH into VM → Manual patch application
│ • Azure portal: Apply specific updates
│ • Scripts: Custom remediation logic
│
└────────────────────┬─────────────────────────────────┘
                     │
                     ▼
┌────────────────────────────────────────────────────────┐
│ VERIFICATION & VALIDATION                              │
├────────────────────────────────────────────────────────┤
│
│ Post-Remediation Checks:
│ ├─ Rescan with Defender: Confirm vulnerability gone
│ ├─ Performance: Monitor CPU, memory, connectivity
│ ├─ Functionality: Run smoke tests (API calls, etc.)
│ ├─ Logs: Check Windows/application logs for errors
│ └─ Security: Verify no misconfigurations introduced
│
│ If successful: Mark as "Remediated"
│ If failed: Rollback → Investigate → Retry
│
└────────────────────┬─────────────────────────────────┘
                     │
                     ▼
┌────────────────────────────────────────────────────────┐
│ CLOSURE & REPORTING                                    │
├────────────────────────────────────────────────────────┤
│
│ Documentation:
│ • Remediation ticket: Timestamp, method, verifier
│ • Audit trail: Who did what, when, why
│ • Lessons learned: What went well, what to improve
│
│ Metrics:
│ • Remediation rate: % of vulnerabilities fixed/month
│ • Mean time to remediate (MTTR): Days from discovery
│ • Regression: Verify vulnerability doesn't reappear
│
└────────────────────────────────────────────────────────┘
```

### Vulnerability Metrics Dashboard

**Monthly Report Format:**

```
VULNERABILITY MANAGEMENT REPORT - MARCH 2024

Discovered: 47 new vulnerabilities
├─ Critical (CVSS 9.0+): 2
├─ High (CVSS 7.0-8.9): 8
├─ Medium (CVSS 4.0-6.9): 22
└─ Low (< CVSS 4.0): 15

Remediated: 38 vulnerabilities (81%)
├─ Within SLA: 35 (92%)
├─ Overdue: 3 (missed deadline)
└─ In progress: 6 (active remediation)

Open: 9 vulnerabilities (17 days avg age)
├─ Waiting for change window: 4
├─ In testing phase: 3
├─ Accepted risk (documented): 2

Trends:
├─ Month-over-month remediation rate: +15% ↑ (positive)
├─ Average MTTR: 18 days (target: <14 days)
└─ Regression rate: 2% (new vulnerabilities on patched assets)

Actions:
1. Schedule critical patches for next maintenance (day/time)
2. Investigate overdue items, escalate blockers
3. Increase testing velocity for in-progress items
```

---

## Compliance Reporting

### Multi-Framework Compliance Tracking

**Compliance Status by Framework:**

```
COMPLIANCE ASSESSMENT - MARCH 2024

┌─────────────────────────────────────────────────┐
│ CIS Microsoft Azure Foundations v1.4.0          │
├─────────────────────────────────────────────────┤
│ Total Controls: 42                              │
│ Compliant:     35 (83%)  ████████░             │
│ Non-compliant: 5  (12%)  █░░░░░░░░             │
│ Not Applicable: 2  (5%)                         │
│                                                 │
│ Non-Compliance Details:                        │
│ 1. Activity log retention < 365 days           │
│ 2. Key Vault not set to "purge protection"     │
│ 3. Storage account TLS < 1.2                   │
│ 4. SQL Server missing encryption               │
│ 5. Application Gateway WAF not enabled         │
│                                                 │
│ Remediation: SLA 30 days (all critical)       │
└─────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────┐
│ NIST 800-53 Controls                            │
├─────────────────────────────────────────────────┤
│ Total: 26 controls assessed                     │
│ Compliant:     24 (92%)  █████████░            │
│ Non-compliant: 2  (8%)   █░░░░░░░░             │
│                                                 │
│ Focus Areas:                                    │
│ • Access Control (AC): 9/10 compliant          │
│ • Identification & Auth (IA): 4/4 compliant    │
│ • System & Communications (SC): 8/9 compliant  │
│ • Audit & Accountability (AU): 3/3 compliant   │
│                                                 │
│ Non-Compliance (gap analysis):                 │
│ 1. SC-7 Boundary Protection                    │
│    └─ Gap: WAF not on all public endpoints    │
│    └─ Remediation: Deploy WAF to APIs (2wk)   │
│                                                 │
│ 2. AU-2 Audit Events                           │
│    └─ Gap: Event logging not enabled on all   │
│    └─ Remediation: Enable diagnostic logs (1wk)
└─────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────┐
│ ISO 27001 Clauses                               │
├─────────────────────────────────────────────────┤
│ Clause A.5 (Organizational Controls): 3/3 ✓    │
│ Clause A.6 (People Controls): 7/8 → 87%       │
│ Clause A.7 (Physical Controls): 5/5 ✓          │
│ Clause A.8 (Technical Controls): 26/28 → 93%  │
│                                                 │
│ Gaps:                                           │
│ • A.6.2.2 (Skill assessment): Create training │
│ • A.8.1.3 (Asset inventory): Tag all resources │
│                                                 │
│ Overall ISO 27001 Readiness: 89% (audit-ready)
└─────────────────────────────────────────────────┘
```

### Evidence Collection & Export

**Automated Evidence Gathering:**

```powershell
# Export compliance findings to CSV for auditors
az security assessment list \
  --query "[].{Name:displayName, Status:status.code, Severity:metadata.severity}" \
  --output table > compliance-assessment-march-2024.csv

# Get all policy assignments and compliance status
az policy assignment list \
  --query "[].{Name:displayName, Status:policyDefinitionId}" \
  --output json > policy-compliance-report.json

# Extract audit logs for specific controls
az monitor activity-log list \
  --resource-group prod-security-rg \
  --caller "security@company.com" \
  --status Succeeded \
  --query "[].{Time:eventTimestamp, Operation:operationName, Status:status.value}" \
  --output table > audit-log-march-2024.csv

# Generate Defender for Cloud compliance scorecard
az security compliance-assessment list \
  --output json | jq '.[] | select(.complianceStandard == "CIS") | .' > cis-compliance-details.json
```

### Audit Readiness Checklist

```
AUDIT PREPARATION CHECKLIST - Q1 2024

Compliance Framework: SOC 2 Type II
Audit Period: January - March 2024
Audit Date: May 15, 2024

Evidence Categories:
□ Access Control
  □ MFA enrollment audit
  □ Privileged role assignments log
  □ Password policy screenshots
  □ Conditional Access policies export

□ Encryption & Key Management
  □ Storage account encryption status
  □ Database TDE enabled confirmation
  □ Key Vault access audit log
  □ CMK rotation history

□ Network Security
  □ NSG rule documentation
  □ Firewall rule audit
  □ WAF configuration export
  □ DDoS mitigation events

□ Monitoring & Logging
  □ Log Analytics workspace schema
  □ Retention policy documentation
  □ Sentinel alert rules export
  □ Incident response playbooks

□ Vulnerability Management
  □ Defender for Cloud scanning results
  □ Vulnerability remediation tracking
  □ Patch management policy
  □ Risk assessment documentation

□ Change Management
  □ CAB approval log
  □ Change ticket history
  □ Rollback procedures
  □ Impact assessments

Collection Status:
├─ Access Control: 5/5 items ✓ (100%)
├─ Encryption: 4/4 items ✓ (100%)
├─ Network: 3/4 items ⚠ (75% - missing firewall audit)
├─ Monitoring: 4/4 items ✓ (100%)
├─ Vulnerability: 4/4 items ✓ (100%)
└─ Change Mgmt: 6/6 items ✓ (100%)

Overall: 26/27 items (96%) ready
□ Schedule auditor walkthrough (2 weeks before audit)
□ Final evidence review meeting
```

---

## KPIs & Dashboards

### Key Performance Indicators

**Security Posture Metrics:**

| KPI | Baseline | Q1 2024 | Target 2024 | Trend |
|-----|----------|---------|------------|-------|
| Secure Score | 55/100 | 72/100 | 80/100 | ↑ +17 |
| CIS Compliance | 65% | 83% | 95% | ↑ +18% |
| Critical Vuln Count | 8 | 2 | 0 | ↓ -75% |
| Avg Remediation Time | 45 days | 18 days | <14 days | ↓ -60% |
| Device Compliance | 75% | 94% | 98% | ↑ +19% |
| MFA Enrollment | 60% | 98% | 100% | ↑ +40% |

**Operational Metrics:**

| Metric | Target | Current | Status |
|--------|--------|---------|--------|
| Mean Time to Detect (MTTD) | <5 min | 3 min | ✓ Pass |
| Mean Time to Respond (MTTR) | <30 min | 45 min | ✗ Fail (SLA miss) |
| False Positive Rate | <15% | 22% | ✗ Fail (tuning needed) |
| Alert Fatigue Ratio | <0.3 | 0.25 | ✓ Pass |
| Incident Resolution Rate | >90% | 85% | ✗ Fail (team capacity) |

**Compliance Metrics:**

| Framework | Q1 2024 | Q2 Target | Evidence Complete |
|-----------|---------|-----------|------------------|
| CIS Azure | 83% | 92% | 95% |
| NIST 800-53 | 92% | 97% | 100% |
| ISO 27001 | 89% | 96% | 90% |
| PCI-DSS 3.2.1 | 88% | 98% | 85% |

### Executive Dashboard

```
┌──────────────────────────────────────────────────────────────┐
│           SECURITY POSTURE EXECUTIVE DASHBOARD               │
│                     MARCH 2024 REPORT                        │
├──────────────────────────────────────────────────────────────┤
│
│ OVERALL RISK SCORE: 28/100 (MEDIUM RISK)   ↓ Improving
│
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ KEY METRICS                                             │ │
│ ├─────────────────────────────────────────────────────────┤ │
│ │                                                         │ │
│ │  Secure Score          Compliance Rate    Incident SLA  │ │
│ │  ┌──────────┐         ┌──────────┐       ┌──────────┐  │ │
│ │  │   72/100 │         │   83/100 │       │  92/100  │  │ │
│ │  │ ↑ +5 pts │         │ ↑ +12%   │       │ ↑ +8%    │  │ │
│ │  └──────────┘         └──────────┘       └──────────┘  │ │
│ │                                                         │ │
│ │  Critical Issues: 2    Open Vulnerabilities: 9         │ │
│ │  └─ RDP exposed on 3 VMs (remediation: 5 days overdue) │ │
│ │  └─ SQL without encryption (patch pending)             │ │
│ │                                                         │ │
│ │  Top Risk: RCE vulnerability in Apache (CVSS 9.8)     │ │
│ │  └─ Action: Patch scheduled for Wed 03/22 02:00 UTC   │ │
│ └─────────────────────────────────────────────────────────┘ │
│
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ TREND ANALYSIS (6-MONTH VIEW)                           │ │
│ ├─────────────────────────────────────────────────────────┤ │
│ │                                                         │ │
│ │ Secure Score Trend:                                     │ │
│ │ Sep │ Oct │ Nov │ Dec │ Jan │ Feb │ Mar │ Apr (target) │ │
│ │ 50  │ 55  │ 60  │ 62  │ 68  │ 70  │ 72  │ 76 →       │ │
│ │ └──────────────────────────────────────────────────► │ │
│ │                                                         │ │
│ │ Remediation Rate Trend (days to close):                │ │
│ │ Previous avg: 45 days   Current avg: 18 days  ↓ -60%  │ │
│ │                                                         │ │
│ │ Vulnerability Count Trend (critical only):             │ │
│ │ Sep │ Oct │ Nov │ Dec │ Jan │ Feb │ Mar │             │ │
│ │ 12  │ 10  │ 8   │ 7   │ 5   │ 3   │ 2   │ ↓ Target: 0│ │
│ └─────────────────────────────────────────────────────────┘ │
│
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ PRIORITY ACTIONS (Next 30 Days)                        │ │
│ ├─────────────────────────────────────────────────────────┤ │
│ │                                                         │ │
│ │ 1. Remediate exposed RDP (3 VMs)                        │ │
│ │    Status: In Progress │ Owner: Cloud Team │ Due: 3/24 │ │
│ │                                                         │ │
│ │ 2. Enable encryption on SQL Server databases (8 DBs)    │ │
│ │    Status: Pending │ Owner: DBA Team │ Due: 3/31       │ │
│ │                                                         │ │
│ │ 3. Patch Apache vulnerability (5 servers)              │ │
│ │    Status: Scheduled │ Owner: Ops │ Due: 3/22 02:00 UTC│ │
│ │                                                         │ │
│ │ 4. Reduce false positive rate in Sentinel (22% → <15%)│ │
│ │    Status: In Progress │ Owner: SOC │ Due: 3/30        │ │
│ │                                                         │ │
│ │ 5. Complete ISO 27001 audit evidence collection        │ │
│ │    Status: 90% Complete │ Owner: Compliance │ Due: 4/15│ │
│ │                                                         │ │
│ └─────────────────────────────────────────────────────────┘ │
│
│ Next Review: April 15, 2024
│ Prepared by: Security Architecture Team
│ Distribution: CISO, VPs, Board
│
└──────────────────────────────────────────────────────────────┘
```

### Technical Dashboard (SOC View)

```
┌──────────────────────────────────────────────────────────────┐
│         SECURITY OPERATIONS CENTER (SOC) DASHBOARD          │
│                  Real-time Monitoring (Live)                │
├──────────────────────────────────────────────────────────────┤
│
│ ALERTS & INCIDENTS (Last 24 Hours)
│
│ Critical: 1  │ High: 5  │ Medium: 18  │ Low: 42  │ Info: 156
│ ███░░░░░░░░ │ ██████░░ │ ███████░░░ │ ████████ │ ████████
│
│ ┌──────────────────────────────────────────────────────────┐
│ │ ACTIVE INCIDENTS                                         │
│ ├──────────────────────────────────────────────────────────┤
│ │ #INC-001234 │ CRITICAL │ RCE in Apache                   │
│ │             │ Owner: Incident Responder │ Age: 4 min    │
│ │             │ Resources affected: 5 servers             │
│ │             │ Status: INVESTIGATING                     │
│ │             │                                            │
│ │ #INC-001233 │ HIGH │ Privilege escalation attempt       │
│ │             │ Owner: Analyst-2 │ Age: 2 hours          │
│ │             │ User: john.doe@company.com                │
│ │             │ Status: UNDER REVIEW                      │
│ │             │                                            │
│ │ #INC-001232 │ MEDIUM │ Anomalous data access           │
│ │             │ Owner: Analyst-1 │ Age: 6 hours          │
│ │             │ Database: prod-db-001                     │
│ │             │ Status: CLOSED (false positive)           │
│ └──────────────────────────────────────────────────────────┘
│
│ THREAT INTELLIGENCE FEEDS
│ ├─ Custom IOC (Indicators of Compromise): 2,456 entries
│ ├─ Microsoft threat intelligence: Updated 30 min ago
│ ├─ CISA alerts: 3 new advisories (review pending)
│ └─ Malware signatures: 45,678 patterns (auto-updated)
│
│ TOP AFFECTED RESOURCES (by incident count, 24h)
│ 1. prod-db-001 (SQL Server)          │ 5 incidents ████░
│ 2. prod-api-01 (App Service)         │ 3 incidents ███░░
│ 3. prod-vm-002 (Azure VM)            │ 2 incidents ██░░░
│ 4. storage-prod (Storage Account)    │ 1 incident  █░░░░
│
│ TEAM STATUS
│ ├─ L1 (Alert Triage): 3/3 analysts online ●●●
│ ├─ L2 (Investigation): 2/2 engineers online ●●
│ ├─ L3 (Escalation): 1/1 manager on-call ●
│ └─ Next shift start: 08:00 UTC (in 2 hours)
│
│ QUEUE STATUS
│ ├─ Alerts awaiting triage: 12
│ ├─ Incidents in progress: 3
│ ├─ Avg response time (critical): 4 min ✓
│ └─ Avg response time (high): 22 min ✓
│
└──────────────────────────────────────────────────────────────┘
```

---

## Automation & Remediation

### SOAR Playbooks (Logic Apps)

**Playbook 1: Auto-Remediate Exposed RDP**

```yaml
Name: "Auto-Remediate-Exposed-RDP"
Trigger: Alert from Sentinel (Public RDP detected)

Steps:
  1. Parse alert JSON
     ├─ Extract: VM name, resource group, public IP
     └─ Validate: Is this expected? (check change ticket)

  2. Check VM owner
     ├─ Query: VM tags → Owner email
     ├─ If no owner: Escalate to team lead
     └─ Send email: "Your VM has exposed RDP"

  3. Update NSG rule
     ├─ Deny: Inbound RDP (3389) from internet
     ├─ Allow: RDP only from Azure Bastion (10.0.1.0/24)
     └─ Log change: NSG modification recorded

  4. Verify remediation
     ├─ Re-scan: Check if RDP still public (wait 5 min)
     ├─ If still exposed: Escalate → manual review
     └─ If remediated: Close incident ✓

  5. Notify owner
     ├─ Email summary: What was done, why, verification
     ├─ Instructions: How to access VM via Bastion
     └─ Timeline: NSG change was X minutes ago

Actions:
  Success: Close alert, update incident, log remediation
  Failure: Escalate, create ticket, page on-call engineer
```

**Playbook 2: Isolate Compromised User**

```yaml
Name: "Isolate-Compromised-User"
Trigger: Alert (Impossible travel, brute force, etc.)

Steps:
  1. Verify alert
     ├─ Check: Is sign-in attempt from known location?
     ├─ Check: Is device compliant?
     └─ If legitimate: Dismiss alert (user confirmed)

  2. Block user (immediate action)
     ├─ Entra ID: Disable sign-in
     ├─ Email user: "Your account was blocked due to suspicious activity"
     └─ Notify manager: "User account compromised, investigation underway"

  3. Revoke tokens
     ├─ Revoke: All active sessions
     ├─ Revoke: All refresh tokens
     └─ Force re-authentication: Next login requires MFA

  4. Change password (admin-initiated)
     ├─ Generate: Random 32-char password
     ├─ Send: Temporary password to registered email (OOB channel)
     └─ Force reset: User must change on next login

  5. Reset MFA
     ├─ Clear: All MFA methods
     ├─ Require: MFA re-enrollment (FIDO2 only, no SMS)
     └─ Send: Instructions to enroll via authenticator app

  6. Investigation
     ├─ Collect: Recent sign-in logs for this user
     ├─ Analyze: Which resources were accessed
     ├─ Check: If other accounts compromised (lateral movement)
     └─ Search: For malicious activity in Sentinel

  7. Notify Security Team
     ├─ Create ticket: Link to this playbook run
     ├─ Email: Incident details, timeline, actions taken
     ├─ Page: On-call incident commander if critical
     └─ Timeline: Full forensic investigation (24-48 hours)

Actions:
  Next step: Manual investigation → Restore access once safe
```

**Playbook 3: Auto-Patch Vulnerability**

```yaml
Name: "Auto-Patch-Critical-Vulnerability"
Trigger: New critical vulnerability (CVSS >= 9.0)

Prerequisites:
  - Vulnerability has public patch available
  - Patch tested and approved for environment
  - Maintenance window scheduled

Steps:
  1. Get patch details
     ├─ CVE ID, description, severity
     ├─ Affected systems: Query (OS type, version)
     └─ Patch download URL

  2. Pre-patch checks
     ├─ Backup: Snapshot VM or DB
     ├─ Notify: Users of maintenance window
     ├─ Verify: Patch MD5 checksum (security)
     └─ Test: Patch in dev/test environment (already done)

  3. Apply patch
     ├─ For VMs: Run Azure Update Management
     │   └─ Sequentially patch: 2 VMs at a time (HA)
     ├─ For SQL: Schedule maintenance window
     │   └─ Backup + apply patch + verify
     └─ For containers: Rebuild image + push to registry

  4. Post-patch validation
     ├─ Rescan: Vulnerability assessment confirms patch
     ├─ Test: Application smoke tests pass
     ├─ Monitor: CPU, memory, error rates (no regression)
     └─ Logs: Windows/application logs show no errors

  5. Notify stakeholders
     ├─ Success email: Patch deployed successfully
     ├─ Evidence: Vulnerability scan proof (before/after)
     ├─ SLA: Patch applied within X hours of release
     └─ Next: Schedule next patch window if needed

  6. Close ticket
     ├─ Update: CMDB with patch details
     ├─ Archive: Patch application logs
     └─ Metrics: Time from vulnerability → patched

Actions:
  Success: Incident resolved, team notified
  Failure: Rollback → Manual investigation → Page on-call
```

### Integration with Change Management

```
┌────────────────────────────────────────────────────────┐
│ CHANGE REQUEST (CAB approval required)                 │
├────────────────────────────────────────────────────────┤
│ Title: Auto-remediate exposed RDP ports               │
│ Type: Security Automation                              │
│ Risk: Low (restricts public access, improves security)│
│ Approver: Cloud Architecture + Security Team          │
│ Status: APPROVED ✓                                    │
│ Change window: 2024-03-22 02:00-04:00 UTC            │
│                                                        │
│ Runbook: Trigger SOAR playbook automatically          │
│ Trigger: Sentinel alert (public RDP detected)         │
│ Action: Update NSG to deny inbound 3389               │
│ Rollback: Manual NSG restoration (if needed)          │
│ Notification: Email owner, escalate if failure        │
│                                                        │
│ Approval signature: _______________                    │
│ CAB date: 2024-03-15                                  │
└────────────────────────────────────────────────────────┘
                        ↓
            Automation approved for deployment
                        ↓
         Run Logic App on alert (no manual step)
                        ↓
         Auto-execute remediation within 5 min
                        ↓
         Send summary email (what happened, why, SLA)
```

---

## Appendices

### A. Defender for Cloud Assessment Policies

**Security Baseline (Microsoft Cloud Security Benchmark v1):**

| Category | Assessment | Recommendation |
|----------|-----------|-----------------|
| Network | Public storage access | Disable anonymous blob access |
| Data | Unencrypted data | Enable encryption at rest (CMK) |
| Identity | Legacy auth | Disable legacy protocols |
| Compute | Missing patches | Apply critical updates |
| Monitoring | No logging | Enable audit logging |

### B. Azure Policy Remediation Examples

**Policy: Enforce HTTPS-only on storage accounts**

```json
{
  "properties": {
    "displayName": "Enforce HTTPS only on storage accounts",
    "policyType": "BuiltIn",
    "mode": "All",
    "description": "Force HTTPS for all storage connections",
    "policyRule": {
      "if": {
        "allOf": [
          {"field": "type", "equals": "Microsoft.Storage/storageAccounts"},
          {"field": "Microsoft.Storage/storageAccounts/supportsHttpsTrafficOnly", "equals": "false"}
        ]
      },
      "then": {
        "effect": "auditIfNotExists",
        "details": {
          "type": "Microsoft.Storage/storageAccounts",
          "existenceCondition": {
            "field": "Microsoft.Storage/storageAccounts/supportsHttpsTrafficOnly",
            "equals": "true"
          }
        }
      }
    }
  }
}
```

### C. Sentinel Alert Rule Library

**High-Value Rules (ready to deploy):**

```kusto
// Rule: Excessive privilege elevation requests
// Purpose: Detect potential privilege escalation attacks

AzureActivity
| where OperationName has "List role assignment"
| where ActivityStatus == "Succeeded"
| summarize TotalRequests=count() by Caller
| where TotalRequests > 10
| project Caller, TotalRequests, AlertSeverity="Medium"

// Rule: Unusual API calls (anomaly detection)
// Purpose: Detect lateral movement via API abuse

AzureActivity
| where TimeGenerated > ago(24h)
| summarize RecentCount=count() by Caller, OperationName
| join (
    AzureActivity
    | where TimeGenerated between (ago(30d) .. ago(1d))
    | summarize HistoricalCount=count() by Caller, OperationName
) on Caller, OperationName
| where RecentCount > HistoricalCount * 5
| project Caller, OperationName, AlertSeverity="High"

// Rule: Data exfiltration pattern detection
// Purpose: Identify possible data theft (bulk downloads)

StorageAccountAccessLogs
| where OperationName in ("GetBlob", "ListBlobs")
| summarize TotalBytes=sum(ResponseBodySize), RequestCount=count() by CallerIP, StorageAccount
| where TotalBytes > 10737418240  // > 10 GB in 1 hour
| project CallerIP, StorageAccount, TotalBytes, AlertSeverity="Critical"
```

### D. Compliance Framework Mapping

**NIST CSF → Azure Services Mapping:**

| NIST Function | Azure Service | Configuration |
|---------------|---------------|---------------|
| Identify (AM) | Asset inventory | Resource Graph + tagging |
| Protect (AC) | Network segmentation | NSGs + Firewall + Private endpoints |
| Protect (CR) | Encryption | Key Vault + TDE + Storage encryption |
| Detect (DE) | Threat detection | Defender for Cloud + Sentinel |
| Respond (RS) | Incident management | Logic Apps + automated playbooks |
| Recover (RC) | Backup/restore | Azure Backup + geo-redundancy |

---

**Document Version:** 1.0
**Last Updated:** March 2026
**Next Review:** June 2026
**Audience:** Security architects, SOC managers, compliance officers, cloud engineers
