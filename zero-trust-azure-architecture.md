# Zero Trust Security Architecture for Azure

## Executive Summary

This document provides a comprehensive Zero Trust security architecture design for enterprise Azure environments. Zero Trust is a security strategy that does not automatically trust anything inside or outside the network perimeter and instead verifies every access request as if it originates from an untrusted network.

**Key Outcomes:**
- 99.5%+ identity and device compliance
- <5 minute detection-to-response time for threats
- Complete audit trail for regulatory compliance
- Elimination of implicit trust relationships

**Target Audience:** Cloud architects, security engineers, compliance officers, infrastructure teams

---

## Table of Contents

1. [Zero Trust Principles](#zero-trust-principles)
2. [Architecture Overview](#architecture-overview)
3. [Seven Pillars of Zero Trust](#seven-pillars-of-zero-trust)
4. [Reference Architecture](#reference-architecture)
5. [NIST CSF Alignment](#nist-csf-alignment)
6. [Implementation Phases](#implementation-phases)
7. [Security Controls Matrix](#security-controls-matrix)
8. [Operational Procedures](#operational-procedures)

---

## Zero Trust Principles

### 1. Verify Explicitly

Every access request, regardless of origin or historical trust, must be verified using:
- **Primary factors:** Multi-factor authentication (MFA), passwordless sign-in
- **Device state:** Compliance status, encryption status, OS version
- **Network location:** IP address, geolocation, VPN status
- **Data classification:** Sensitivity level of requested resources
- **User context:** Risk score, sign-in risk, anomalous behavior

**Implementation:**
```
Authentication Flow:
User → MFA Challenge → Device Compliance Check → Risk Assessment →
Conditional Access Policy Evaluation → Grant/Deny/Session Control
```

### 2. Least Privilege Access

Users and service principals receive minimum permissions necessary:
- **Just-In-Time (JIT):** Temporary elevation of privileges
- **Just-Enough-Access (JEA):** Role-based access with resource scoping
- **Time-bound:** Access expires automatically
- **Approval workflows:** Human review for sensitive operations
- **Monitoring:** Real-time alerting on privileged operations

**Access Model:**
```
Base Role + Conditional Elevation (JIT) + Resource Constraints +
Time Limits + Approval Chain = Least Privilege
```

### 3. Assume Breach

Assume that attackers have already compromised some infrastructure:
- **Lateral movement prevention:** Network segmentation, encryption
- **Threat detection:** Continuous monitoring and anomaly detection
- **Incident response:** Automated response playbooks
- **Segmentation:** Zero Trust Network Access (ZTNA)
- **Encryption:** All data encrypted at rest and in transit

**Breach Assumption Model:**
```
If: Attacker has User Credentials
Then: MFA + Device Compliance + Risk Assessment prevents access

If: Attacker has Device Credentials
Then: Network segmentation + encryption prevents lateral movement

If: Attacker has Network Access
Then: Encrypted communications prevent data exfiltration
```

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                      ZERO TRUST ARCHITECTURE                     │
└─────────────────────────────────────────────────────────────────┘

┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│   Identity   │  │    Device    │  │   Network    │  │ Application  │
│    Pillar    │  │    Pillar    │  │    Pillar    │  │    Pillar    │
├──────────────┤  ├──────────────┤  ├──────────────┤  ├──────────────┤
│ • Entra ID   │  │ • Intune     │  │ • Firewall   │  │ • API Mgmt   │
│ • CA Policy  │  │ • Compliance │  │ • NSG        │  │ • WAF        │
│ • MFA        │  │ • Hybrid Join│  │ • Private EP │  │ • App Gate   │
│ • PIM        │  │ • Device CA  │  │ • Bastion    │  │ • Secrets    │
└──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘
         │               │                  │               │
         │               │                  │               │
         └───────────────┼──────────────────┼───────────────┘
                         │                  │
                    ┌────┴──────┐      ┌────┴──────┐
                    │    Data   │      │Visibility │
                    │   Pillar  │      │  Pillar   │
                    ├───────────┤      ├───────────┤
                    │ • Purview │      │ • Sentinel│
                    │ • KV      │      │ • Defender│
                    │ • Encrypt │      │ • Logs    │
                    │ • TDE     │      │ • Alerts  │
                    └───────────┘      └───────────┘
```

---

## Seven Pillars of Zero Trust

### Pillar 1: Identity

**Objective:** Authenticate all users and service principals; enforce least privilege

#### Azure Entra ID (formerly Azure AD)

**Configuration:**
- **Tenant Structure:** Dedicated security tenant for identity federation
- **User Provisioning:** Automated provisioning from HR systems via scoping filters
- **Group Management:** Dynamic membership groups based on user properties
- **B2B Collaboration:** External user federation with conditional access policies
- **Multi-tenant:** Cross-tenant resource access via Guest accounts

**Key Components:**

| Component | Configuration | Purpose |
|-----------|---------------|---------|
| User Accounts | Managed identities + Service Principals | Human and workload identities |
| Password Policy | 16+ characters, complexity, no history | Baseline authentication security |
| Password Reset | SSPR enabled, security questions disabled | User autonomy without helpdesk load |
| Hybrid Identity | AD Connect Sync + Cloud Sync agents | Consistent identity across on-premises and cloud |

#### Multi-Factor Authentication (MFA)

**Deployment Model:**
```
Baseline MFA: Microsoft Authenticator app (push notifications)
High-Risk Operations: Microsoft Authenticator app + FIDO2 security key
Administrative Access: Hardware FIDO2 key required
```

**MFA Enforcement:**
- All user sign-ins (except hardened endpoints)
- All administrative access (no exceptions)
- All external access (partner, vendor, contractor)
- Service principal access to sensitive resources (certificate-based, no secrets)

**Configuration:**
```
Authentication Methods Priority:
1. Passwordless sign-in (Windows Hello for Business, FIDO2)
2. Push notification approval (Microsoft Authenticator)
3. Time-based OTP (Microsoft Authenticator)
4. SMS (deprecated, emergency only)
5. Voice call (deprecated, emergency only)
```

#### Conditional Access Policies

**Policy Framework:**

| Policy Name | Condition | Action | Risk Level |
|-------------|-----------|--------|-----------|
| Block Legacy Auth | Legacy Protocol Detection | Block | Critical |
| Require MFA High-Risk | Risk Level >= High | Session MFA | High |
| Geo-Blocking | Country not in whitelist | Block | Critical |
| Require Compliant Device | Device Compliance = False | Block/Grant w/ Conditions | Medium |
| App Protection | Managed App Check = False | Session control | High |
| Insider Risk | Bulk download + Rapid file access | Alert + Monitor | Critical |

**Example Policy Logic:**
```
IF (Sign-in Risk = High OR User Risk = High)
  AND Device Compliance = False
THEN Require MFA + Session control to 1 hour
ELSE IF (Legacy Authentication Detected)
  THEN Block immediately
ELSE Grant access
```

#### Privileged Identity Management (PIM)

**Access Model:**
- **Admin Roles:** Require JIT elevation with approval
- **Approval Chain:** User's manager + Security team
- **Elevation Duration:** 1 hour for routine tasks, 4 hours for maintenance windows
- **Audit Trail:** Every elevation logged in audit logs

**Privileged Roles in Scope:**
- Global Administrator
- Security Administrator
- Exchange Administrator
- SharePoint Administrator
- User Administrator
- Cloud Application Administrator

**PIM Configuration:**
```
Activation Requirements:
├── Multifactor Authentication: Required
├── Justification: Required (business case)
├── Approval: User Manager + Security Team
├── Duration: 1-8 hours (configurable per role)
├── Time Limit: 8 hours maximum per day
└── Alerts: Email on activation + audit log entry
```

#### Self-Service Password Reset (SSPR)

**Configuration:**
- **Authentication Methods:** 2 methods required (email + security questions or mobile)
- **Enablement:** All users in security groups
- **Change Frequency:** Every 90 days (enforced)
- **History Enforcement:** Last 24 passwords cannot be reused
- **Passwordless Transition:** Windows Hello, FIDO2 migration path

---

### Pillar 2: Device

**Objective:** Ensure all devices meet security baselines before network access

#### Microsoft Intune Device Management

**Device Categories:**

| Category | Ownership | Enrollment | Compliance Requirements |
|----------|-----------|-----------|------------------------|
| Corporate | Organization | Mandatory | Full - Bitlocker, Defender, MFA |
| BYOD | Employee | Optional | Managed App Container |
| Kiosk | Shared | Locked-down | Single app, no personal use |
| IoT | Systems | Conditional | Device-specific baselines |

#### Compliance Policies

**Windows 10/11 Enterprise Compliance:**
```
Encryption:
  ├── BitLocker: Required (TPM 2.0 enforced)
  └── File-level: EFS for sensitive data

Operating System:
  ├── OS Version: Windows 10 21H2 or Windows 11 minimum
  ├── Build: Latest security build within 30 days
  ├── Updates: Critical/Security within 7 days
  └── Patches: Monthly quality rollup monthly

Security Settings:
  ├── Firewall: Windows Firewall enabled, domain profile
  ├── Antimalware: Windows Defender Antimalware Service enabled
  ├── Defender Signature: Updated daily
  ├── Real-time Protection: Enabled
  └── Cloud Protection: Enabled

Device Compliance:
  ├── TPM Version: 2.0 minimum
  ├── UEFI Firmware: Secure Boot enabled
  ├── Device Lock: PIN required, minimum 6 characters
  ├── Password: Enforced, minimum 14 characters, complexity
  └── Timeout: Screen locks after 5 minutes inactivity
```

**macOS Compliance:**
```
Encryption:
  └── FileVault 2: Required, recovery key escrowed

System:
  ├── OS Version: Latest 2 versions minimum
  ├── Gatekeeper: Enabled (signed apps only)
  └── SIP: System Integrity Protection enabled

Security:
  ├── Firewall: Enabled
  ├── Antimalware: Defender ATP required
  └── Secure Enclave: 2FA required
```

#### Hybrid Azure AD Join

**Architecture:**
```
On-Premises AD ←→ Azure AD Connect ←→ Azure Entra ID
        ↓
   Device Registration (Hybrid Join)
        ↓
   Intune Policy Application
        ↓
   Conditional Access Evaluation
```

**Device Registration Flow:**
1. User logs into domain-joined device with AD credentials
2. Azure AD Connect synchronizes device object to Azure Entra ID
3. Device registers with Azure Entra ID (hybrid join)
4. Intune applies compliance policies
5. Conditional Access evaluates device state on every authentication

**Benefits:**
- SSO to cloud and on-premises resources
- Conditional Access based on device compliance
- Granular Intune policy deployment
- Seamless Windows Hello for Business enrollment

#### Device Conditional Access

**Device-Based Policies:**

| Policy | Condition | Action |
|--------|-----------|--------|
| Corporate Device Required | Device = Unmanaged/Non-compliant | Block |
| Encrypted Disk Required | BitLocker = Disabled | Grant w/ Session Control |
| OS Update Required | Latest Update > 30 days old | Require MFA + Grant |
| Mobile Device Protection | Mobile OS < Latest - 2 versions | Block corporate data access |

---

### Pillar 3: Network

**Objective:** Prevent lateral movement and data exfiltration through network segmentation

#### Azure Firewall Premium

**Architecture:**
```
Internet
   ↓
Azure DDoS Standard (Layer 3-4 protection)
   ↓
Azure Firewall Premium (Layer 4-7 protection)
   ├── Network Rules (IP/Port)
   ├── Application Rules (FQDN/URL categories)
   ├── NAT Rules (DNAT for inbound)
   ├── TLS Inspection (SSL/TLS decryption for HTTPS inspection)
   └── Threat Intelligence (IP/Domain reputation blocking)
   ↓
Network Segmentation (NSGs)
   ↓
Workloads
```

**Firewall Rules Structure:**

```
Inbound (Internet → Azure):
1. Allow: Public endpoints (API Management, App Gateway)
2. Allow: Threat intelligence verified traffic
3. Deny: All others (default deny)

Egress (Azure → Internet):
1. Allow: Microsoft Update servers (Windows Update)
2. Allow: Azure services (API endpoints, CDN)
3. Allow: Whitelisted external services
4. Deny-log: Suspicious outbound (DLP detection)
5. Deny: All others (default deny)

East-West (Internal):
1. Allow: Application-specific rules (N-tier apps)
2. Deny: Lateral movement across subnets
3. Deny: Database access from non-app servers
```

**TLS Inspection Configuration:**
```
Root CA Deployed To:
├── Windows Trusted Root CA Store (Intune policy)
├── macOS Keychain (via MDM profile)
├── Azure VMs (via startup script)
└── Mobile Devices (via Intune App Configuration

Firefox CA Store:
├── Manually imported or
└── Deployed via GPO/Intune configuration profile
```

#### Network Security Groups (NSG)

**Tiered Network Design:**

```
Virtual Network: 10.0.0.0/16
│
├── Management Subnet: 10.0.1.0/24
│   ├── Purpose: Azure Bastion, jumphost
│   ├── NSG Rules: Inbound RDP/SSH only from trusted IPs
│   └── Outbound: Microsoft Update, Azure Management API
│
├── Identity Subnet: 10.0.2.0/24
│   ├── Purpose: Domain controllers (on-premises sync)
│   ├── NSG Rules: LDAP/Kerberos from app subnet only
│   └── Outbound: Azure AD Connect to Entra ID
│
├── Application Subnet: 10.0.10.0/24
│   ├── Purpose: Business logic, web servers
│   ├── NSG Rules: HTTP/HTTPS inbound from App Gateway only
│   ├── Inbound: Port 3389 (RDP) from Bastion only
│   └── Outbound: Database port 1433 to DB subnet only
│
├── Database Subnet: 10.0.20.0/24
│   ├── Purpose: SQL Database, PostgreSQL
│   ├── NSG Rules: Port 1433 inbound from app subnet only
│   ├── Outbound: Storage account for backups
│   └── Deny: Direct internet access
│
└── Integration Subnet: 10.0.30.0/24
    ├── Purpose: API Management, Logic Apps
    ├── NSG Rules: HTTP/HTTPS from CDN/public IPs
    └── Outbound: Backend services, external APIs
```

**NSG Rule Priority System:**
```
100: Deny all inbound from internet (baseline)
101-999: Allow specific inbound rules (ordered by restriction)
4000-4095: Deny all outbound (baseline)
4001-4099: Allow specific outbound rules
```

#### Private Endpoints & Service Endpoints

**Architecture:**
```
Virtual Network (10.0.0.0/16)
│
├── Private Endpoint: Storage Account
│   ├── Private IP: 10.0.20.100
│   ├── DNS: privatelink.blob.core.windows.net
│   └── Route: Via private network (no internet)
│
├── Private Endpoint: Key Vault
│   ├── Private IP: 10.0.20.101
│   ├── DNS: privatelink.vaultcore.azure.net
│   └── Route: Via private network (no internet)
│
├── Private Endpoint: SQL Database
│   ├── Private IP: 10.0.20.102
│   ├── DNS: privatelink.database.windows.net
│   └── Route: Via private network (no internet)
│
└── Service Endpoint: Service Bus
    ├── Traffic: Via Microsoft backbone (no internet)
    ├── ACL: VNet/Subnet restriction
    └── Outbound: To Service Bus namespace
```

**DNS Resolution for Private Endpoints:**
```
Private DNS Zone: privatelink.blob.core.windows.net
├── Record: blob.account.privatelink.blob.core.windows.net → 10.0.20.100
└── Link: VNet integration for automatic DNS resolution

Query Flow:
1. App queries blob.account.blob.core.windows.net
2. DNS resolver: privatelink.blob.core.windows.net zone
3. Returns: Private IP 10.0.20.100
4. Connection: Direct to private endpoint (no internet egress)
```

#### Azure Bastion

**Deployment:**
```
Azure Bastion Instance
├── SKU: Premium (concurrent sessions, session recording)
├── Deployment: Standard subnet (10.0.1.0/24)
└── Access: RDP/SSH through Azure Portal (no public IPs)

NSG Rules:
├── Inbound: Port 443 from GatewayManager, internet
├── Outbound: Port 3389, 22 to target subnet
└── Deny: Direct RDP/SSH from internet
```

**Session Recording (Premium SKU):**
```
Session Recordings → Managed Identity → Storage Account (Private Endpoint)
        ↓
    Archived (7-day retention)
        ↓
    Searchable via Portal (for incident investigation)
```

**Zero Trust RDP/SSH Access Pattern:**
```
User Device
    ↓
Azure Portal Authentication (Entra ID + MFA)
    ↓
Conditional Access Policy (Device compliance check)
    ↓
Bastion Session Initiated (MFA verified)
    ↓
RDP/SSH Connection (No public IP exposure)
    ↓
Session Logging + Recording (Audit trail)
    ↓
Automatic Logout (5-hour timeout)
```

---

### Pillar 4: Application

**Objective:** Protect application and API traffic from compromise and abuse

#### API Management

**Deployment:**
```
Clients
    ↓
Azure API Gateway (public endpoint)
    ↓
API Management Policy Engine
├── Rate limiting: 1000 req/min per subscription
├── Throttling: 100 req/sec per operation
├── Authentication: Subscription key + JWT validation
├── Authorization: RBAC based on JWT claims
├── Request inspection: Content validation, size limits
└── Response caching: 5-minute TTL for GET operations
    ↓
Backend APIs (private endpoints or firewall-protected)
```

**Security Policies:**

```yaml
inbound:
  - rate-limit:
      calls: 1000
      renewal-period: 60
  - set-header:
      name: X-CSRF-Token
      value: Token
  - validate-jwt:
      openid-config-url: "https://{tenant}.b2clogin.com/{tenant}.onmicrosoft.com/v2.0/.well-known/openid-configuration"
      audiences: api-id
      claim-checks: required
  - cors:
      allowed-origins: [*.example.com]
      allowed-methods: [GET, POST]

outbound:
  - set-header:
      name: Strict-Transport-Security
      value: "max-age=31536000; includeSubDomains"
  - set-header:
      name: X-Frame-Options
      value: "DENY"
  - set-header:
      name: X-Content-Type-Options
      value: "nosniff"
```

#### Web Application Firewall (WAF)

**Deployment:**
```
Internet
    ↓
Azure DDoS Standard
    ↓
Azure WAF (attached to App Gateway or CDN)
├── OWASP Top 10 protection
├── Custom rules (regex-based blocking)
├── Geo-filtering
├── Rate limiting
├── IP reputation filtering
└── Botnet protection
    ↓
Application Backend
```

**WAF Rule Sets:**

| Rule Set | Purpose | Sensitivity |
|----------|---------|-------------|
| OWASP CRS 3.2 | Core rule set (injection, XSS, etc.) | Medium (default) |
| Microsoft Managed Rules | Threat intelligence-based | High |
| Custom Rules | Organization-specific patterns | Medium |
| Geo-blocking | Whitelist allowed countries | High |
| Rate-limiting | DDoS/brute force prevention | Medium |

**Example Custom Rules:**
```
Rule 1: Block SQL Injection patterns
  Condition: RequestBody contains "UNION.*SELECT" (regex)
  Action: Block
  Priority: 10

Rule 2: Block API abuse
  Condition: Path = "/api/login" AND RequestCount > 10/minute
  Action: Block (status 429)
  Priority: 20

Rule 3: Geographic restriction
  Condition: Client IP geolocation NOT IN [US, CA, MX]
  Action: Block
  Priority: 5
```

#### Application Gateway

**Deployment:**
```
Internet
    ↓
Application Gateway (public IP)
├── HTTP(S) listener (port 80, 443)
├── SSL/TLS termination (Azure-managed or customer-managed certs)
├── WAF integration
├── Backend pool (multiple instances for HA)
├── Health probes (HTTP 200 expected)
└── Path-based routing (if needed)
    ↓
Backend VMs/VMSS (private IPs, NSG restricted)
```

**SSL/TLS Configuration:**
```
Cipher Suites (TLS 1.2+):
├── TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (priority 1)
├── TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (priority 2)
├── TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (priority 3)
└── Deny: TLS 1.0, TLS 1.1, weak ciphers

Certificate Management:
├── Customer-managed: Private key in Key Vault (Managed Identity access)
├── Azure-managed: Auto-renewal, no key access needed
└── SNI: Multiple certificates per listener
```

---

### Pillar 5: Data

**Objective:** Classify, encrypt, and protect data throughout its lifecycle

#### Microsoft Purview Information Protection

**Data Classification:**

```
Classification Levels:
├── Public: No sensitivity, can be disclosed
├── Internal: Organization use only, not for public
├── Confidential: Limited distribution, unauthorized disclosure risk
├── Highly Confidential: Restricted access, severe impact if disclosed
└── Restricted: Individual records (PII, PHI, PCI)

Automatic Classification Rules:
├── Credit card numbers → Highly Confidential
├── Social Security numbers → Restricted (PII)
├── Health information → Restricted (PHI)
├── Customer data → Confidential
└── Public marketing materials → Public
```

**Policy Enforcement:**

```
File with "Confidential" label:
├── Storage: Azure Blob with encryption key in Key Vault
├── Sharing: Only authenticated users, audit trail
├── Printing: Watermark, no local copy
├── DLP: Block email to external recipients
├── Retention: 7 years minimum, then delete
└── Alert: Admin notified on unauthorized access
```

#### Encryption at Rest

**Storage Encryption:**

| Service | Encryption Method | Key Management |
|---------|-------------------|-----------------|
| Azure Storage | AES-256 (SSE-SA or SSE-CMK) | Customer-managed in Key Vault |
| SQL Database | Transparent Data Encryption (TDE) | Azure-managed or BYOK |
| Cosmos DB | AES-256 | Azure-managed or CMK |
| Azure VMs | Disk encryption set (CMK) | Customer-managed in Key Vault |

**Implementation:**

```
Storage Account:
1. Create Managed Identity for app
2. Grant Key Vault key access to Managed Identity
3. Configure encryption scope with customer-managed key
4. All blobs encrypted with CMK automatically

SQL Database:
1. Enable TDE with CMK
2. Store master key in Key Vault
3. Grant database access to Key Vault
4. Auto-rotation of CMK enabled

VM Disk:
1. Create disk encryption set with CMK
2. Apply encryption set to data disks
3. Managed Identity for key access
4. Enable secure boot + TPM 2.0
```

#### Encryption in Transit

**Network Communications:**

| Protocol | Encryption | Key Exchange | Usage |
|----------|-----------|-------------|-------|
| HTTPS (TLS 1.2+) | AES-256-GCM | ECDHE | Web APIs, portals |
| SQL Server (TLS 1.2+) | AES-256-GCM | ECDHE | Database connections |
| Service Bus (AMQP over TLS) | AES-256-GCM | ECDHE | Message brokers |
| Storage (HTTPS only) | AES-256-GCM | ECDHE | Blob, queue, table |

**Enforcement:**
```
Azure Storage:
├── Require Secure Transfer: Enabled (HTTPS only)
├── Minimum TLS Version: 1.2
└── Disable HTTP: Listener removed

Application:
├── HSTS header: Strict-Transport-Security (1 year)
├── Certificate pinning: For API clients
└── Certificate validation: Hostname verification enabled
```

#### Azure Key Vault

**Architecture:**
```
Secrets Management
├── Storage account access keys
├── Database connection strings
├── API keys for third-party services
└── SSH private keys

Encryption Keys
├── Customer-managed encryption keys (CMK)
├── Disk encryption keys
└── TDE master keys

Certificates
├── SSL/TLS certificates for web services
├── Client certificates for authentication
└── Code signing certificates
```

**Access Control:**
```
Azure RBAC:
├── Key Vault Secrets Officer: Full access
├── Key Vault Reader: Read metadata
└── Key Vault Crypto Service Encryption User: Encrypt/decrypt only

Network Access:
├── Public endpoint: Disabled or restricted to trusted IPs
├── Private endpoint: Enabled for app communication
└── Service endpoint: Not recommended (classic)

Auditing:
├── All access logged to Storage account
├── Retention: 7 years
└── Alert: Unauthorized access attempts
```

---

### Pillar 6: Visibility & Analytics

**Objective:** Detect threats and maintain compliance posture through continuous monitoring

#### Microsoft Sentinel (SIEM)

**Architecture:**
```
Data Sources
├── Azure Activity Logs
├── Azure Audit Logs
├── Firewall logs
├── IDS/IPS alerts
├── Endpoint Detection & Response (EDR)
├── Third-party syslog
└── Custom logs
    ↓
Log Analytics Workspace
├── Ingestion: 1GB+/day
├── Retention: 90 days (searchable), 2-year archive
└── Tier: Pay-as-you-go
    ↓
Sentinel Analytics
├── Scheduled alerts (KQL queries)
├── Anomaly detection (ML-based)
├── Threat intelligence correlation
└── Fusion (advanced multi-stage attack detection)
    ↓
Incident Management
├── Grouping: Related alerts → Incident
├── Triage: Severity, false positive filtering
├── Automation: SOAR playbooks
└── Response: Ticket creation, user disable, isolation
```

**Data Connectors:**

| Connector | Data Type | Latency |
|-----------|-----------|---------|
| Azure Activity | Resource deployment, IAM changes | 5 min |
| Audit Logs | User sign-ins, privilege escalation | 10 min |
| Azure Firewall | Network flow, threat intel matches | 1 min |
| Defender for Cloud | Security findings, vulnerability scores | 5 min |
| Windows Security Event | EDR telemetry, process execution | Real-time |
| AWS CloudTrail | Cross-cloud activity (if federated) | 10 min |

**Alert Rules (KQL Examples):**

```kusto
// Suspicious sign-in pattern: 10+ failed attempts in 5 minutes
SigninLogs
| where ResultType != "0"
| where TimeGenerated > ago(5m)
| summarize count() by UserPrincipalName
| where count_ >= 10
| project UserPrincipalName, AlertSeverity="High"

// Privileged operation outside business hours
AuditLogs
| where OperationName has "Add member to role"
| where TimeGenerated !between (datetime(2024-01-01 09:00), datetime(2024-01-01 18:00))
| project User=InitiatedBy, Role=TargetResources[0], AlertSeverity="Medium"

// Bulk file deletion (possible ransomware)
StorageAccountLogs
| where OperationName == "DeleteBlob"
| summarize count() by AccountName
| where count_ > 100
| project AlertSeverity="Critical"
```

#### Defender for Cloud

**Configuration:**
```
Subscription: Enabled (Standard or Premium)
│
├── Vulnerability Assessment
│   ├── Asset discovery: VMs, container registries, databases
│   ├── Scan frequency: Continuous (agents) or on-demand (agentless)
│   ├── Remediation: Patching recommendations with SLA
│   └── Tracking: Dashboards by severity, remediation progress
│
├── Threat Detection
│   ├── Behavioral analysis: User anomalies, impossible travel
│   ├── Machine learning: Malware detection, lateral movement
│   ├── Signature-based: Known attack patterns
│   └── Alerting: Real-time, integrated with Sentinel
│
├── Compliance Monitoring
│   ├── Standards: CIS, PCI-DSS, ISO 27001, NIST
│   ├── Continuous assessment: Resource compliance status
│   ├── Regulatory reporting: Evidence collection for audits
│   └── Remediation tracking: Control implementation progress
│
└── Attack Path Analysis
    ├── Graph model: All resources and their relationships
    ├── Lateral movement paths: Attacker's probable moves
    ├── Risk prioritization: High-impact vulnerabilities first
    └── Contextual recommendations: Reduce exposure paths
```

**Defender Plans:**

| Plan | Coverage | Annual Cost (per resource) |
|------|----------|--------------------------|
| Servers | VMs, Arc machines, vulnerability scanning | $15 |
| SQL Servers | Azure SQL, SQL on VMs, threat detection | $15 |
| Storage | Blob anomaly detection, malware analysis | $0.02 per GB |
| Containers | ACR scanning, K8s threat detection | $20 |
| App Service | Web app anomaly detection, DDoS alerts | $10 |

**Microsoft Cloud Security Benchmark (MCSB):**
```
Security Control Groups:
├── Network Security: Firewall, NSG, DDoS
├── Identity and Access Control: RBAC, MFA, PIM
├── Data Protection: Encryption, DLP, classification
├── Asset Management: Inventory, tagging, lifecycle
├── Logging and Threat Detection: Audit logging, SIEM
├── Incident Response: Playbooks, automation, runbooks
├── Governance and Strategy: Policies, training, reviews
└── Supply Chain Security: Dependency scanning, attestation

Baseline Configuration:
Each control mapped to Azure services with recommended settings.
Measured via secure score (0-800 points).
```

#### Log Analytics Workspace

**Configuration:**
```
Workspace: prod-logs-eastus
├── Pricing Tier: Pay-as-you-go (per GB ingested)
├── Data Retention: 90 days (searchable), 2 years (archive)
├── Daily ingestion cap: 10 GB
└── Private endpoint: Enabled (data doesn't traverse internet)

Data Tables:
├── AzureActivity: Resource deployments, RBAC changes
├── SigninLogs: User authentications, risk indicators
├── AuditLogs: Privilege elevations, configuration changes
├── SecurityEvent: Windows Security events (Process execution, etc.)
└── Custom tables: Application logs (ingested via API or agent)

Access Control:
├── Azure RBAC: Log Analytics Reader role for ops team
├── Resource context: View logs only for permitted resources
├── Query-level RBAC: Row-level security via KQL filtering
└── Audit: All queries logged for compliance
```

---

## Reference Architecture Diagram

```
INTERNET
    │
    ├─────────────────────────────────────────────────────
    │
    ▼
┌─────────────────────────────────────────────────────────┐
│          AZURE DDoS PROTECTION STANDARD                 │
│  (Layer 3-4, automatic attack detection/mitigation)     │
└─────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────┐
│           AZURE FIREWALL PREMIUM                        │
│  ┌────────────────────────────────────────────────────┐ │
│  │ Threat Intelligence Filtering (IP/Domain blocking) │ │
│  │ Application Rules (FQDN, URL categories)          │ │
│  │ TLS Inspection (Layer 7 deep packet inspection)    │ │
│  └────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
    │
    ├──────────────────────────────────────────────────────
    │
    ├─── HTTP/HTTPS ─────────────────────────────────────┐
    │                                                      │
    ▼                                                      ▼
┌──────────────────┐                          ┌────────────────────────┐
│  API MANAGEMENT  │                          │  APPLICATION GATEWAY   │
│  + WAF           │                          │  + WAF                 │
└──────────────────┘                          └────────────────────────┘
    │                                              │
    └──────────────────────────┬───────────────────┘
                               │
                    ┌──────────▼────────────┐
                    │  VIRTUAL NETWORK      │
                    │  10.0.0.0/16          │
                    └──────────┬────────────┘
                               │
        ┌──────────────────────┼──────────────────────┐
        │                      │                      │
    ┌───▼──────────┐    ┌──────▼──────┐    ┌─────────▼─────┐
    │ AZURE BASTION│    │   APP TIER  │    │  DATABASE     │
    │ (Jump Host)  │    │  (Private)  │    │   TIER        │
    └──────────────┘    └─────────────┘    └───────────────┘
        │                      │                    │
        │                      ▼                    │
        │              ┌─────────────────────────┐  │
        │              │  App Service / VMs      │  │
        │              │  Managed Identities     │  │
        │              └─────────────────────────┘  │
        │                      │                    │
        └──────────────────────┼────────────────────┘
                               │
                    ┌──────────▼────────────┐
                    │   KEY VAULT           │
                    │  (CMK, Secrets)       │
                    └───────────────────────┘
                               │
                    ┌──────────▼────────────┐
                    │  STORAGE ACCOUNT      │
                    │ (Encrypted, Private)  │
                    └───────────────────────┘
                               │
        ┌──────────────────────┼──────────────────────┐
        │                      │                      │
    ┌───▼────────────┐  ┌──────▼──────┐    ┌─────────▼─────┐
    │  ENTRA ID      │  │   SENTINEL  │    │ DEFENDER FOR  │
    │  (Authentication)│  │   (SIEM)   │    │    CLOUD      │
    └────────────────┘  └─────────────┘    └───────────────┘
        │                      │                    │
        ├──────────────────────┼────────────────────┤
        │                      │                    │
        ▼                      ▼                    ▼
    ┌─────────────────────────────────────────────────────┐
    │       LOG ANALYTICS WORKSPACE                       │
    │  (Logs, metrics, telemetry - 90d hot, 2yr archive) │
    └─────────────────────────────────────────────────────┘
        │
        ├─── Analytics Rules ──────► Sentinel Incidents
        ├─── KQL Queries ──────────► Custom dashboards
        ├─── Export Rules ─────────► SOAR Playbooks
        └─── API Access ───────────► Third-party tools

AUTOMATION LAYER (responds to alerts):
├─ Playbook 1: Disable compromised user + notify admin
├─ Playbook 2: Isolate affected VM from network
└─ Playbook 3: Collect forensic evidence + lock account
```

---

## NIST CSF Alignment

### Govern (Policy & Risk Management)

| NIST Function | Azure Implementation | Outcome |
|---------------|---------------------|---------|
| Asset Management | Purview + tags | Inventory of all resources |
| Business Environment | Policy-driven naming | Clear resource ownership |
| Risk Assessment | Defender for Cloud | Prioritized remediation |
| Risk Management Strategy | Security baseline policies | Consistent controls |

### Identify

| NIST Category | Control | Implementation |
|---------------|---------|-----------------|
| AM-1: Physical and cyber assets identified | Azure Resource Graph + tagging | All resources tracked |
| AM-2: Software platforms and applications tracked | Defender for Cloud asset inventory | Apps/versions enumerated |
| BE-1: Business objectives defined | Governance structure established | Security aligned with goals |

### Protect

| NIST Category | Control | Implementation |
|---------------|---------|-----------------|
| AA-1: Access authorization | Entra ID RBAC, PIM | Least privilege enforced |
| AA-2: Privileged access managed | PIM with JIT elevation | Temporary admin access |
| AC-1: Access enforcement | NSG, firewall, NACLs | Network segmentation |
| AC-2: Data flow enforcement | DLP policies, encryption | Data protected in transit/rest |
| PR-6: Data recovery capability | Backup + replication | RPO < 1 hour, RTO < 4 hours |

### Detect

| NIST Category | Control | Implementation |
|---------------|---------|-----------------|
| DE-1: Anomalies detected | Sentinel ML analytics | Behavioral anomalies flagged |
| DE-2: Incidents detected | Defender for Cloud + Sentinel | Threat detection active |
| DE-3: Environmental changes detected | Activity logs + audit logs | Change tracking automated |

### Respond

| NIST Category | Control | Implementation |
|---------------|---------|-----------------|
| RS-1: Response plan executed | SOAR playbooks (Logic Apps) | Automated response |
| RS-2: Incidents analyzed | Sentinel incident management | Forensics + root cause |
| RS-3: Incidents contained | Isolation playbooks | Lateral movement prevented |

### Recover

| NIST Category | Control | Implementation |
|---------------|---------|-----------------|
| RC-1: Recovery procedures | Tested backup/restore | RTO < 4 hours validated |
| RC-2: Resilience and redundancy | Multi-region deployment | Failover automatic |
| RC-3: Recovery testing | Quarterly DR drills | Team trained, procedures proven |

---

## Implementation Phases

### Phase 1: Identity Foundation (Months 1-3)

**Objectives:**
- Establish centralized identity
- Enable multi-factor authentication
- Implement privileged access management

**Deliverables:**

| Task | Deliverable | Success Criteria |
|------|-------------|-----------------|
| Entra ID tenant setup | Azure subscription linked | All users synced via Connect |
| MFA rollout | MFA enabled for all users | 100% compliance within 2 weeks |
| PIM implementation | Privileged roles managed | JIT activation working |
| SSPR deployment | Self-service reset enabled | <5% helpdesk password resets |
| Conditional Access | Baseline policies | Legacy auth blocked, high-risk blocked |

**Risks & Mitigations:**

| Risk | Impact | Mitigation |
|------|--------|-----------|
| User adoption resistance | Low productivity | Phased rollout, training, support |
| MFA bypass assumptions | Increased breach risk | Hardware key enforcement phase 2 |
| Legacy system incompatibility | Service disruption | Compatibility testing, hybrid bridge |

---

### Phase 2: Device Management (Months 3-6)

**Objectives:**
- Ensure device compliance
- Manage corporate and BYOD devices
- Enforce disk encryption

**Deliverables:**

| Task | Deliverable | Success Criteria |
|------|-------------|-----------------|
| Intune MDM | Device enrollment | 95%+ device enrollment |
| Compliance policies | Windows/macOS baselines | Compliant devices > 90% |
| BitLocker deployment | Disk encryption | 100% corporate devices encrypted |
| Hybrid AD Join | Device registration | Domain-joined + cloud-registered |
| App protection | MAM policies | Corporate apps containerized |

**Device Compliance Metrics:**
```
Baseline: All devices must meet minimum security posture
├── OS: Current + 1 previous version
├── Encryption: BitLocker/FileVault enabled
├── Firewall: Windows Firewall/macOS firewall enabled
├── Antimalware: Windows Defender enabled + updated
└── Updates: Critical patches within 7 days

Compliance Score: (Compliant Devices / Total Devices) × 100
Target: 95% by end of Phase 2
```

---

### Phase 3: Network Segmentation (Months 6-9)

**Objectives:**
- Deploy Azure Firewall
- Implement network segmentation
- Enable private endpoints

**Deliverables:**

| Task | Deliverable | Success Criteria |
|------|-------------|-----------------|
| Firewall deployment | Azure Firewall Premium | Stateful filtering, TLS inspection |
| NSG redesign | Segmented subnets | 4+ tiers (management, identity, app, data) |
| Private endpoints | Zero internet exposure | All PaaS services use private endpoints |
| Bastion deployment | Jumphost access | No public RDP/SSH IPs |
| DDoS protection | Azure DDoS Standard | Auto-mitigation of layer 3-4 attacks |

**Network Diagram (Post-Phase 3):**
```
┌─────────────────────────────────────────┐
│ Virtual Network: 10.0.0.0/16            │
├─────────────────────────────────────────┤
│ Management Subnet: 10.0.1.0/24           │
│ ├─ Azure Bastion (no public IP)         │
│ └─ NSG: Allow 443 from GatewayManager   │
├─────────────────────────────────────────┤
│ App Subnet: 10.0.10.0/24                │
│ ├─ VMs (private IPs only)              │
│ └─ NSG: Allow 443 from App Gateway,    │
│      Allow 3389 from Bastion           │
├─────────────────────────────────────────┤
│ Data Subnet: 10.0.20.0/24               │
│ ├─ SQL Database (private endpoint)     │
│ └─ NSG: Allow 1433 from app subnet     │
├─────────────────────────────────────────┤
│ Integration Subnet: 10.0.30.0/24        │
│ ├─ API Management (private)            │
│ └─ NSG: Allow 443 from App Gateway     │
└─────────────────────────────────────────┘
```

---

### Phase 4: Applications & Data Security (Months 9-12)

**Objectives:**
- Deploy WAF and API Management
- Implement data classification and encryption
- Establish continuous monitoring

**Deliverables:**

| Task | Deliverable | Success Criteria |
|------|-------------|-----------------|
| WAF deployment | Layer 7 protection | OWASP Top 10 blocked |
| API Management | Rate limiting, authentication | JWT validation enforced |
| Data classification | Purview labeling | 100% sensitive data labeled |
| Encryption | CMK deployment | All PII encrypted with CMK |
| Sentinel deployment | SIEM operational | Custom alert rules in place |
| Defender for Cloud | Continuous monitoring | Security score > 600 |

**Data Security Checklist:**
```
Before moving to production:
├─ Data Classification: Purview tags applied
├─ Encryption at Rest: CMK in Key Vault
├─ Encryption in Transit: TLS 1.2+ enforced
├─ Access Control: RBAC + PIM
├─ Audit Logging: All access logged
├─ Retention: Archive policy in place
└─ DLP Rules: Sensitive data export blocked
```

---

## Security Controls Matrix

### Control Categories & Azure Services

| NIST Category | CIS Benchmark | Control | Azure Service | Configuration |
|---------------|---------------|---------|---------------|---------------|
| Identity & Access | 1.1 | Centralized identity | Entra ID | Sync all users |
| Identity & Access | 1.2 | MFA required | Entra ID MFA | 100% enforcement |
| Identity & Access | 1.3 | Privileged access | PIM | JIT elevation |
| Identity & Access | 1.4 | Password policy | Entra ID | 16+ chars, complex |
| Network Security | 2.1 | Network segmentation | NSG + Firewall | 4+ subnets |
| Network Security | 2.2 | Public exposure | Private Endpoints | No public IPs for PaaS |
| Network Security | 2.3 | DDoS protection | DDoS Standard | Auto-mitigation |
| Data Protection | 3.1 | Encryption at rest | CMK + TDE | All data encrypted |
| Data Protection | 3.2 | Encryption in transit | TLS 1.2+ | All APIs/DB use TLS |
| Data Protection | 3.3 | Key management | Key Vault | HSM-backed, rotated |
| Application Security | 4.1 | WAF protection | Azure WAF | OWASP CRS enabled |
| Monitoring | 5.1 | Centralized logging | Sentinel + Log Analytics | 90-day searchable |
| Monitoring | 5.2 | Alert & response | Sentinel Analytics | Custom KQL rules |
| Incident Response | 6.1 | Incident handling | SOAR playbooks | Automated response |

---

## Operational Procedures

### Identity Operations

#### MFA Enrollment

**User Steps:**
1. Sign in to Azure Portal
2. Go to Security Info > Add sign-in method
3. Choose "Authenticator app" (recommended) or "SMS"
4. Download Microsoft Authenticator, scan QR code
5. Test approval notification
6. Save backup codes in secure location

**Admin Monitoring:**
```
Query: Check MFA status for all users
KQL:
SigninLogs
| where MfaDetail has "MFA not required"
| distinct UserPrincipalName, TimeGenerated
| sort by TimeGenerated desc

Alert: If > 10% users without MFA, escalate
```

#### PIM Elevation Request

**User Steps:**
1. Azure Portal > Privileged Identity Management > My roles
2. Click "Activate" next to desired role
3. Select duration (1-8 hours)
4. Enter justification ("Update firewall rules for Q2 project")
5. Submit request
6. Approver receives email with request
7. Once approved, role active for specified duration

**Approval Workflow:**
```
Elevation request
    ↓
Manager email: "User X requesting Admin role"
    ↓
Manager approves/denies
    ↓
If approved: User's role activated for 1 hour
    ↓
Audit log: Activation recorded with approver, justification
    ↓
Auto-expiration: Role deactivated after 1 hour
```

#### SSPR Recovery

**Self-Service Scenario:**
1. User forgot password
2. Login page > "Can't access your account"
3. Enter email, complete security questions
4. Reset code sent via email
5. Enter code, set new password
6. Automatic sync to on-premises AD (if hybrid)

**Verification Query:**
```
KQL: Track SSPR usage
AuditLogs
| where OperationName has "Reset password"
| summarize count() by UserPrincipalName, TimeGenerated
| where count_ > 5
| alert-team "User requesting multiple password resets"
```

---

### Device Operations

#### Device Compliance Remediation

**Non-Compliant Device Workflow:**
```
1. Intune detects non-compliance (e.g., BitLocker disabled)
   └─ User receives notification in Company Portal

2. User actions:
   ├─ Option A: Enable BitLocker (auto-remediation if enabled)
   ├─ Option B: Contact helpdesk for assistance
   └─ Option C: Device marked non-compliant (access restricted)

3. If access restricted:
   └─ User cannot access corporate email, apps, networks
      └─ Status in Intune: "Not compliant" (red)

4. Admin escalation:
   └─ If non-compliant > 7 days
   └─ Mark device as out-of-compliance
   └─ Require full Intune re-enrollment
```

**Compliance Monitoring Dashboard:**
```
Metric: Device Compliance Trend (Weekly)
Target: 95% compliant devices

Mon: 87% (4 devices non-compliant)
Tue: 89% (3 devices non-compliant)
Wed: 91% (2 devices non-compliant)
Thu: 93% (1 device non-compliant)
Fri: 95% (all compliant) ✓

Root causes tracked: OS outdated (60%), BitLocker disabled (25%), Firewall off (15%)
```

#### Bastion Access Audit

**Monthly Audit:**
```
KQL: Review all Bastion sessions for the month
AzureDiagnostics
| where ResourceType == "BASTIONHOSTS"
| where OperationName has "SessionStarted" or OperationName has "SessionEnded"
| project User, StartTime=TimeGenerated, TargetVM=ResourceId
| where TimeGenerated > ago(30d)

For each session:
├─ Verify user was authorized for VM access
├─ Check session duration (should be < 5 hours)
├─ Verify recording was enabled (Premium SKU)
└─ Look for anomalies (off-hours access, suspicious activity)

If anomaly detected: → Investigate → SOAR playbook → User disable (if needed)
```

---

### Network Operations

#### Firewall Rule Review

**Monthly Review (First Monday):**

1. **Egress Traffic Analysis:**
   ```
   Identify unnecessary outbound rules:
   ├─ Connections to deprecated services
   ├─ High-bandwidth transfers to unknown destinations
   ├─ Failed connection attempts (log count > 1000)
   └─ Recommend: Delete stale rules, update threat intel feeds
   ```

2. **Deny Log Review:**
   ```
   KQL: Find patterns in denied traffic
   AzureDiagnostics
   | where ResourceType == "AZUREFIREWALLS"
   | where Action == "Deny"
   | summarize count() by SourceIp, DestinationIp, DestinationPort
   | where count_ > 100
   └─ Determine: Legitimate blocked traffic (add rule) vs. attack patterns (monitor)
   ```

3. **TLS Inspection Certificate:**
   ```
   Monthly check:
   ├─ Certificate expiration: Renewal 30 days before expiry
   ├─ Certificate pinning: Verify clients updated
   └─ CA trust: All clients have root CA in trust store
   ```

---

### Data Security Operations

#### Encryption Key Rotation

**Quarterly Rotation Schedule:**

```
Process:
1. Key Vault: Generate new CMK version
2. Storage Account: Update encryption scope to new key
3. SQL Database: Initiate TDE key rotation (auto, 15 min)
4. VMs: Initiate disk reencryption job (off-peak hours)
5. Validation: Verify no data loss during rotation
6. Old key: Disable after successful rotation, retain 1 year

Timeline:
├─ Quarter 1 (Jan-Mar): Month 1 rotation
├─ Quarter 2 (Apr-Jun): Month 2 rotation
├─ Quarter 3 (Jul-Sep): Month 3 rotation
└─ Quarter 4 (Oct-Dec): No rotation (freeze before year-end)
```

#### Data Classification Audit

**Monthly Audit:**

```
1. Identify newly created storage accounts/databases
2. Verify Purview auto-classification applied
3. Spot-check labeled files:
   └─ "Confidential" files: Verify restricted access (not public)
   └─ "Highly Confidential": Verify CMK encryption
   └─ "PII": Verify RBAC, DLP enabled
4. Alert: Any data labeled "Public" that contains sensitive information
5. Escalate to data owner for reclassification
```

---

### Monitoring & Alerting Operations

#### Sentinel Alert Triage

**Daily Routine (08:00 AM):**

```
1. Open Sentinel > Incidents
2. Sort by Severity: Critical → High → Medium
3. For each incident:
   ├─ Click incident
   ├─ Review related alerts
   ├─ Check user/asset context (is this normal?)
   ├─ Actions:
   │  ├─ True Positive: Assign to responder, create ticket
   │  ├─ False Positive: Suppress alert, update rule
   │  └─ Information: Log and close (no action needed)
   └─ Document decision in incident comments

4. Summary: Weekly report to SOC manager
   └─ Total incidents: X
   └─ True positives: Y
   └─ False positive rate: Z%
   └─ Response time: avg T minutes
```

**Alert Rules - High Priority Examples:**

```
Rule 1: Privilege escalation (HIGH)
IF: User assigned to Global Administrator role
THEN: Alert immediately
ACTION: Incident → Verify request → Response playbook

Rule 2: Impossible travel (MEDIUM)
IF: User logs in from Country A, then Country B within 2 hours
     (distance requires flight)
THEN: Alert
ACTION: Review IP, check MFA, verify account

Rule 3: Bulk data download (HIGH)
IF: User downloads > 5GB in 1 hour
AND: Destination is external IP
THEN: Alert
ACTION: Suspend account → Investigation → Restore if legitimate
```

---

## Appendices

### A. Acronym Reference

| Acronym | Definition |
|---------|-----------|
| CA | Conditional Access |
| CMK | Customer-Managed Key |
| CSF | Cybersecurity Framework |
| DLP | Data Loss Prevention |
| EDR | Endpoint Detection & Response |
| JEA | Just-Enough-Access |
| JIT | Just-In-Time |
| MFA | Multi-Factor Authentication |
| NSG | Network Security Group |
| PII | Personally Identifiable Information |
| PIM | Privileged Identity Management |
| RBAC | Role-Based Access Control |
| SSPR | Self-Service Password Reset |
| TLS | Transport Layer Security |
| ZTNA | Zero Trust Network Access |

### B. Implementation Checklist

```
Phase 1 - Identity:
□ Entra ID tenant created
□ User sync configured (Azure AD Connect)
□ MFA enabled for all users
□ PIM configured with approval workflows
□ SSPR deployed and tested
□ Conditional Access policies baseline

Phase 2 - Devices:
□ Intune enrolled (95%+ of devices)
□ Compliance policies deployed
□ BitLocker enabled on all Windows devices
□ Hybrid AD Join configured
□ Mobile device management (iOS/Android)

Phase 3 - Network:
□ Firewall Premium deployed
□ Network segmented (4+ subnets)
□ NSGs configured and tested
□ Private Endpoints enabled for PaaS
□ Azure Bastion deployed
□ DDoS Standard enabled

Phase 4 - Applications & Data:
□ WAF deployed and tested
□ API Management configured
□ Data classified via Purview
□ CMK encryption deployed
□ Sentinel configured with custom rules
□ Defender for Cloud enabled (Standard+)
```

### C. Reference Documents

- NIST Cybersecurity Framework (CSF) v1.1
- Microsoft Azure Security Benchmark (MCSB)
- CIS Microsoft Azure Foundations Benchmark v1.4
- Zero Trust Model (NIST SP 800-207)
- Microsoft Zero Trust Deployment Guide

---

**Document Version:** 1.0
**Last Updated:** March 2026
**Next Review:** June 2026
