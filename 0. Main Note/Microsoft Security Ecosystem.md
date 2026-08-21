# SC 200: Microsoft Security Operations Analyst — Revision Guide

> A condensed, exam focused revision guide built from your study material, reorganized and expanded for fast review before the **SC 200: Microsoft Security Operations Analyst Associate** exam.

## Table of Contents

1. [The Big Picture: Microsoft Security Ecosystem](#1-the-big-picture-microsoft-security-ecosystem)
2. [From Alert to Incident: The Defender XDR Correlation Model](#2-from-alert-to-incident-the-defender-xdr-correlation-model)
3. [Incident Management (Case Handling) in Defender XDR](#3-incident-management-case-handling-in-defender-xdr)
4. [Connecting to External Ticketing / ITSM](#4-connecting-to-external-ticketing--itsm)
5. [Microsoft Sentinel: The Enterprise SIEM and SOAR](#5-microsoft-sentinel-the-enterprise-siem-and-soar)
6. [Where Do SOC Analysts Work? Choosing the Right Portal](#6-where-do-soc-analysts-work-choosing-the-right-portal)
7. [Complete Microsoft Security Architecture](#7-complete-microsoft-security-architecture)
8. [Deep Dive: Microsoft Security Products](#8-deep-dive-microsoft-security-products)
9. [Threat Hunting and KQL for SC 200](#9-threat-hunting-and-kql-for-sc-200)
10. [Automation and Playbooks (SOAR)](#10-automation-and-playbooks-soar)
11. [Microsoft Security Copilot](#11-microsoft-security-copilot)
12. [Identity Protection Deep Dive (Entra ID)](#12-identity-protection-deep-dive-entra-id)
13. [Attack Lifecycle and MITRE ATT&CK Mapping](#13-attack-lifecycle-and-mitre-attck-mapping)
14. [SC 200 Last Minute Revision (Cheat Sheet)](#14-sc-200-last-minute-revision-cheat-sheet)

---

## How to Use This Guide

Read top to bottom once for the mental model, then use Section 14 as your day before the exam cheat sheet. Diagrams show data and process flow using vertical arrows; study them until you can redraw them from memory.

---

## 1. The Big Picture: Microsoft Security Ecosystem

### 1.1 Core Idea

Microsoft security is not one product. It is a chain: signals are generated at the edges of the environment (users, devices, email, identity), each protection product analyzes its own domain and raises alerts, **Microsoft Defender XDR** correlates those alerts into incidents, and **Microsoft Sentinel** adds full enterprise visibility plus SIEM and SOAR capability on top.

### 1.2 High Level Architecture

```text
Users / Devices / Email / Identity
              │
              ▼
   Microsoft Security Products
              │
   ┌──────────┼──────────────────────┐
   │          │                      │
Defender   Defender for      Defender for Identity
Endpoint   Office 365        Defender for Cloud Apps
                              Entra ID Identity Protection
              │
              ▼
        Generate Alerts
              │
              ▼
      Microsoft Defender XDR
   (Correlates alerts into Incidents)
              │
              ▼
     SOC Analyst Investigation
              │
   ┌──────────┼──────────────┐
   ▼          ▼              ▼
Automatic   Manual        Escalation
Remediation Investigation
              │
              ▼
     Microsoft Sentinel (SIEM)
              │
              ▼
   SOAR / External Ticketing / ITSM
     (ServiceNow, Jira, and similar)
```

### 1.3 Core Products at a Glance

| Product | Protects | Sends Alerts To |
|---|---|---|
| Microsoft Defender for Endpoint (MDE) | Devices (Windows, Linux, macOS, Android, iOS) | Defender XDR |
| Microsoft Defender for Office 365 (MDO) | Email and collaboration (Exchange Online, Teams, SharePoint, OneDrive) | Defender XDR |
| Microsoft Defender for Identity (MDI) | On premises Active Directory and AD FS | Defender XDR |
| Microsoft Defender for Cloud Apps (MDCA) | SaaS and cloud applications (CASB) | Defender XDR |
| Microsoft Entra ID Identity Protection | User identities and sign in risk | Defender XDR |
| Microsoft Defender for Cloud | Cloud infrastructure and workloads (Azure, AWS, GCP) | Defender XDR |
| Microsoft Intune | Device management and compliance (not primarily detection) | Feeds Conditional Access decisions |
| Microsoft Sentinel | The entire enterprise: all of the above plus firewalls, Linux, third party clouds | Is itself the top level SIEM |

> **Exam tip:** The exam frequently tests whether you know *which console* to use for a given task. As a rule of thumb: endpoint deep forensics and response actions happen in **Defender for Endpoint / Defender XDR**; cross environment correlation, long term retention, and custom detections against non Microsoft data happen in **Sentinel**.

---

## 2. From Alert to Incident: The Defender XDR Correlation Model

### 2.1 Step 1: Every Product Generates Its Own Alerts

Each Microsoft security product raises its own, independent alert.

| Product | Example Alert |
|---|---|
| Defender for Endpoint | Malware detected |
| Defender for Office 365 | Phishing email detected |
| Defender for Identity | Suspected Pass-the-Hash attack |
| Entra ID | Impossible travel sign in |

At this stage these are four **separate alerts**, with no relationship shown between them yet.

### 2.2 Step 2: Defender XDR Correlates Alerts into Incidents

Instead of showing four unrelated alerts, Defender XDR groups related alerts into a single **incident**.

```text
Alert 1        Alert 2        Alert 3        Alert 4
   │              │              │              │
   └──────────────┴──────────────┴──────────────┘
                       │
                       ▼
                   Incident
             "Identity Compromise"
        (contains Alerts 1, 2, 3, and 4)
```

This automatic correlation of alerts, entities, and evidence across multiple products is exactly why the platform is called **XDR, Extended Detection and Response**.

### 2.3 Step 3: What Is Inside an Incident

An analyst normally opens the **incident**, not the individual alerts. Everything related to the attack is already grouped inside it.

```text
Incident
   │
   ├── Alerts
   ├── Evidence
   ├── Timeline
   ├── Attack story
   └── Assets
         ├── Users
         ├── Devices
         └── Emails
```

### 2.4 Worked Example: Phishing to Identity Compromise

```text
Phishing Email
      │
      ▼
Office 365 Alert
      │
      ▼
User downloads malware
      │
      ▼
Endpoint Alert
      │
      ▼
Attacker steals credentials
      │
      ▼
Identity Alert
      │
      ▼
Impossible travel sign in
      │
      ▼
Entra Alert
```

Defender XDR combines all four alerts into one incident, for example titled **"Possible Identity Compromise"**, showing the affected user, the affected device, and a total alert count. The analyst now investigates one incident instead of four disconnected alerts.

### 2.5 Step 4: Investigation

**Timeline** reconstructs the sequence of events with timestamps, for example:

```text
09:00  Email received
   ▼
09:02  Link clicked
   ▼
09:03  Malware executed
   ▼
09:10  Credential theft
   ▼
09:15  Login from an unexpected country
```

**Evidence** collected typically includes: user, device, IP address, email, URL, file hash, and process tree.

**Attack story** is Defender XDR's automatic reconstruction of the attack chain, for example:

```text
Phishing
   │
   ▼
Credential theft
   │
   ▼
Lateral movement
   │
   ▼
Persistence
```

### 2.6 Step 5: Response Actions by Pillar

| Pillar | Example Response Action |
|---|---|
| Endpoint | Isolate device |
| Identity | Reset password, disable account |
| Email | Delete the email from all mailboxes (soft delete or hard delete) |
| Cloud Apps | Revoke sessions, revoke OAuth consent |
| User | Block sign in |

---

## 3. Incident Management (Case Handling) in Defender XDR

### 3.1 No Native Case Management System

> **Important distinction:** Microsoft Defender XDR does **not** ship a full, traditional case management system the way a dedicated tool such as TheHive does. Instead, the incident itself acts as a lightweight case record.

### 3.2 Incident Fields

```text
Incident
   │
   ├── Assign owner
   ├── Change status
   ├── Add comments
   ├── Classification
   └── Determination
```

Example incident record:

| Field | Example Value |
|---|---|
| Status | Active |
| Owner | John |
| Classification | True positive |
| Determination | Phishing |
| Comments | Malware confirmed |

### 3.3 Classification vs Determination

These two fields are commonly confused on the exam.

| Field | Purpose | Example Values |
|---|---|---|
| **Classification** | The high level verdict: was this a real threat? | True positive, False positive, Informational or expected activity |
| **Determination** | The specific reason behind that verdict | Phishing, Malware, Compromised account, Security testing, Unwanted software |

> **Exam tip:** Classification answers "was it real". Determination answers "what exactly was it". You typically set Classification first, then a matching Determination.

### 3.4 Incident Status Lifecycle

```text
New
 │
 ▼
Active
 │
 ▼
In Progress
 │
 ▼
Resolved
 │
 ▼
Closed
```

---

## 4. Connecting to External Ticketing / ITSM

### 4.1 Why Organizations Add Ticketing

Large organizations usually already run an IT ticketing platform, for example ServiceNow, Jira, or BMC Remedy. Microsoft detects; the ticketing platform tracks the operational work.

### 4.2 Workflow

```text
Defender XDR
     │
     ▼
   Incident
     │
     ▼
Sentinel Automation
     │
     ▼
Create ServiceNow Ticket
     │
     ▼
SOC works the ticket
```

### 4.3 Automation Rules vs Playbooks

This ServiceNow style integration is built with Sentinel's automation layer, so it is worth clarifying the two automation building blocks now (full detail in Section 10):

| Concept | What It Does |
|---|---|
| **Automation rule** | Lightweight, no code logic that runs when an incident is created or updated: assign owner, change status, add tags, suppress noise, or trigger a playbook. |
| **Playbook** | A Logic App workflow that performs an actual action, for example creating a ServiceNow ticket, posting to Teams, or isolating a device. Automation rules usually call playbooks as a step. |

---

## 5. Microsoft Sentinel: The Enterprise SIEM and SOAR

### 5.1 What Sentinel Is

Sentinel is Microsoft's cloud native **SIEM (Security Information and Event Management)** and **SOAR (Security Orchestration, Automation, and Response)** platform. It sees the entire organization, not only Microsoft signals.

### 5.2 Data Sources

Sentinel ingests data far beyond Microsoft products, for example:

* Defender XDR incidents
* Firewall logs (Cisco, Palo Alto, Fortinet)
* Linux syslog
* AWS CloudTrail
* Azure activity logs
* VPN logs
* Web server and database logs

### 5.3 Sentinel vs Defender XDR

| Aspect | Microsoft Defender XDR | Microsoft Sentinel |
|---|---|---|
| Scope | Microsoft security products only | Entire enterprise: Microsoft plus third party sources |
| Core strength | Deep endpoint, identity, email, and cloud app detection and automatic response | Broad correlation, long term retention, custom analytics, and cross source hunting |
| Response depth | Very deep: kill process, quarantine file, isolate device, collect investigation package | Coordinates response through automation but relies on connected products for deep endpoint action |
| Typical primary user | Small, Microsoft only organizations | Large enterprises with mixed vendor environments |
| Underlying technology | Correlation engine over Microsoft telemetry | Log Analytics workspace plus KQL, now extendable with the Sentinel data lake |

### 5.4 Real Attack Example: What Each Platform Sees

Attacker path: VPN, then Cisco firewall, then an exploited Apache server, then a Linux shell, then stolen AD credentials, then a compromised Windows PC.

```text
What Defender XDR sees (Microsoft telemetry only)
      Credential theft
            │
            ▼
   Defender for Identity alert
            │
            ▼
      Windows malware
            │
            ▼
       Endpoint alert
```

Defender XDR has no visibility into the Cisco firewall logs, Apache access logs, Linux SSH logs, or VPN authentication logs.

```text
What Sentinel sees (every connected source)
   VPN login
      │
      ▼
   Cisco firewall
      │
      ▼
   Apache logs
      │
      ▼
   Linux logs
      │
      ▼
   Active Directory
      │
      ▼
   Defender XDR
      │
      ▼
   Incident
```

### 5.5 Why You Still Need Defender XDR

Sentinel cannot perform deep, real time endpoint forensics on its own. When malware executes, Defender for Endpoint immediately knows the process tree, registry changes, file hash, memory behavior, network connections, and device timeline, and it can automatically kill the process, quarantine the file, isolate the device, and collect an investigation package. Sentinel coordinates and correlates; Defender XDR performs the deep endpoint level detection and response.

### 5.6 Detection to Incident Flow Example

```text
50,000 Firewall Logs
        │
        ▼
   Analytics Rule
        │
        ▼
  Detect Port Scan
        │
        ▼
   Create Incident
```

### 5.7 Core Sentinel Building Blocks

| Component | What It Is | Exam Relevance |
|---|---|---|
| **Log Analytics workspace** | The Azure resource that stores ingested log data and runs KQL queries | Sentinel is built on top of one or more workspaces |
| **Data connectors** | Prebuilt integrations that bring data in, for example Windows Security Events via AMA, Syslog and Common Event Format (CEF) via AMA, Azure Policy and diagnostic settings for Azure activity | Know AMA (Azure Monitor Agent) is the current standard ingestion agent, replacing the legacy Log Analytics agent |
| **Data collection rules (DCR)** | Define exactly what data an AMA connector collects and how it is transformed before ingestion | Central to configuring Windows Security Events and Syslog and CEF connectors |
| **Analytics rules** | The detection logic that turns raw logs into alerts and incidents | Types: Scheduled, Near real time (NRT), Microsoft security (mirrors Defender product alerts), Fusion (multistage attack detection using machine learning), and Machine learning behavior analytics |
| **Automation rules** | No code orchestration triggered on incident create or update | Assign owners, run playbooks, suppress or close false positives |
| **Playbooks** | Logic App based workflows for actual response actions | Send notifications, enrich alerts, isolate devices, open tickets |
| **Watchlists** | Custom reference lists (VIP users, known good IPs, terminated employees) used inside KQL queries and analytics rules | Speeds up allow list and deny list style detections |
| **Workbooks** | Interactive dashboards and reports built on KQL | Used for monitoring trends, not for generating incidents |
| **UEBA (User and Entity Behavior Analytics)** | Baselines normal behavior for users, devices, and IP addresses and flags anomalies | Backed by the `BehaviorAnalytics` table |
| **Threat intelligence** | Indicators of compromise (IOCs) ingested from feeds (TAXII, upload, or the Microsoft Defender Threat Intelligence connector) | Feeds threat intelligence analytics rules and hunting queries |
| **Hunting and notebooks** | Proactive, hypothesis driven KQL queries plus Jupyter notebook based investigation | Hunting does not wait for an analytics rule to fire |
| **Content hub and solutions** | Packaged bundles of connectors, analytics rules, workbooks, and playbooks for a given product or vendor | Fastest way to onboard a new data source with matching detections |
| **MITRE ATT&CK coverage** | Sentinel maps analytics rules to MITRE ATT&CK tactics and techniques | Used to visualize detection coverage gaps |

> **2026 update, exam relevant:** Sentinel now offers three data tiers. The **Analytics tier** is the classic, high performance tier used for real time alerting, hunting, and workbooks. The **Data lake tier** is a low cost tier for long term retention (up to 12 years) that supports KQL jobs and Python or notebook based analysis, but is not directly available for real time alerting. The **XDR tier** holds Defender XDR advanced hunting tables at a default 30 day retention. Analytics tier data is mirrored into the data lake by default.
>
> **Sentinel graph**, also introduced in 2026, is a graph based analytics layer over the data lake. It powers **blast radius analysis** (visualizing which critical assets an attacker could reach from a compromised entity) and **graph based hunting** (visually traversing relationships between users, devices, and other entities). It is closely tied to embedded Security Copilot experiences.

---

## 6. Where Do SOC Analysts Work? Choosing the Right Portal

### 6.1 Small Microsoft Only Organization

If the environment is entirely Microsoft (Windows, Microsoft 365, Entra ID, Defender), the analyst usually works directly inside **Microsoft Defender XDR**, because nearly all relevant security events already land there.

### 6.2 Large Enterprise

If the environment is mixed (Windows, Linux, AWS, Azure, Cisco, Palo Alto, Oracle, SAP, Microsoft 365, Defender), the analyst usually works primarily inside **Microsoft Sentinel**, because Sentinel has visibility across the entire environment. Defender XDR is still opened whenever deep endpoint detail is needed.

### 6.3 Real Enterprise Workflow

```text
Windows PC
    │
    ▼
Defender for Endpoint
    │
    ▼
Defender XDR
    │
    ▼
Microsoft Sentinel  ◄────── Linux logs, Cisco firewall,
    │                       VPN logs, AWS logs, Azure logs,
    │                       web server logs, database logs
    ▼
SOC analyst starts here
    │
    ▼
Incident involves a Windows endpoint?
    │
    ▼
Drill down into Defender XDR
    │
    ▼
Investigate process tree, isolate device,
perform endpoint response actions
```

> **Key exam sentence to remember:** Defender XDR tells you what happened inside the Microsoft security ecosystem, while Sentinel tells you what happened across the entire enterprise.

---

## 7. Complete Microsoft Security Architecture

```text
                        USERS
                          │
          ┌───────────────┼───────────────┐
          │               │               │
          ▼               ▼               ▼
     Endpoints        Identities        Emails
          │               │               │
          ▼               ▼               ▼
   Defender for      Defender for    Defender for
     Endpoint          Identity       Office 365
          │               │               │
          └───────────────┼───────────────┘
                          │
                          ▼
                  Microsoft Defender XDR
             (Correlates Microsoft alerts)
                          │
                          ▼
                  Microsoft Sentinel
             (Enterprise SIEM and SOAR)
                          ▲
                          │
          ┌───────────────┼───────────────────┐
          │               │                   │
          ▼               ▼                   ▼
     Azure logs      Firewall logs        Linux logs
     AWS logs         VPN logs             Syslog
     Cisco            Palo Alto          Other sources
```

---

## 8. Deep Dive: Microsoft Security Products

Each product below follows the same pattern: what it protects, what telemetry it collects, what it detects, and where its alerts flow.

### 8.1 Microsoft Defender for Endpoint (MDE)

| Category | Details |
|---|---|
| Protects | Devices: Windows, Linux, macOS, Android, iOS |
| Collects | Running processes, command lines, PowerShell activity, registry changes, file creation, network connections, USB activity, drivers, services, scheduled tasks |
| Detects | Malware, ransomware, exploits, living off the land attacks, credential dumping, lateral movement |
| Sends alerts to | Defender XDR |

Key capabilities to remember: **EDR** (Endpoint Detection and Response), built in **Antivirus**, **TVM** (Threat and Vulnerability Management, now often called Microsoft Defender Vulnerability Management), **AIR** (Automated Investigation and Response), **Device timeline**, and **Live Response** (a remote, real time investigation shell on the device).

### 8.2 Microsoft Defender for Office 365 (MDO)

| Category | Details |
|---|---|
| Protects | Email and collaboration: Exchange Online, Outlook, Teams, SharePoint, OneDrive |
| Collects | Email headers, attachments, URLs, sender reputation, mail flow, user clicks, Safe Links activity |
| Detects | Phishing, malware attachments, business email compromise, spoofing, malicious URLs |
| Sends alerts to | Defender XDR |

Key features: **Safe Links** (time of click URL rewriting and checking), **Safe Attachments** (detonation sandbox for attachments), **Anti-phishing policies**, **Threat Explorer** (hunt and investigate email threats), and **Campaign views** (groups related phishing waves together).

### 8.3 Microsoft Defender for Identity (MDI)

| Category | Details |
|---|---|
| Protects | On premises Active Directory |
| Sensor installed on | Domain controllers, AD FS servers, and AD CS (certificate services) servers |
| Collects | Kerberos, NTLM, LDAP, authentication events, domain activity, network traffic |
| Detects | Pass-the-Hash, Pass-the-Ticket, Golden Ticket, DCSync, lateral movement, privilege escalation |
| Sends alerts to | Defender XDR |

> **Exam tip:** Defender for Identity is the product to remember whenever a question involves on premises Active Directory attacks such as DCSync (a technique for replicating password hashes from a domain controller) or Golden Ticket forgery (forging a Kerberos ticket granting ticket).

### 8.4 Microsoft Defender for Cloud Apps (MDCA)

| Category | Details |
|---|---|
| Protects | Cloud applications, for example Microsoft 365, Salesforce, Box, Dropbox, Google Workspace, ServiceNow |
| Collects | User activity, OAuth permissions, file sharing events, cloud sessions, API activity |
| Detects | Impossible cloud behavior, OAuth abuse, data exfiltration, shadow IT, insider threats |
| Sends alerts to | Defender XDR |

This is Microsoft's **CASB** (Cloud Access Security Broker). It also provides **Cloud Discovery** (identifies unsanctioned Shadow IT app use from network and proxy logs), **Conditional Access App Control** (real time session control, for example block download), and **App governance** (OAuth app risk and permission management).

### 8.5 Microsoft Defender for Cloud

| Category | Details |
|---|---|
| Protects | Cloud infrastructure: Azure, AWS, Google Cloud |
| Typical resources covered | Virtual machines, containers, Kubernetes, storage, SQL, networking |
| Collects | Azure activity, VM security signals, configuration data, vulnerability data, recommendations |
| Detects | Misconfigurations, cloud attacks, exposed services, vulnerabilities |
| Sends alerts to | Defender XDR |

Defender for Cloud combines two roles worth separating in your head:

| Capability | Purpose |
|---|---|
| **CSPM (Cloud Security Posture Management)** | Continuous configuration and compliance scoring, secure score, recommendations |
| **CWP (Cloud Workload Protection)**, the Defender plans | Active threat detection for specific resource types: servers, containers, storage, SQL, Key Vault, and more |

### 8.6 Microsoft Entra ID Identity Protection

| Category | Details |
|---|---|
| Protects | User identities |
| Collects | Login locations, devices, browser information, IP addresses, MFA status, risk detections |
| Detects | Impossible travel, anonymous IP use, password spray, leaked credentials |
| Sends alerts to | Defender XDR |

See Section 12 for a full breakdown of risk levels and Conditional Access integration.

### 8.7 Microsoft Intune

> **Important distinction:** Intune is **not** primarily a detection product. It is a **device management platform**.

Intune manages device enrollment, compliance policies, device configuration, and security baselines. Its exam relevant power comes from its integration with Defender for Endpoint and Conditional Access:

```text
Device becomes infected
        │
        ▼
Defender for Endpoint
        │
        ▼
Device risk level = High
        │
        ▼
Intune marks device as Not compliant
        │
        ▼
Conditional Access blocks access
```

---

## 9. Threat Hunting and KQL for SC 200

### 9.1 KQL Quick Syntax Reference

| Operator | Purpose | Example |
|---|---|---|
| `where` | Filter rows | `where EventID == 4625` |
| `project` | Choose and rename columns | `project TimeGenerated, Account, IPAddress` |
| `extend` | Add a computed column | `extend HourOfDay = hourofday(TimeGenerated)` |
| `summarize` | Aggregate rows | `summarize Count = count() by Account` |
| `join` | Combine two tables on a key | `join kind=inner DeviceInfo on DeviceId` |
| `union` | Stack rows from multiple tables | `union SecurityAlert, SecurityIncident` |
| `sort by` / `order by` | Order the result set | `sort by TimeGenerated desc` |
| `take` / `limit` | Return a fixed number of rows | `take 50` |
| `distinct` | Unique values only | `distinct Account` |
| `bin()` | Bucket a value, commonly time | `bin(TimeGenerated, 1h)` |
| `ago()` | Relative time filter | `where TimeGenerated > ago(7d)` |
| `let` | Define a reusable variable or subquery | `let SuspiciousIPs = datatable(...)` |
| `mv-expand` | Expand a dynamic array into rows | `mv-expand ParsedFields` |

### 9.2 Defender XDR Advanced Hunting Tables

| Table | Contains |
|---|---|
| `DeviceInfo`, `DeviceNetworkInfo` | Device inventory and network configuration |
| `DeviceProcessEvents` | Process creation events |
| `DeviceNetworkEvents` | Network connections initiated from devices |
| `DeviceFileEvents` | File creation, modification, and deletion |
| `DeviceRegistryEvents` | Registry key changes |
| `DeviceLogonEvents` | Local and remote logon activity on devices |
| `EmailEvents`, `EmailAttachmentInfo`, `EmailUrlInfo` | Email metadata, attachments, and URLs |
| `IdentityLogonEvents`, `IdentityQueryEvents`, `IdentityDirectoryEvents` | Active Directory and Entra ID identity activity |
| `CloudAppEvents` | Cloud application and SaaS activity |
| `AlertInfo`, `AlertEvidence` | Alert metadata and the entities tied to each alert |

### 9.3 Sentinel Specific Tables

| Table | Contains |
|---|---|
| `SecurityAlert` | Alerts from connected security products |
| `SecurityIncident` | Sentinel incidents |
| `SigninLogs`, `AuditLogs` | Entra ID sign in and audit activity |
| `OfficeActivity` | Microsoft 365 audit activity |
| `AzureActivity` | Azure control plane operations |
| `CommonSecurityLog` | CEF formatted logs (firewalls and network devices) |
| `Syslog` | Linux and Unix system logs |
| `ThreatIntelligenceIndicator` | Ingested threat intelligence indicators |
| `BehaviorAnalytics` | UEBA baselines and anomaly scoring |

### 9.4 Example Queries

Detect a possible password spray pattern (many failed sign ins from one source in a short window):

```kql
SigninLogs
| where ResultType != 0
| summarize FailedCount = count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 1h)
| where FailedCount > 10
```

Find suspicious process activity spawned from Office applications, a common initial access pattern:

```kql
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "powerpnt.exe")
| where FileName in~ ("powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

Correlate a malicious email attachment with later file activity on a device (cross table join, a common exam hunting pattern):

```kql
EmailAttachmentInfo
| where FileType == "exe"
| join DeviceFileEvents on SHA256
| project Timestamp, RecipientEmailAddress, FileName, DeviceName
```

### 9.5 Hunting Workflow

```text
Hypothesis
   │
   ▼
Write KQL query
   │
   ▼
Run against Sentinel or Defender XDR data
   │
   ▼
Review results
   │
   ▼
Save as a hunting bookmark
   │
   ▼
Promote to a custom detection or analytics rule
```

---

## 10. Automation and Playbooks (SOAR)

| Concept | Automation Rule | Playbook |
|---|---|---|
| Built on | Sentinel's native rule engine | Azure Logic Apps |
| Trigger | Incident created or updated | Called by an automation rule, an analytics rule, or run manually |
| Typical actions | Assign owner, change status, add tags, suppress or close, run a playbook | Send an email or Teams message, enrich with threat intelligence, isolate a device, create a ticket in ServiceNow or Jira |
| Coding required | No | Low code, built visually, can include custom logic |
| Order of execution | Runs first when triggered, orchestrates what happens next | Executes as one step inside an automation rule, or is called directly |

```text
Incident created or updated
        │
        ▼
   Automation rule fires
        │
   ┌────┴────┐
   ▼         ▼
Direct     Calls a
actions    Playbook
(assign,    │
 tag,       ▼
 close)   Logic App runs
          (notify, enrich,
           isolate, ticket)
```

> **Exam tip:** If a question asks what to build to change an incident's owner or status automatically, the answer is an **automation rule**. If a question asks what to build to actually take an external action (send an email, call an API, isolate a device, open a ticket), the answer is a **playbook**.

---

## 11. Microsoft Security Copilot

Security Copilot is Microsoft's generative AI layer for security operations. It appears in two forms:

| Form | Description |
|---|---|
| **Embedded experiences** | Copilot features built directly into Defender XDR, Sentinel, Intune, and Entra, for example incident summarization, guided response, and script or file analysis |
| **Standalone experience** | A dedicated Security Copilot workspace where an analyst runs natural language prompts and multi step **promptbooks** across connected security data |

Key exam relevant capabilities:

* **Incident summarization**: turns a complex incident's alerts, entities, and timeline into a plain language summary.
* **KQL generation**: converts a natural language question into a runnable KQL query for hunting.
* **Guided response**: recommends and can help execute remediation steps for a given incident.
* **Threat intelligence lookups**: enriches indicators (files, IPs, domains) with reputation and context.
* **Promptbooks**: reusable, multi step prompt sequences for recurring investigation tasks.

```text
Analyst opens incident
        │
        ▼
Asks Security Copilot to summarize
        │
        ▼
Copilot reads alerts, entities, evidence
        │
        ▼
Returns plain language summary
        │
        ▼
Analyst asks for a KQL hunting query
        │
        ▼
Copilot generates and can run the query
        │
        ▼
Analyst reviews and takes response action
```

---

## 12. Identity Protection Deep Dive (Entra ID)

### 12.1 Risk Types

| Risk Type | Meaning |
|---|---|
| **User risk** | The likelihood that a given identity itself is compromised, based on patterns over time (for example leaked credentials appearing on the dark web) |
| **Sign-in risk** | The likelihood that a specific sign in attempt is not the legitimate user (for example impossible travel, anonymous IP, unfamiliar sign in properties) |

### 12.2 Risk Levels

Both risk types are scored as **Low**, **Medium**, or **High**.

### 12.3 Common Risk Detections

* Impossible travel (a sign in from two distant locations in an implausibly short time)
* Anonymous IP address (proxy, VPN, or Tor exit node)
* Password spray (many accounts, low volume per account, guessed passwords)
* Leaked credentials (username and password found in a breach dataset)

### 12.4 Conditional Access Integration

Conditional Access policies consume signals from Identity Protection, Intune device compliance, and location or application context to make real time access decisions.

```text
Sign in attempt
      │
      ▼
Evaluate Conditional Access conditions
 (user or group, app, location, device
  compliance, sign in risk, user risk)
      │
      ▼
   Decision
      │
   ┌──┴──────────────┐
   ▼                 ▼
Grant access     Block, or require
                 MFA, or require
                 password change
```

### 12.5 Workload Identities

**Workload identities** are non human identities, for example applications, service principals, and managed identities. Entra Workload ID risk detection and Conditional Access for workload identities protect these accounts from credential leakage and unusual usage patterns, separately from ordinary user identity protection.

---

## 13. Attack Lifecycle and MITRE ATT&CK Mapping

```text
Initial access
     │
     ▼
Execution
     │
     ▼
Identity compromise / Credential access
     │
     ▼
Lateral movement
     │
     ▼
Persistence
     │
     ▼
Detection
     │
     ▼
Investigation
     │
     ▼
Response
     │
     ▼
Remediation
     │
     ▼
Recovery
```

| Lifecycle Stage | Related MITRE ATT&CK Tactic | Example Technique |
|---|---|---|
| Initial access | Initial Access | Phishing |
| Execution | Execution | Malicious macro or script execution |
| Credential access | Credential Access | Pass-the-Hash, DCSync |
| Lateral movement | Lateral Movement | Remote services, pass the ticket |
| Persistence | Persistence | Scheduled task, new account creation |
| Privilege escalation | Privilege Escalation | Token manipulation |
| Exfiltration | Exfiltration | Data transfer to a cloud account |

> **Exam tip:** Sentinel analytics rules and hunting queries are frequently mapped to MITRE ATT&CK tactics and techniques. Expect questions about analyzing attack vector coverage using the MITRE ATT&CK matrix inside Sentinel, and about recognizing which tactic a described behavior belongs to.

---

## 14. SC 200 Last Minute Revision (Cheat Sheet)

### 14.1 The One Sentence Version

> Products detect. Defender XDR correlates Microsoft signals into incidents and performs deep endpoint response. Sentinel ingests everything, everywhere, and adds SIEM analytics plus SOAR automation on top.

### 14.2 Product Cheat Table

| Product | One Line Purpose |
|---|---|
| Defender for Endpoint | Device level EDR: malware, ransomware, living off the land |
| Defender for Office 365 | Email and collaboration protection: phishing, malware, BEC |
| Defender for Identity | On premises AD protection: Pass-the-Hash, DCSync, Golden Ticket |
| Defender for Cloud Apps | CASB: OAuth abuse, shadow IT, exfiltration |
| Defender for Cloud | Cloud posture (CSPM) and workload protection (CWP) |
| Entra ID Identity Protection | User and sign in risk scoring |
| Intune | Device management and compliance, feeds Conditional Access |
| Defender XDR | Correlates all of the above into incidents |
| Sentinel | Enterprise SIEM and SOAR across every source, Microsoft or not |

### 14.3 Frequently Confused Concepts

| Term A | Term B | The Difference |
|---|---|---|
| Alert | Incident | Alert is one product's detection. Incident is Defender XDR's correlated group of alerts, entities, and evidence. |
| Classification | Determination | Classification is the verdict (true positive or false positive). Determination is the specific reason (phishing, malware, and so on). |
| Automation rule | Playbook | Automation rule orchestrates and decides what happens on an incident. Playbook (Logic App) performs the actual action. |
| Defender for Cloud | Defender for Cloud Apps | Defender for Cloud protects infrastructure and workloads (VMs, containers, SQL). Defender for Cloud Apps is a CASB protecting SaaS applications. |
| User risk | Sign-in risk | User risk is the ongoing likelihood an identity is compromised. Sign-in risk is the risk of one specific sign in event. |
| Analytics tier | Data lake tier | Analytics tier is real time, used for alerting and hunting. Data lake tier is low cost, long term (up to 12 years), not directly usable for real time alerts. |
| Watchlist | Workbook | Watchlist is reference data used inside detections and queries. Workbook is a dashboard for visualization and reporting. |
| TVM / Defender Vulnerability Management | EDR | TVM finds and prioritizes vulnerabilities and misconfigurations. EDR detects and responds to active threats on the endpoint. |

### 14.4 Sentinel Analytics Rule Types

| Type | When It Runs |
|---|---|
| Scheduled | On a defined interval (for example every 5 minutes) against a KQL query |
| Near real time (NRT) | Near instantly, for a narrow set of supported, low latency scenarios |
| Microsoft security | Mirrors alerts already generated by a connected Microsoft product |
| Fusion | Machine learning based, detects multistage attacks by correlating low fidelity signals |
| Machine learning behavior analytics | Built in ML models for specific known scenarios (for example anomalous sign ins) |

### 14.5 Core KQL Syntax to Have Memorized

```kql
TableName
| where TimeGenerated > ago(24h)
| where ColumnName == "Value"
| summarize Count = count() by ColumnName2
| sort by Count desc
| take 20
```

* `where` filters, `summarize` aggregates, `project` selects columns, `join` merges tables, `ago()` sets a relative time window.

### 14.6 Incident Lifecycle Recap

```text
New → Active → In Progress → Resolved → Closed
```

### 14.7 Response Action Quick Reference

| Compromise Type | Typical Response |
|---|---|
| Malicious device | Isolate device, collect investigation package, kill process |
| Compromised identity | Reset password, revoke sessions, require MFA, block sign in |
| Malicious email | Delete from all mailboxes (soft or hard delete), block sender |
| Risky cloud app session | Revoke OAuth consent, revoke session, block app |

### 14.8 Portal Decision Rule

```text
Is the environment entirely Microsoft?
        │
   ┌────┴────┐
  Yes        No
   │          │
   ▼          ▼
Work in    Work in Sentinel,
Defender   drill into Defender
   XDR      XDR for endpoint depth
```

### 14.9 Final Day Before the Exam Checklist

* Can you draw the alert to incident to Sentinel pipeline from memory.
* Can you state what each Defender product protects, collects, detects, and where it sends alerts.
* Can you explain Classification vs Determination, and Automation rule vs Playbook, without hesitating.
* Can you name the three Sentinel data tiers and why each exists.
* Can you write a basic KQL query using `where`, `summarize`, and `join`.
* Have you reviewed Security Copilot's role in incident summarization, KQL generation, and guided response.

> Good luck. Review this cheat sheet one final time right before you sit the exam.
