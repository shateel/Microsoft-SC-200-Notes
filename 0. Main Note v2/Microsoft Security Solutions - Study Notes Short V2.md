# Microsoft Security Solutions — Study Notes

*A structured overview of the Microsoft Defender / Entra / Purview security ecosystem (relevant to the SC-200 Security Operations Analyst exam).*

---

## 1. The Big Picture — How These Products Fit Together

Microsoft's security portfolio is organized around **where a threat can appear**. Each product protects one layer, and all of them feed signals into a central platform, **Microsoft Defender XDR**, for correlation and investigation.

| Layer | Product | Protects Against |
|---|---|---|
| Devices | **Microsoft Defender for Endpoint** | Endpoint/malware/ransomware attacks (EDR) |
| Email & Collaboration | **Microsoft Defender for Office 365** | Phishing, malicious links/attachments |
| On-prem Identity | **Microsoft Defender for Identity** | Active Directory attacks, lateral movement |
| Cloud Identity | **Microsoft Entra ID Protection** | Risky sign-ins, risky users, compromised credentials |
| SaaS / Cloud Apps | **Microsoft Defender for Cloud Apps** | Shadow IT, risky SaaS usage (CASB) |
| Cloud Infrastructure | **Microsoft Defender for Cloud** | Misconfigured/attacked cloud & hybrid workloads |
| IoT / OT | **Microsoft Defender for IoT** | Attacks on industrial and IoT devices |
| Insider Behavior | **Microsoft Purview Insider Risk Management** | Risky/malicious activity by people *inside* the org |
| **Correlation Layer** | **Microsoft Defender XDR** | Unifies signals from all the above into incidents |

```
 Devices        Email/M365      On-prem AD      Cloud Identity     SaaS Apps       Cloud Workloads     IoT/OT
    │               │               │                │                │                 │               │
Defender for    Defender for    Defender for     Entra ID          Defender for      Defender for    Defender
 Endpoint       Office 365       Identity        Protection        Cloud Apps           Cloud          for IoT
    │               │               │                │                │                 │               │
    └───────────────┴───────────────┴────────────────┴────────────────┴─────────────────┴───────────────┘
                                                        │
                                                        ▼
                                          MICROSOFT DEFENDER XDR
                                          (correlated incidents, hunting,
                                           automated investigation & response)
```

> **Note:** Insider risk (Purview) and cloud posture data can also surface in the Defender portal, but Purview Insider Risk Management is administered primarily through the **Microsoft Purview compliance portal**, not Defender XDR itself.

---

## 2. Microsoft Defender XDR

Microsoft Defender XDR (Extended Detection and Response) is the **unified SOC platform**, not a separate sensor. It ingests, correlates, and prioritizes signals from Defender for Endpoint, Defender for Office 365, Defender for Identity, Defender for Cloud Apps, and Entra ID Protection into a single view.

Key capabilities you should know:

- **Incidents & alerts** – related alerts across products are grouped into one incident representing a single attack.
- **Advanced Hunting (KQL)** – query raw telemetry across all connected products.
- **Automated investigation and response (AIR)** – auto-remediates common threats.
- **Attack disruption** – automatically contains fast-moving attacks (e.g., isolates a compromised account/device) even before a human responds.
- **Threat analytics** – Microsoft threat-intelligence reports mapped to your environment.
- **Custom detection rules** – KQL-based rules that generate alerts automatically.
- **Alert tuning, suppression, and correlation** – reduce noise, avoid duplicate alerts.
- **Device groups** – scope of policies/automation.

```
Defender for Endpoint ─┐
Defender for Identity ─┤
Defender for Office365 ─┼──► Defender XDR ──► Correlated Incident ──► SOC Analyst
Entra ID Protection ───┤
Defender for Cloud Apps┘
```

**Exam takeaway:** Defender XDR is the *investigation and correlation layer* sitting above the individual Defender products — think "single pane of glass," not a standalone sensor.

---

## 3. Microsoft Defender for Endpoint (MDE)

**What it is:** Microsoft's **Endpoint Detection and Response (EDR)** and endpoint protection platform (formerly *Microsoft Defender ATP*).

**Protects:** Windows clients/servers, macOS, Linux, iOS/Android (mobile), and certain network devices.

**Core job:** Prevent, detect, investigate, hunt, and respond to threats on endpoints.

**What it monitors:**
- Process creation and command-line activity
- File creation/modification
- Registry changes
- Network and DNS connections
- Logon activity
- PowerShell/script execution
- Exploitation, persistence, and lateral-movement behavior

### Example SOC scenario
```
Malicious document opened
        ↓
   WINWORD.EXE
        ↓
   powershell.exe (encoded command)
        ↓
   Downloads payload
        ↓
   Creates persistence
```
Defender for Endpoint surfaces this as a process tree. The analyst can then:
- Isolate the device
- Kill the malicious process
- Quarantine the file
- Remove persistence
- Pivot to Advanced Hunting to find the same pattern elsewhere

---

## 4. Microsoft Defender for Office 365 (MDO)

**What it is:** Cloud-based protection for Microsoft 365 **email and collaboration** services (formerly *Office 365 ATP*).

**Protects:** Exchange Online mail, Microsoft Teams, SharePoint, OneDrive, and Office documents/links shared across them.

**Threats it addresses:** phishing, spear phishing, Business Email Compromise (BEC), malware, spam, malicious attachments/URLs, impersonation, and zero-day/advanced threats.

### How a message is evaluated
```
Incoming Email
      │
      ▼
  Sender Analysis ─ URL Analysis ─ Attachment Analysis
      │
      ▼
Threat Intelligence + Machine Learning
      │
      ▼
   Risk Decision → Allow / Quarantine / Block
```

### Key technologies (exam-critical)

| Feature | Purpose |
|---|---|
| **Safe Attachments** | Detonates suspicious attachments in an isolated sandbox before delivery ("Is this file dangerous?") |
| **Safe Links** | Rewrites and checks URLs at time-of-click, even after delivery ("Is this link dangerous?") |
| **Anti-phishing / Anti-impersonation** | Detects domain/user impersonation and spoofing (e.g., `ceo@company-security.com` mimicking `company.com`) |
| **Threat Explorer** | Investigation console — who received/clicked a malicious message, was it delivered/quarantined, etc. |
| **Automated Investigation and Response (AIR)** | Automatically finds and remediates related messages sent to many mailboxes |

---

## 5. Microsoft Defender for Identity (MDI)

**What it is:** Monitors and protects **on-premises Active Directory (AD DS)** identities and domain infrastructure (formerly *Azure ATP*).

**Deployment:** A lightweight **sensor** installed on:
- Domain Controllers
- AD FS (Active Directory Federation Services) servers
- AD CS (Active Directory Certificate Services) servers, where supported

The sensor observes authentication traffic (Kerberos, NTLM, LDAP) and forwards signals to the Defender portal for behavioral analysis — it doesn't just match single malicious commands, it analyzes *patterns and relationships* over time.

### What it detects
- Credential theft
- Reconnaissance (enumerating domain admins, computers, groups)
- Lateral movement
- Privilege escalation
- Pass-the-Hash / Pass-the-Ticket
- Kerberoasting
- **Golden Ticket** attacks (forging Kerberos tickets using a stolen **KRBTGT** account hash)

### Attack chain example
```
Compromised standard user
        ↓
Credential discovery
        ↓
Privilege escalation
        ↓
Domain Admin access
        ↓
Lateral movement → Domain compromise
```

---

## 6. Microsoft Entra ID Protection

> **Important correction:** *Microsoft Entra ID* and *Microsoft Entra ID Protection* are related but distinct.
> - **Microsoft Entra ID** (formerly *Azure Active Directory*) is the overall **cloud identity and access management platform** — it manages users, groups, apps, devices, authentication, SSO, and Conditional Access.
> - **Microsoft Entra ID Protection** is the specific **risk-detection capability inside Entra ID** that identifies risky users and risky sign-ins and can trigger automated remediation (e.g., forced MFA, password reset, or blocking access) via Conditional Access.

**What Entra ID Protection looks for:**
- Risky sign-ins (impossible travel, anonymous IP addresses, atypical travel, unfamiliar sign-in properties)
- Leaked/compromised credentials found in breach data
- Malicious IP addresses
- Anomalous authentication patterns

### Simplified authentication flow (Entra ID + Conditional Access)
```
User Login
   │
   ├── Username/Password
   ├── MFA
   ├── Device compliance
   ├── Location
   ├── Sign-in / user risk (from Entra ID Protection)
   │
   ▼
Conditional Access Decision → Access Granted / Denied
```

### Defender for Identity vs. Entra ID Protection

| | **Defender for Identity** | **Entra ID Protection** |
|---|---|---|
| Scope | On-premises Active Directory | Microsoft Entra ID (cloud identity) |
| Signals | Domain Controllers, Kerberos, NTLM, LDAP | Sign-in logs, risk detections, leaked credentials |
| Typical exam keywords | Domain Admin, AD reconnaissance, lateral movement | Risky sign-in, risky user, impossible travel |

---

## 7. Microsoft Defender for Cloud Apps (MDCA)

**What it is:** A **Cloud Access Security Broker (CASB)** that provides visibility and control over SaaS/cloud application usage (formerly *Microsoft Cloud App Security – MCAS*).

**Problem it solves — Shadow IT:**
```
Employee finds an unsanctioned cloud app
        ↓
Creates an account, uploads company data
        ↓
Security team has no visibility ("Shadow IT")
```

### Core capabilities
- **Cloud Discovery** – analyzes firewall/proxy logs to reveal which cloud apps are actually being used and assesses their risk.
- **Cloud App Catalog** – risk-scores thousands of SaaS apps against security/compliance criteria.
- **Conditional Access App Control** – enforces real-time session controls (block downloads, require MFA, monitor) by integrating with Entra Conditional Access.
- **Activity/anomaly policies** – flag suspicious in-app behavior (e.g., mass downloads, impossible travel within an app).

**Exam takeaway:** *Defender for Cloud Apps = discover, monitor, and govern SaaS/cloud app usage.*

---

## 8. Microsoft Defender for Cloud

**What it is:** A cloud security posture and workload protection platform for Azure, hybrid, and multicloud environments (evolved from *Azure Security Center* + *Azure Defender*, and now often described as a **CNAPP** — Cloud-Native Application Protection Platform).

**Protects:** VMs, SQL/databases, storage, containers, Kubernetes (AKS), and servers — across Azure, AWS, and GCP (via connectors).

### Two concepts you must know

| Concept | Question it answers | Example |
|---|---|---|
| **CSPM** – Cloud Security Posture Management | "How securely is my environment *configured*?" | Storage account with public access enabled → misconfiguration flagged, secure score impacted |
| **CWPP** – Cloud Workload Protection Platform | "Is my workload actively *being attacked*?" | Suspicious process detected running on an Azure VM |

### Don't confuse these two products
```
Defender for Cloud       → Cloud infrastructure & workload security (VMs, storage, containers, posture)
Defender for Cloud Apps  → SaaS application security & usage governance (Shadow IT, CASB)
```

---

## 9. Microsoft Defender for IoT

**What it is:** Security for **IoT and Operational Technology (OT)** environments — devices that often can't run a traditional endpoint agent.

**Protects:** PLCs, industrial controllers, sensors, cameras, medical devices, building-management systems.

**Why it's different:** A corporate laptop can run an EDR agent; an industrial PLC usually cannot — so Defender for IoT relies primarily on **network-level (passive) monitoring** rather than an installed agent.

### Simplified architecture
```
OT/IoT Network (PLCs, sensors, controllers)
        │
        ▼
  Defender for IoT (network sensor)
        │
        ▼
  Device inventory, vulnerabilities, protocol analysis, threat detection
        │
        ▼
       SOC
```

### Example
```
Compromised corporate workstation
        ↓
Attempts to reach the OT network
        ↓
Communicates with a PLC
        ↓
Defender for IoT flags the unusual cross-network communication
```

---

## 10. Microsoft Purview Insider Risk Management

**What it is:** Part of the **Microsoft Purview** compliance suite; identifies and investigates **risky activity by people inside the organization** — not just malicious devices or external attackers.

**"Insider" can mean:**
- A current employee or contractor
- A privileged user
- Someone who is departing the organization
- A legitimate account that has been compromised

**Important distinction:** Insider risk does **not** always mean malicious intent — it also covers accidental data leakage, policy violations, and compromised-account behavior.

### Example: departing employee
```
Employee resigns
      ↓
Downloads large volume of files
      ↓
Copies sensitive documents
      ↓
Uploads to personal cloud storage
      ↓
Purview Insider Risk Management correlates signals → generates an alert/case
```

### Signal sources feeding risk policies
```
Files · Email · SharePoint · OneDrive · Teams · Endpoint activity · HR data (e.g., resignation)
                                   │
                                   ▼
                Purview Insider Risk Management
                                   │
                                   ▼
                    Risk score → Alert → Case → Investigation
```

**Exam takeaway:** *Purview Insider Risk Management = identify, investigate, and manage risky user behavior and data-exfiltration risk from within the organization.*

---

## 11. Quick-Reference Memorization Table

| Product | Protects | Main Focus | Former Name | Keyword |
|---|---|---|---|---|
| **Defender for Endpoint** | Devices | EDR, malware, ransomware, hunting | Microsoft Defender ATP | Devices |
| **Defender for Office 365** | Email & M365 | Phishing, malware, malicious links/files | Office 365 ATP | Email |
| **Defender for Identity** | On-prem AD | Identity attacks, Kerberos abuse, lateral movement | Azure ATP | Active Directory |
| **Entra ID Protection** | Cloud identity | Risky users/sign-ins | Azure AD Identity Protection | Risky sign-in |
| **Defender for Cloud Apps** | Cloud/SaaS apps | Shadow IT, CASB, app governance | Microsoft Cloud App Security (MCAS) | Cloud Apps |
| **Defender for Cloud** | Cloud/hybrid infrastructure | CSPM + CWPP for workloads | Azure Security Center + Azure Defender | Cloud workloads |
| **Defender for IoT** | IoT/OT devices | Network-based device/threat detection | — | IoT/OT |
| **Purview Insider Risk Management** | Users/data | Insider risk, data exfiltration | — | Insiders |
| **Defender XDR** | All of the above | Correlation, incidents, hunting, automated response | Microsoft 365 Defender | Correlation layer |

---

## 12. Key Concepts Explicitly Tied to Defender XDR (SC-200 Scope)

- Incidents & alerts
- Advanced Hunting (KQL)
- Automated investigation and response
- Attack disruption
- Threat analytics
- Custom detection rules
- Alert tuning, suppression, and correlation
- Device groups
- Hunting graphs
- Multi-stage attack investigation

**Bottom line:** Learn each Defender product's *individual scope* first, then understand that **Defender XDR is not a separate product to memorize signals for — it's the correlation and response layer that ties every other product together into one investigation experience.**
