# Microsoft Security Solutions — Study Notes

*Covers Microsoft Defender XDR and its component products, Microsoft Entra ID Protection, and Microsoft Purview Insider Risk Management. Written for exam prep (e.g., SC-200) and general understanding.*

---

## The Big Picture

Microsoft's security portfolio protects six main areas of an organization. Each area has a dedicated product, and all of them feed their signals into one correlation layer — **Microsoft Defender XDR**.

| Area | Product | Protects Against |
|---|---|---|
| Devices | **Defender for Endpoint** | Malware, ransomware, endpoint attacks |
| Email & Microsoft 365 apps | **Defender for Office 365** | Phishing, malicious links/attachments |
| On-premises Active Directory | **Defender for Identity** | Credential theft, lateral movement, domain attacks |
| Cloud/SaaS applications | **Defender for Cloud Apps** | Shadow IT, risky SaaS usage, data exposure |
| Cloud infrastructure & workloads | **Defender for Cloud** | Misconfigurations, workload attacks |
| IoT / Operational Technology | **Defender for IoT** | Attacks on industrial and unmanaged devices |
| Cloud identity (Microsoft Entra ID) | **Entra ID Protection** | Risky sign-ins, risky users, leaked credentials |
| User behavior & data | **Purview Insider Risk Management** | Data leakage/exfiltration by insiders |

> **Note:** The original notes grouped "Microsoft Entra ID" (the identity *platform*) and "Entra ID Protection" (the risk-*detection* capability built on top of it) together. They are related but distinct — see the dedicated section below for the difference.

---

## 1. Microsoft Defender XDR

**Microsoft Defender XDR** (formerly Microsoft 365 Defender) is not a separate detection engine for a specific asset type — it is the **unified extended detection and response (XDR) layer** that sits above the individual Defender products and correlates their signals.

Rather than an analyst checking five different consoles, Defender XDR combines everything into a **single incident** in one portal: **security.microsoft.com**.

**What it pulls signals from:**
- Defender for Endpoint (devices)
- Defender for Office 365 (email/collaboration)
- Defender for Identity (on-prem AD)
- Defender for Cloud Apps (SaaS)
- Microsoft Entra ID Protection (cloud identity)
- Microsoft Defender for Cloud (workloads, when connected)

**Core capabilities:**
- **Incidents** — automatically groups related alerts from multiple products into one story of an attack
- **Alerts** — individual detections from each underlying product
- **Advanced Hunting (KQL)** — write custom queries across up to 30 days of raw signal data from connected products
- **Automated Investigation and Response (AIR)** — automatically investigates and remediates certain alert types
- **Attack disruption** — automatically contains an active attack in progress (e.g., isolating a compromised device or disabling a compromised account) while the SOC investigates
- **Threat analytics** — Microsoft's threat-intelligence reports mapped to your environment
- **Custom detection rules** — build your own detection logic using KQL
- **Device groups, alert tuning/suppression, and correlation** — manage noise and scope

**Mental model:**
```
┌─────────────────────────────────────────┐
│     Microsoft Defender for Endpoint     │
│    Microsoft Defender for Office 365    │
│     Microsoft Defender for Identity     │
│    Microsoft Defender for Cloud Apps    │
│      Microsoft Defender for Cloud       │
│       Microsoft Defender for IoT        │
│       Microsoft Entra ID Protection     │
│ Microsoft Purview Insider Risk Mgmt     │
└────────────────────┬────────────────────┘
                     │
                     ▼
           Microsoft Defender XDR
                     │
                     ▼
            Correlated Incident
                     │
                     ▼
                SOC Analyst
```
**Exam takeaway:** If a question describes cross-product correlation, a unified incident, or hunting across multiple signal sources, think **Defender XDR** — not one individual product.

---

## 2. Microsoft Defender for Endpoint

**Microsoft Defender for Endpoint (MDE)** is Microsoft's **Endpoint Detection and Response (EDR)** and endpoint protection platform.

**Supported platforms:** Windows clients and servers, macOS, Linux, iOS, Android, and (through network discovery) unmanaged/BYOD devices.

**Primary job:** Prevent, detect, investigate, and respond to threats on endpoints.

**What it monitors:**
- Process creation and command-line activity
- File creation/modification
- Registry changes
- Network and DNS activity
- Logon activity
- PowerShell and script execution
- Malware behavior and exploitation attempts
- Persistence mechanisms and lateral movement

**Example SOC scenario:**

```
Malicious attachment opened
        │
        ▼
   WINWORD.EXE
        │
        ▼
   powershell.exe (encoded command)
        │
        ▼
   Downloads payload → creates persistence
```

Defender for Endpoint surfaces this as a **process tree**, letting the analyst see exactly how the attack unfolded. Response actions include isolating the device, stopping the malicious process, quarantining files, collecting a forensic package, and hunting for the same behavior across other devices with **Advanced Hunting**.

---

## 3. Microsoft Defender for Office 365

**Microsoft Defender for Office 365 (MDO)** protects Microsoft 365 email and collaboration surfaces — **email, Teams, SharePoint, and OneDrive** — from phishing, malware, and malicious links.

**Threats it addresses:**

| Threat | Example |
|---|---|
| Phishing | Fake Microsoft 365 login page |
| Spear phishing | Targeted email to a CFO |
| Business Email Compromise (BEC) | Attacker impersonates the CEO |
| Malware | Malicious executable or document |
| Malicious attachments | Weaponized Word/PDF file |
| Malicious URLs | Link to a credential-harvesting site |
| Impersonation / spoofing | Look-alike sender domain |
| Spam | Unwanted bulk mail |

**Key technologies:**

- **Safe Attachments** — detonates suspicious attachments in an isolated sandbox before delivery to determine whether they're malicious.
- **Safe Links** — rewrites and re-checks URLs at time-of-click, even after delivery, so a link that was safe when sent but was later weaponized is still blocked.
- **Anti-phishing policies** — detect user and domain impersonation, spoofing, and suspicious sender behavior (e.g., mailbox intelligence).
- **Threat Explorer** (and Real-time detections) — the investigation/search console for email-based incidents: who received a message, who clicked a link, whether it was quarantined, and who else was targeted.
- **Automated Investigation and Response (AIR)** — automatically investigates a reported phishing email, finds every other mailbox that received the same message, and can remediate all of them at once.
- **Zero-hour Auto Purge (ZAP)** *(added for completeness — not in the original notes)* — retroactively removes a message from mailboxes if it's found to be malicious after delivery.

**Simplified flow:**
```
Incoming email/link/file
        │
        ▼
 Sender analysis | URL analysis | Attachment analysis
        │
        ▼
 Threat Intelligence + Machine Learning
        │
        ▼
   Allow · Quarantine · Block
```

---

## 4. Microsoft Defender for Identity

**Microsoft Defender for Identity (MDI)** monitors and protects your **on-premises Active Directory (AD DS)** environment — domain controllers, AD FS, and AD CS servers.

**How it's deployed:** A lightweight **sensor** is installed directly on domain controllers (and AD FS/AD CS servers, where supported). The sensor observes authentication traffic and directory activity and sends signals to the Microsoft Defender portal for analysis.

**What it detects:**
- Credential theft (e.g., **Pass-the-Hash**, **Pass-the-Ticket**)
- **Kerberoasting**
- Reconnaissance (enumerating domain admins, computers, groups, privileged accounts)
- Lateral movement
- Privilege escalation
- **Golden Ticket** attacks — forging Kerberos tickets after compromising the **KRBTGT** account hash

**Example attack chain:**
```
Compromised user account
        │
        ▼
Credential discovery → Privilege escalation → Domain Admin
        │
        ▼
Lateral movement → Full domain compromise
```

MDI doesn't just match a single malicious command — it analyzes **behavior and relationships** across the identity environment over time, which is what makes identity-based detection effective against attacks that look like normal admin activity on the surface.

---

## 5. Microsoft Defender for Cloud Apps

**Microsoft Defender for Cloud Apps (MDCA)** is Microsoft's **Cloud Access Security Broker (CASB)**. It provides visibility and control over **SaaS and cloud application usage** — Microsoft 365, Salesforce, Google Workspace, Dropbox, Box, and thousands of other cataloged apps.

**The problem it solves — Shadow IT:**
```
Employee finds an unsanctioned cloud service
        │
        ▼
Creates an account and uploads company data
        │
        ▼
Security team has no visibility
```

**Key capabilities:**
- **Cloud Discovery** — analyzes network/firewall logs to identify which cloud apps are actually being used in the organization, then risk-scores them against the **Cloud App Catalog**.
- **Conditional Access App Control** — integrates with Microsoft Entra Conditional Access to apply real-time session controls (e.g., block downloads, require read-only access) inside sanctioned cloud apps.
- **Information Protection** *(added for completeness)* — applies and enforces sensitivity labels on files stored in connected cloud apps.
- **Activity policies and anomaly detection** *(added for completeness)* — flag risky behavior such as impossible travel, mass downloads, or unusual file-sharing activity within a SaaS app.

**Exam takeaway:** *Defender for Cloud Apps = discover, monitor, and govern SaaS/cloud application usage.*

---

## 6. Microsoft Defender for Cloud

**Microsoft Defender for Cloud** protects **cloud infrastructure and workloads** — VMs, databases, storage, containers, Kubernetes — across Azure, and (via connectors) AWS, GCP, and on-premises/hybrid resources.

**Two concepts to know cold:**

| Concept | Full name | Question it answers |
|---|---|---|
| **CSPM** | Cloud Security Posture Management | *"How securely is my cloud environment configured?"* |
| **CWPP** | Cloud Workload Protection Platform | *"Is my cloud workload actively being attacked?"* |

**CSPM example:**
```
Storage Account
 ├── Public access enabled   ❌
 ├── Encryption enabled      ✓
 ├── Logging enabled         ✓
 └── Secure configuration    ✓
```
Defender for Cloud surfaces this as a **security recommendation** and rolls findings into an overall **Secure Score**.

**CWPP example:**
```
Azure VM → suspicious process → malware behavior → detection → alert
```

> **Clarification:** Defender for Cloud offers CSPM capabilities as a **free, always-on foundational tier**, plus optional paid **Defender plans** (one per resource type — servers, storage, databases, containers, Key Vault, etc.) that add the CWPP-style threat detection.

**Don't confuse it with Defender for Cloud *Apps*:**

| | Protects |
|---|---|
| **Defender for Cloud** | Cloud infrastructure & workloads (VMs, databases, containers) |
| **Defender for Cloud Apps** | SaaS applications & cloud app usage (CASB) |

---

## 7. Microsoft Defender for IoT

**Microsoft Defender for IoT** secures **IoT and Operational Technology (OT)** devices — industrial controllers, PLCs, sensors, cameras, medical devices, and building systems — that traditional endpoint agents often cannot run on.

**Why it's different:**
```
Corporate PC       →  can install an EDR agent
Industrial PLC     →  usually cannot support an EDR agent
```
Because agents aren't an option, Defender for IoT relies primarily on **network-level, passive traffic monitoring** — sensors placed on the OT/IoT network analyze protocol traffic without touching the devices themselves.

**What it provides:**
- Automatic device inventory and asset discovery
- Network communication mapping (what talks to what)
- Vulnerability assessment for discovered devices
- Detection of unauthorized devices and abnormal protocol activity
- Alerts on suspicious cross-network communication (e.g., a compromised corporate PC trying to reach an OT network)

> **Added for completeness:** Defender for IoT also has an **Enterprise IoT** monitoring add-on that integrates with Defender for Endpoint to extend visibility to IoT devices on standard corporate (not just OT/industrial) networks — printers, VoIP phones, smart TVs, etc.

---

## 8. Microsoft Entra ID Protection

This is the section that needed the most clarification from the original notes, so read carefully:

- **Microsoft Entra ID** (formerly Azure Active Directory) is the underlying **cloud identity and access management platform** — it manages users, groups, applications, devices, authentication, and Conditional Access.
- **Microsoft Entra ID Protection** is the **risk-detection capability built on top of Entra ID** (requires an Entra ID P2 license). It doesn't manage identities itself — it evaluates **risk signals** around sign-ins and accounts and can feed that risk score into Conditional Access policies.

**What Entra ID Protection detects:**
- Risky sign-ins (impossible travel, anonymous/malicious IP addresses, atypical sign-in properties, unfamiliar sign-in locations)
- Risky users (accounts showing a pattern of risky activity over time)
- Leaked/compromised credentials found in breach data
- Suspicious authentication patterns (e.g., password spray)

**How it plugs into access decisions:**
```
User signs in
     │
     ▼
Entra ID evaluates: credentials, MFA, device compliance,
location, and Entra ID Protection risk score
     │
     ▼
Conditional Access policy decision
     │
     ▼
Access granted / blocked / step-up MFA required
```

### Defender for Identity vs. Entra ID Protection — the classic exam distinction

| Signal in the question | Think |
|---|---|
| Domain Controller, on-prem AD, LDAP, Kerberos, NTLM, Domain Admin, AD reconnaissance | **Defender for Identity** |
| Microsoft Entra ID, risky sign-in, risky user, impossible travel, leaked credentials, cloud identity | **Entra ID Protection** |

```
                    IDENTITIES
                        │
              ┌─────────┴─────────┐
       On-premises AD        Microsoft Entra ID
              │                   │
              ▼                   ▼
     Defender for Identity   Entra ID Protection
```

---

## 9. Microsoft Purview Insider Risk Management

**Microsoft Purview Insider Risk Management** detects and helps investigate **potentially risky activity by people already inside the organization** — employees, contractors, privileged users, departing staff, or even compromised accounts.

**Important distinction:** "Insider risk" does **not** mean "malicious employee." It also covers:
- Accidental data leakage
- Intentional data theft
- Policy violations
- Data exfiltration by a compromised account

**Example — employee departure:**
```
Employee resigns
     │
     ▼
Downloads thousands of files → copies sensitive documents
     │
     ▼
Uploads files to personal cloud storage
     │
     ▼
Insider Risk Management correlates the signals → generates an alert/case
```

**Signal sources it draws from:** file activity, email, SharePoint, OneDrive, Microsoft Teams, endpoint activity (via Defender for Endpoint integration), physical badge/HR signals (where configured), and more.

**Risk policies:** Organizations configure policy templates (e.g., "data theft by departing employees," "data leaks," "security policy violations") that define which signals to watch and how to score them. Detected activity generates alerts that can escalate into a **case** for formal investigation, with built-in safeguards like pseudonymization of user identities until an investigator has proper justification to reveal them.

**Exam takeaway:** *Insider Risk Management = identify, investigate, and manage risky user behavior and data-related insider threats — not external attackers.*

---

## Quick Reference Table

| Product | Protects | Main Focus | Mental Shortcut |
|---|---|---|---|
| **Defender XDR** | Everything (correlation layer) | Unified incidents, hunting, automated response | **"The umbrella"** |
| **Defender for Endpoint** | Devices | Endpoint attacks, malware, ransomware, EDR | **Devices** |
| **Defender for Office 365** | Email & M365 apps | Phishing, malware, malicious links/files | **Email** |
| **Defender for Identity** | On-prem AD | Credential theft, Kerberos abuse, lateral movement | **On-prem AD** |
| **Defender for Cloud Apps** | Cloud/SaaS apps | Shadow IT, SaaS visibility & control (CASB) | **Cloud Apps** |
| **Defender for Cloud** | Cloud infrastructure/workloads | Posture (CSPM) + workload protection (CWPP) | **Cloud Infra** |
| **Defender for IoT** | IoT/OT devices | Device & network threats, asset discovery | **IoT/OT** |
| **Entra ID Protection** | Entra ID (cloud) identities | Risky users/sign-ins, leaked credentials | **Cloud Identity** |
| **Purview Insider Risk Mgmt** | Users & data | Insider risk, data exfiltration | **Insiders** |

---

## Key Distinctions Worth Memorizing

1. **Defender for Cloud vs. Defender for Cloud Apps** — infrastructure/workloads vs. SaaS application usage.
2. **Defender for Identity vs. Entra ID Protection** — on-premises AD vs. cloud identity (Entra ID).
3. **Microsoft Entra ID vs. Entra ID Protection** — the identity *platform* vs. the *risk-detection add-on* on top of it.
4. **CSPM vs. CWPP** (inside Defender for Cloud) — "is it configured securely?" vs. "is it being attacked right now?"
5. **Defender XDR is not one more product to memorize in isolation** — it's the correlation and investigation layer that ties every other Defender product (and Entra ID Protection) together into a single incident view.
