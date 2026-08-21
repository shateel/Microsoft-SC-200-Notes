# Microsoft Security Products: Complete SC 200 Study Note

> A single reference covering Microsoft Defender XDR, the individual Defender products, Microsoft Entra ID Protection, and Microsoft Purview Insider Risk Management, written for SC 200 Security Operations Analyst preparation.

## Table of Contents

1. [Microsoft Defender XDR](#1-microsoft-defender-xdr)
2. [Microsoft Defender for Endpoint](#2-microsoft-defender-for-endpoint)
3. [Microsoft Defender for Office 365](#3-microsoft-defender-for-office-365)
4. [Microsoft Defender for Identity](#4-microsoft-defender-for-identity)
5. [Microsoft Defender for Cloud Apps](#5-microsoft-defender-for-cloud-apps)
6. [Microsoft Defender for Cloud](#6-microsoft-defender-for-cloud)
7. [Microsoft Defender for IoT](#7-microsoft-defender-for-iot)
8. [Microsoft Entra ID Protection](#8-microsoft-entra-id-protection)
9. [Microsoft Purview Insider Risk Management](#9-microsoft-purview-insider-risk-management)
10. [Overall Architecture: How These Products Work Together](#10-overall-architecture-how-these-products-work-together)
11. [Product Comparison Table](#11-product-comparison-table)
12. [Which Product Should I Think Of?](#12-which-product-should-i-think-of)
13. [SC 200 Exam Quick Revision](#13-sc-200-exam-quick-revision)
14. [Key Differences Between Commonly Confused Products](#14-key-differences-between-commonly-confused-products)
15. [End to End SOC Scenario](#15-end-to-end-soc-scenario)

---

## 1. Microsoft Defender XDR

### 1.1 Overview

Microsoft Defender XDR is Microsoft's unified **Extended Detection and Response (XDR)** platform. It is not a separate sensor that watches a single surface. Instead, it is the correlation and investigation layer that sits above the individual Defender products, Entra ID Protection, and (through connected experiences) Microsoft Purview.

It is used because a single attack rarely stays inside one product's view. A phishing email, an infected laptop, a stolen password, and a suspicious cloud login are often the same attack seen from four different angles. Defender XDR combines these views automatically so an analyst does not have to manually stitch alerts together.

> **Correction of a common misconception:** Defender XDR is often listed as if it were "just one more Defender product." It is more accurate to describe it as the central nervous system that receives signals from the other products, correlates them, and presents a single incident for investigation.

### 1.2 How It Works

Each connected product (Defender for Endpoint, Defender for Office 365, Defender for Identity, Defender for Cloud Apps, and, through the wider ecosystem, Entra ID Protection and Defender for Cloud) sends its own alerts into the unified Defender portal at `security.microsoft.com`. Defender XDR then applies correlation logic across entities (the same user, device, mailbox, IP address, or file appearing in multiple alerts) to group related alerts into a single incident.


```text
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
              Generate Alerts
                     │
                     ▼
           Microsoft Defender XDR
     (Correlates alerts into Incidents)
                     │
                     ▼
        Single Correlated Incident
                     │
                     ▼
             SOC Investigation
```

### 1.3 Key Capabilities

* **Incidents:** grouped alerts, entities, and evidence for a single attack.
* **Advanced Hunting:** proactive threat hunting using **Kusto Query Language (KQL)** across endpoint, email, identity, and cloud app tables.
* **Automated Investigation and Response (AIR):** automatically investigates supported alert types and can take remediation actions.
* **Automatic attack disruption:** automatically contains an active, high confidence attack (for example, disabling a compromised account or isolating a device) while the investigation continues.
* **Threat analytics:** curated reports from Microsoft threat intelligence teams on active threat actors and campaigns, mapped to the organization's own exposure.
* **Custom detection rules:** analyst written KQL queries that run on a schedule and automatically generate alerts or incidents.
* **Hunting graphs:** visual exploration of how entities relate to one another during an investigation.
* **Unified case management:** incident status, classification, determination, assignment, and comments in one place.

### 1.4 Alerts and Incidents

Defender XDR does not usually generate its own raw detections from scratch. Its primary alert source is the connected products. Its main output is the **incident**: a correlated container of alerts, affected assets, evidence, and an automatically reconstructed attack story.

### 1.5 Relationship to Individual Defender Products

| Individual Product | Defender XDR |
|---|---|
| Watches one surface (endpoint, email, identity, or cloud app) | Watches the relationships between all surfaces |
| Generates its own alerts | Receives and correlates alerts from every connected product |
| Has its own deep, product specific console for detailed forensics | Provides the unified incident queue, Advanced Hunting, and cross product investigation |

### 1.6 SOC Scenario

An analyst opens the unified Defender portal and sees one incident named **"Multistage attack involving phishing, endpoint compromise, and identity access."** Instead of separately checking Exchange, the endpoint console, and Entra sign in logs, the analyst opens a single incident that already lists the phishing email, the infected device, and the risky sign in as one connected timeline.

### 1.7 SC 200 Exam Notes

> Defender XDR skills form a large part of the SC 200 exam. Be comfortable with: incident management (status, classification, determination), Advanced Hunting KQL, custom detection rules, automated investigation and response, automatic attack disruption, threat analytics, alert tuning and suppression, and multistage attack investigation. Remember that Defender XDR is the correlation and investigation platform, not a data source in its own right.

---

## 2. Microsoft Defender for Endpoint

### 2.1 Overview

Microsoft Defender for Endpoint (MDE) is Microsoft's enterprise endpoint security platform. It provides **Endpoint Detection and Response (EDR)** together with antivirus, attack surface reduction, and vulnerability management for devices.

It is used to prevent, detect, investigate, and respond to threats that occur directly on a device, such as malware execution, exploitation, or an attacker moving through a compromised machine.

It protects:

* Windows clients and servers
* macOS
* Linux
* Android and iOS (through supported configurations)
* Network devices discovered through built in device discovery

### 2.2 How It Works

MDE deploys sensors to endpoints. These sensors continuously collect telemetry and send it to the Microsoft Defender portal for analysis.

Signals collected include:

* Process creation and command line activity
* File creation and modification
* Registry changes
* Network connections and DNS activity
* Logon activity
* PowerShell and script execution
* Persistence mechanisms

```text
Malicious Document Opened
          │
          ▼
     WINWORD.EXE
          │
          ▼
      powershell.exe
          │
          ▼
 Suspicious network connection
          │
          ▼
     Malicious payload downloaded
          │
          ▼
        MDE Sensor
          │
          ▼
   Behavioral Detection Engine
          │
          ▼
        Alert Generated
```

### 2.3 Key Capabilities

* **Endpoint Detection and Response (EDR):** device timeline, process trees, and behavioral detections.
* **Microsoft Defender Antivirus:** signature and machine learning based malware prevention, integrated with the same sensor.
* **Attack surface reduction (ASR) rules:** block specific risky behaviors, for example Office applications creating child processes.
* **Threat and vulnerability management:** discovers missing patches, misconfigurations, and exposed software so risk can be prioritized before an attack occurs.
* **Automated investigation and response (AIR):** automatically investigates common alert types on the device and can remediate them.
* **Live response:** gives an analyst a remote, real time command shell on the device for deep investigation.
* **Device isolation and file quarantine:** immediate containment actions available to the analyst.

### 2.4 Alerts and Incidents

MDE generates alerts for malware detections, suspicious behavior, exploitation attempts, and living off the land activity. Related alerts on the same device or user are grouped by Defender XDR into a single incident.

### 2.5 Integration with Microsoft Defender XDR

MDE alerts flow directly into the unified Defender portal. Its device level tables (for example `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`) are available in Advanced Hunting and can be correlated with email, identity, and cloud app tables during an investigation.

### 2.6 Relationship to Other Products

MDE is the primary source of device level telemetry for the whole Defender ecosystem. It complements Defender for Identity (which watches the domain controller side of authentication) and Defender for Cloud Apps (which watches cloud sessions), giving Defender XDR visibility from the device outward.

### 2.7 SOC Scenario

An employee opens a malicious attachment. MDE observes `WINWORD.EXE` spawning `powershell.exe`, which then downloads a payload and creates a scheduled task for persistence. The analyst reviews the process tree in the device timeline, isolates the machine, stops the malicious process, collects an investigation package, removes the persistence mechanism, and runs an Advanced Hunting query to check whether other devices show the same behavior.

### 2.8 SC 200 Exam Notes

> Know the difference between **prevention** (antivirus, ASR rules), **detection and response** (EDR, device timeline), and **exposure management** (threat and vulnerability management). Remember live response, device isolation, and Advanced Hunting device tables as core exam topics. Attack surface reduction rules and automated investigation and response are frequently tested.

---

## 3. Microsoft Defender for Office 365

### 3.1 Overview

Microsoft Defender for Office 365 (MDO) is Microsoft's security service, delivered through the cloud, for protecting Microsoft 365 email and collaboration workloads. It is used to stop threats that arrive through messages, links, and shared files before, or shortly after, they reach a user.

It protects:

* Exchange Online mailboxes
* Microsoft Teams messages and shared files
* SharePoint Online
* OneDrive

### 3.2 How It Works

Every incoming email and every file shared through the protected collaboration surfaces is analyzed by MDO using sender reputation, URL analysis, attachment detonation, and machine learning, before a delivery decision is made.

```text
              INTERNET
                 │
                 ▼
           Incoming Email
                 │
                 ▼
      Defender for Office 365
                 │
     ┌───────────┼────────────┐
     ▼            ▼            ▼
  Sender        URL        Attachment
 Analysis     Analysis      Analysis
     │            │            │
     └───────────┼────────────┘
                 ▼
         Threat Intelligence
                 │
                 ▼
           Machine Learning
                 │
                 ▼
             Risk Decision
      ┌──────────┼───────────┐
      ▼          ▼           ▼
   Allow    Quarantine     Block
```

### 3.3 Key Capabilities

* **Safe Attachments:** detonates suspicious attachments in an isolated environment before allowing delivery.
* **Safe Links:** rewrites and checks URLs at the time a user clicks them, not only at delivery time.
* **Anti-phishing protection:** detects user impersonation, domain impersonation, spoofing, and suspicious sender behavior, for example a lookalike domain such as `ceo@company-security.com` pretending to be `company.com`.
* **Threat Explorer:** an investigation and search interface for email related security events across the organization. It answers questions such as who received a malicious message, who clicked a link, and whether a message was delivered or quarantined.
* **Automated investigation and response:** automatically identifies every user who received a confirmed malicious email (useful because a phishing campaign can target hundreds of mailboxes at once) and can remediate all copies.
* **Campaign views:** groups related phishing waves so an analyst can see the full scope of a coordinated attack.

### 3.4 Alerts and Incidents

MDO generates alerts for phishing, malware attachments, malicious URL clicks, business email compromise (BEC), and impersonation attempts. These alerts appear in the unified Defender portal and can be correlated with endpoint or identity alerts affecting the same user.

### 3.5 Integration with Microsoft Defender XDR

Email signals and Threat Explorer data are surfaced inside Defender XDR incidents, so an email based alert can be automatically linked with what happens afterward on the recipient's device or account.

### 3.6 Relationship to Other Products

MDO protects the delivery channel (email and collaboration content). Once a user interacts with malicious content, the attack typically continues on the endpoint (MDE), the identity (Defender for Identity or Entra ID Protection), or a cloud application (Defender for Cloud Apps). MDO is almost always the first product to see the beginning of a phishing driven attack chain.

### 3.7 SOC Scenario

A phishing email with the subject "Your Microsoft account has expired, click here to verify" is delivered to fifty employees. Safe Links flags the URL as malicious after several users click it. The analyst uses Threat Explorer to identify every recipient, confirms which mailboxes still contain the message, and uses automated investigation and response to remove the email from all affected mailboxes in one action.

### 3.8 SC 200 Exam Notes

> Remember the distinct purposes of **Safe Attachments** (file safety), **Safe Links** (URL safety), and **anti-phishing policies** (sender or domain impersonation). **Threat Explorer** is the primary investigation tool for email incidents. Know common threat categories: phishing, spear phishing, business email compromise, malware attachments, malicious URLs, impersonation, and spam.

---

## 4. Microsoft Defender for Identity

### 4.1 Overview

Microsoft Defender for Identity (MDI) is Microsoft's security solution for monitoring and protecting **on premises Active Directory (AD)** identities and domain infrastructure. It is used to detect attacks that specifically target Active Directory, such as credential theft, reconnaissance, lateral movement, privilege escalation, and domain compromise.

It protects:

* Active Directory Domain Services (AD DS)
* Domain controllers
* User and privileged accounts authenticating against on premises AD

### 4.2 How It Works

MDI uses a lightweight sensor installed on:

* Domain controllers
* Active Directory Federation Services (AD FS) servers
* Active Directory Certificate Services (AD CS) servers, where supported

The sensor observes authentication protocols and directory activity, including Kerberos, NTLM, and LDAP traffic, and analyzes behavior and relationships across the identity environment rather than looking for a single fixed signature.

```text
       USER / DEVICE
             │
             ▼
      Authentication
             │
             ▼
       Domain Controller
             │
   ┌─────────┴─────────┐
   ▼                   ▼
AD Activity      Authentication Activity
   │                   │
   └─────────┬─────────┘
             ▼
        MDI Sensor
             │
             ▼
   Microsoft Defender XDR
             │
             ▼
     Behavioral Analysis
             │
             ▼
  Suspicious Activity Detected?
       │            │
       NO          YES
       │            │
       ▼            ▼
   Continue     Alert Generated
                     │
                     ▼
                 Incident
                     │
                     ▼
               SOC Analyst
```

### 4.3 Key Capabilities and Detected Attacks

* **Credential theft**, including **Pass-the-Hash** and **Pass-the-Ticket** attacks.
* **Kerberoasting**, an attack that targets service account credentials.
* **Reconnaissance detection**, for example an attacker enumerating domain admins, computers, users, and groups.
* **Lateral movement and privilege escalation** across the domain.
* **Golden Ticket attacks**, where an attacker who has obtained the KRBTGT account hash forges Kerberos ticket granting tickets.
* **Domain dominance techniques**, such as DCSync, where an attacker impersonates a domain controller to replicate password hashes.

### 4.4 Alerts and Incidents

MDI raises alerts tied to specific identities, computers, and detected attack techniques. Because MDI's strength is behavioral and relationship based analysis, its alerts often represent a meaningful stage in an attack chain rather than an isolated event.

### 4.5 Integration with Microsoft Defender XDR

MDI alerts appear in the unified Defender portal and correlate automatically with endpoint and email alerts affecting the same compromised account, allowing Defender XDR to connect "malware on a laptop" with "credential theft against the domain controller" as one incident.

### 4.6 Relationship to Other Products

MDI is frequently confused with Entra ID Protection. The distinction is explained in full in [Section 14](#14-key-differences-between-commonly-confused-products), but the short version is: MDI watches on premises Active Directory, while Entra ID Protection watches Microsoft Entra ID, Microsoft's cloud identity platform.

### 4.7 SOC Scenario

An attacker compromises a standard employee account, then performs directory reconnaissance to identify domain admins, escalates privileges, and attempts lateral movement toward a domain controller. MDI detects the reconnaissance pattern and the abnormal authentication behavior, raises an alert, and the analyst investigates the account's authentication history, identifies the compromised host, and contains the account before domain dominance is achieved.

### 4.8 SC 200 Exam Notes

> Memorize where the MDI sensor is installed (domain controllers, AD FS, and AD CS) and the named attack techniques it detects: Pass-the-Hash, Pass-the-Ticket, Kerberoasting, Golden Ticket, and DCSync. If a question mentions domain controllers, LDAP, Kerberos, NTLM, or Active Directory reconnaissance, the answer is almost always Defender for Identity, not Entra ID Protection.

---

## 5. Microsoft Defender for Cloud Apps

### 5.1 Overview

Microsoft Defender for Cloud Apps (MDCA) is Microsoft's **Cloud Access Security Broker (CASB)**. It is used to gain visibility into which cloud applications an organization actually uses, assess their risk, and control how data moves through them.

It protects:

* Sanctioned SaaS applications, for example Microsoft 365, Salesforce, and Google Workspace
* The organization from unsanctioned or unknown application use, commonly called **Shadow IT**

### 5.2 How It Works

MDCA can connect directly to sanctioned cloud applications through APIs to inspect activity and content, analyze network and firewall logs through **Cloud Discovery** to find applications in use that were not previously known, and apply real time session controls through **Conditional Access App Control**.

```text
User
  │
  ▼
Cloud Application Session
  │
  ▼
Defender for Cloud Apps
  │
  ├── Cloud Discovery ── identifies unknown apps from network logs
  ├── App Catalog ────── scores app risk
  ├── Activity Policies ── flags risky user behavior
  └── Session Control ── monitors or blocks the live session
  │
  ▼
Allow / Monitor / Block
```

### 5.3 Key Capabilities

* **Cloud Discovery:** analyzes network or firewall logs to reveal every cloud application actually in use, including unsanctioned ones.
* **Cloud App Catalog:** scores thousands of applications against security relevant criteria so the organization can decide which are acceptable.
* **Conditional Access App Control:** integrates with Microsoft Entra Conditional Access to monitor or restrict a cloud session in real time, for example blocking a download of sensitive data from an unmanaged device.
* **Activity and file policies:** detect risky behavior such as mass downloads, unusual sharing, or impossible cloud activity.
* **OAuth app governance:** reviews permissions granted to third party applications connected to Microsoft 365.

### 5.4 Alerts and Incidents

MDCA generates alerts for anomalous cloud activity, risky OAuth grants, mass download or exfiltration patterns, and use of unsanctioned applications. These alerts feed into the unified Defender portal.

### 5.5 Integration with Microsoft Defender XDR

MDCA alerts appear as part of Defender XDR incidents, so a compromised identity detected by Entra ID Protection or Defender for Identity can be automatically connected to suspicious activity the same account performs inside a cloud application.

### 5.6 Relationship to Other Products

MDCA is frequently confused with Defender for Cloud. MDCA secures the use of SaaS applications; Defender for Cloud secures the underlying cloud infrastructure and workloads. The full comparison is in [Section 14](#14-key-differences-between-commonly-confused-products).

### 5.7 SOC Scenario

An employee discovers an unapproved cloud storage service, creates an account without informing the security team, and uploads company files. Cloud Discovery identifies the previously unknown application from firewall logs, the App Catalog marks it as high risk, and the analyst uses activity policies to confirm sensitive files were uploaded, then blocks the application through Conditional Access App Control.

### 5.8 SC 200 Exam Notes

> Defender for Cloud Apps equals discover, monitor, and control cloud and SaaS application usage. Remember **Cloud Discovery** (finding unknown apps), the **App Catalog** (scoring app risk), and **Conditional Access App Control** (real time session control). The exam word to associate with MDCA is **Shadow IT**.

---

## 6. Microsoft Defender for Cloud

### 6.1 Overview

Microsoft Defender for Cloud is Microsoft's cloud security platform for protecting cloud infrastructure and workloads. It is used to answer two different questions: how securely are cloud resources configured, and are cloud workloads currently under attack.

It protects:

* Virtual machines and servers, including hybrid and multicloud servers
* Databases, for example Azure SQL
* Storage accounts
* Containers and Kubernetes
* Other cloud resources across Azure and, through connectors, AWS and Google Cloud

### 6.2 How It Works

Defender for Cloud combines two complementary capabilities.

| Capability | Question It Answers | Example |
|---|---|---|
| **Cloud Security Posture Management (CSPM)** | How securely is my cloud environment configured? | A storage account with public access enabled generates a security recommendation |
| **Cloud Workload Protection (CWP)**, sometimes called CWPP | Is my cloud workload actively being attacked? | An Azure virtual machine runs a suspicious process, which is detected and raised as an alert |

```text
Cloud Resource (VM, Storage, SQL, Container)
             │
   ┌─────────┴──────────┐
   ▼                    ▼
Configuration        Runtime
  Analysis            Analysis
   │                    │
   ▼                    ▼
Posture              Threat
Recommendations      Detection
   │                    │
   └─────────┬──────────┘
             ▼
   Secure Score / Alerts
```

### 6.3 Key Capabilities

* **Secure score:** a measurable summary of the organization's overall cloud security posture.
* **Security recommendations:** prioritized, actionable fixes for misconfigurations.
* **Defender plans (workload protection):** threat detection for specific resource types, for example Defender for Servers, Defender for Storage, Defender for Containers, Defender for SQL, and Defender for Key Vault.
* **Multicloud support:** posture management, and in many cases workload protection, extends to AWS and Google Cloud through native connectors.
* **Regulatory compliance dashboard:** maps configuration against standards and frameworks the organization must follow.

### 6.4 Alerts and Incidents

Posture issues appear as prioritized recommendations rather than incidents. Active threats against a workload, for example a suspicious process on a virtual machine, generate security alerts that flow into the unified Defender portal like any other Defender alert.

### 6.5 Integration with Microsoft Defender XDR

Defender for Cloud workload protection alerts are visible in the unified Defender portal and can be correlated with identity or endpoint alerts, which matters when an attacker pivots from a compromised on premises account into a cloud hosted virtual machine or database.

### 6.6 Relationship to Other Products

Defender for Cloud is frequently confused with Defender for Cloud Apps because of the similar name. Defender for Cloud protects infrastructure and workloads; Defender for Cloud Apps protects SaaS application usage. The full comparison is in [Section 14](#14-key-differences-between-commonly-confused-products).

### 6.7 SOC Scenario

A cloud administrator accidentally leaves a storage account open to public access. Defender for Cloud raises a posture recommendation, which the cloud security team prioritizes and remediates. Separately, in a different scenario, a virtual machine begins running suspicious processes consistent with malware, and Defender for Cloud raises a workload protection alert that a SOC analyst investigates using the same unified Defender portal used for endpoint alerts.

### 6.8 SC 200 Exam Notes

> Remember CSPM equals configuration and posture, while CWP equals active threat detection on running workloads. Defender for Cloud is not limited to Azure; it extends to hybrid and multicloud environments through connectors and the Azure Arc agent.

---

## 7. Microsoft Defender for IoT

### 7.1 Overview

Microsoft Defender for IoT is Microsoft's security solution for Internet of Things (IoT) and **Operational Technology (OT)** environments. It is used because many industrial and specialized devices cannot run a traditional endpoint security agent, so network level visibility becomes the practical way to protect them.

It protects:

* Industrial controllers and programmable logic controllers (PLCs)
* Sensors, cameras, and building systems
* Medical devices
* Enterprise IoT devices such as printers, VOIP phones, and smart TVs on the corporate network
* Industrial and OT networks, including SCADA and ICS environments

### 7.2 How It Works

Defender for IoT has two complementary deployment models.

* **OT network sensors:** agentless sensors, typically connected through a network tap or a switch port mirror (SPAN), passively monitor OT and industrial network traffic without needing software installed on the industrial devices themselves.
* **Enterprise IoT monitoring:** extends visibility to IoT devices on standard corporate networks. It builds on existing Microsoft Defender for Endpoint network sensing capability rather than requiring a fully separate OT sensor.

```text
   OT / IoT Network
         │
   ┌─────┴─────┐
   ▼           ▼
  PLC        Sensor
   │           │
   └─────┬─────┘
         ▼
  Defender for IoT
   (network sensor)
         │
         ▼
   Threat Detection
         │
         ▼
        SOC
```

### 7.3 Key Capabilities

* **Asset discovery and inventory:** automatically identifies devices on OT and IoT networks, including device type and communication patterns.
* **Vulnerability assessment:** highlights outdated firmware, weak configurations, and known vulnerabilities specific to industrial equipment.
* **Behavioral threat detection:** identifies unauthorized devices, abnormal protocol activity, and suspicious communication patterns typical of OT and ICS specific attacks.
* **Network segmentation insight:** helps identify where IT and OT networks are insufficiently separated, which is a common path attackers use to reach industrial systems.

### 7.4 Alerts and Incidents

Defender for IoT generates alerts for unauthorized devices, abnormal communication between OT assets, protocol anomalies, and known threat indicators observed on the OT or IoT network.

### 7.5 Integration with Microsoft Defender XDR

Defender for IoT alerts, particularly from Enterprise IoT monitoring, can surface in the unified Defender portal, allowing an OT or IoT related alert to be correlated with a broader incident that started on a traditional endpoint or identity.

### 7.6 Relationship to Other Products

Defender for IoT is frequently confused with Defender for Endpoint. Defender for Endpoint protects devices capable of running a security agent; Defender for IoT protects devices that typically cannot, using network level visibility instead. The full comparison is in [Section 14](#14-key-differences-between-commonly-confused-products).

### 7.7 SOC Scenario

An attacker compromises a workstation on the corporate network and attempts to reach the industrial network to communicate with a PLC. Defender for IoT observes the unusual communication between an IT segment device and an OT asset, raises an alert, and the SOC uses this network level visibility to investigate the attempted pivot from IT into OT.

### 7.8 SC 200 Exam Notes

> Remember the reason Defender for IoT exists: many OT and industrial devices cannot run an endpoint agent, so detection relies on network traffic analysis instead of device telemetry. Know the distinction between OT network sensors (industrial environments) and Enterprise IoT monitoring (corporate network IoT devices).

---

## 8. Microsoft Entra ID Protection

### 8.1 Overview

Microsoft Entra ID Protection is a risk detection and remediation service built into **Microsoft Entra ID**, Microsoft's cloud based identity and access management platform, formerly known as Azure Active Directory (Azure AD).

> **Correction of a common source of confusion:** Microsoft Entra ID itself is the broad identity platform that manages users, groups, applications, authentication, and Conditional Access. **Entra ID Protection** is the specific risk detection capability within that platform, focused on identifying risky users and risky sign ins. The two terms are related but not identical, and SC 200 questions usually test the risk detection capability specifically.

It is used to detect signs that a cloud identity may be compromised and to trigger an automatic or policy driven response, most often through Conditional Access.

It protects: user identities authenticating to Microsoft Entra ID and the cloud resources those identities can access.

### 8.2 How It Works

Entra ID Protection continuously evaluates sign in and account behavior against known risk indicators and assigns a risk level.

* **User risk:** the likelihood that the identity itself has been compromised, based on longer term signals, for example leaked credentials found outside the organization.
* **Sign in risk:** the likelihood that a specific sign in attempt is not the legitimate user, for example an impossible travel pattern or a sign in from an anonymous IP address.

```text
Sign In Attempt
       │
       ▼
Entra ID Protection Evaluates
   ┌───────┼─────────┐
   ▼       ▼         ▼
Location  Device   Sign In Pattern
   │       │         │
   └───────┼─────────┘
           ▼
     Risk Level Assigned
     (Low, Medium, High)
           │
           ▼
   Conditional Access Policy
     ┌─────┼──────┐
     ▼     ▼      ▼
   Allow  Require   Block
          MFA
```

### 8.3 Key Capabilities

* **Risky user and risky sign in detections**, including impossible travel, anonymous IP address use, atypical sign in properties, and leaked credentials.
* **Risk levels:** each risky user or sign in is scored Low, Medium, or High so policies can respond proportionally.
* **Integration with Conditional Access:** risk levels can automatically trigger a required action, such as multifactor authentication or a password change, or block access entirely.
* **Workload identity risk detection:** extends risk detection to non human identities such as applications and service principals, not only user accounts.
* **Risk investigation reports:** give the SOC a history of risky users and risky sign ins for review.

### 8.4 Alerts and Incidents

Entra ID Protection generates risk detections and risk based alerts tied to specific identities and sign in events. These are surfaced in the unified Defender portal alongside other identity related alerts.

### 8.5 Integration with Microsoft Defender XDR

Entra ID Protection signals appear inside Defender XDR incidents, allowing a risky sign in to be automatically linked with related activity detected by Defender for Endpoint, Defender for Cloud Apps, or Defender for Identity for the same user.

### 8.6 Relationship to Other Products

Entra ID Protection is frequently confused with Defender for Identity. Entra ID Protection watches Microsoft Entra ID, the cloud identity platform; Defender for Identity watches on premises Active Directory. The full comparison is in [Section 14](#14-key-differences-between-commonly-confused-products).

### 8.7 SOC Scenario

A user's credentials appear in a leaked credential feed, and shortly afterward a sign in occurs from a country the user has never signed in from before, on an unfamiliar device. Entra ID Protection assigns a high risk level to both the user and the sign in. Conditional Access automatically requires multifactor authentication, which the attacker cannot satisfy, blocking access. The analyst reviews the risk detection details and confirms the account should be reset as a precaution.

### 8.8 SC 200 Exam Notes

> If a question mentions Microsoft Entra ID, risky sign in, risky user, impossible travel, leaked credentials, or cloud identity, think **Entra ID Protection**. If it mentions domain controllers, Kerberos, NTLM, or on premises Active Directory, think **Defender for Identity**. Remember the two risk types, user risk and sign in risk, and that Conditional Access is the enforcement layer that acts on the risk level.

---

## 9. Microsoft Purview Insider Risk Management

### 9.1 Overview

Microsoft Purview Insider Risk Management is a service inside the **Microsoft Purview compliance portal** that focuses on identifying and investigating potentially risky activities performed by people who already have legitimate access inside the organization: employees, contractors, privileged users, departing employees, or accounts that have been compromised.

> **Important clarification:** insider risk does not always mean malicious intent. It can also involve accidental data leakage, policy violations, or a compromised account behaving abnormally.

It protects: organizational data and intellectual property from risks originating from trusted, already authenticated users and accounts.

### 9.2 How It Works

Insider Risk Management correlates signals from multiple Microsoft 365 sources, using configurable policies built around specific risk scenarios, such as data theft by a departing employee or data leaks by a current employee.

Data sources it can draw from include:

* Exchange Online, SharePoint Online, OneDrive, and Microsoft Teams activity
* Microsoft Purview Communication Compliance signals
* Microsoft Defender for Endpoint device indicators, where connected
* Human resources data, for example a resignation or termination date, through supported connectors
* Physical access signals, where connectors are configured

```text
User Activity
    │
    ├── File access and downloads
    ├── Email and Teams activity
    ├── SharePoint and OneDrive activity
    └── Optional signals: device, HR, physical access
    │
    ▼
Purview Insider Risk Management
    │
    ▼
Risk Analysis Against Policy
    │
    ▼
Alert / Case
    │
    ▼
Investigation by Compliance or Insider Risk Team
```

### 9.3 Key Capabilities

* **Risk policies:** prebuilt templates for common scenarios, such as data theft by departing users, data leaks, or security policy violations.
* **Sequence detection:** recognizes a sequence of related risky actions rather than a single isolated event, for example downloading many files followed by uploading them to personal cloud storage.
* **Adaptive Protection:** dynamically adjusts data loss prevention controls based on a user's current insider risk level.
* **Case management:** investigators can review evidence, add notes, and escalate cases through a dedicated workflow inside the Purview portal.
* **Privacy controls:** built in pseudonymization options that protect user identity during early stage analysis.

### 9.4 Alerts and Incidents

Insider Risk Management generates alerts and cases inside the Microsoft Purview compliance portal. These are reviewed by compliance or insider risk investigators, not primarily by the SOC's Defender XDR incident queue.

### 9.5 Integration with Microsoft Defender XDR

> **Important distinction for the exam:** Insider Risk Management is a Microsoft Purview capability, managed through the compliance portal at `purview.microsoft.com`, not a native Defender XDR product. It can optionally use Defender for Endpoint signals as one input, but its cases are not automatically surfaced as Defender XDR incidents in the same way endpoint, email, identity, or cloud app alerts are. Treat it as a related but separate discipline: data governance and insider risk, rather than security operations incident response.

### 9.6 Relationship to Other Products

Insider Risk Management is frequently confused with the Defender security products because both deal with "risk." The full comparison is in [Section 14](#14-key-differences-between-commonly-confused-products).

### 9.7 SOC Scenario

An employee who has submitted their resignation begins downloading thousands of files, copying sensitive documents, and uploading them to a personal cloud storage account shortly before their last day. Insider Risk Management correlates this sequence of activity against a departing employee policy, generates an alert, and opens a case for the insider risk investigation team to review and, if needed, escalate to HR or legal.

### 9.8 SC 200 Exam Notes

> Remember that Insider Risk Management equals identifying, investigating, and managing potentially risky behavior from trusted insiders and data related risks. Know that it lives in Microsoft Purview, not the Defender security portal, even though the exam expects you to know it exists and understand its purpose.

---

## 10. Overall Architecture: How These Products Work Together

```text
Users / Devices / Applications / Email / Identity / Cloud / IoT
                              │
                              ▼
                  Microsoft Security Signals
                              │
   ┌───────────┬───────────┬─────────────┬─────────────┬───────────┐
   ▼           ▼           ▼             ▼             ▼           ▼
Defender    Defender    Defender      Defender      Entra ID    Defender
for         for         for           for Cloud     Protection  for IoT
Endpoint    Office 365  Identity      Apps
   │           │           │             │             │           │
   └───────────┴───────────┴──────┬──────┴─────────────┴───────────┘
                                   ▼
                      Microsoft Defender XDR
                    (Correlation and Incidents)
                                   │
                    ┌──────────────┴───────────────┐
                    ▼                               ▼
             SOC Investigation              Microsoft Purview
          (Advanced Hunting, KQL,        Insider Risk Management
        Automated Investigation and     (Separate compliance path
         Response, Attack Disruption)     for insider risk cases)
                    │
                    ▼
             Response / Remediation

                        Separately:
                 Microsoft Defender for Cloud
             (Cloud posture and workload protection,
              alerts also visible in the unified portal)
```

Key points this diagram illustrates:

* Six of the covered products (Defender for Endpoint, Defender for Office 365, Defender for Identity, Defender for Cloud Apps, Defender for Cloud, and, through connected experiences, Entra ID Protection and Defender for IoT) send alerts into **Microsoft Defender XDR**, which performs correlation and produces incidents.
* **Microsoft Defender XDR** is the shared investigation surface: Advanced Hunting, automated investigation and response, and attack disruption all operate here.
* **Microsoft Purview Insider Risk Management** sits alongside this ecosystem rather than inside it. It focuses on trusted insider behavior and data risk, managed through the Purview compliance portal, and is not part of the standard Defender XDR incident correlation flow.
* **Microsoft Defender for Cloud** contributes both posture recommendations (which stay inside the Defender for Cloud experience) and active workload threat alerts (which do surface in the unified Defender portal).

---

## 11. Product Comparison Table

| Product | Primary Purpose | Protects | Main Signals or Data | Key SOC Use |
|---|---|---|---|---|
| **Microsoft Defender XDR** | Correlate alerts into incidents and enable cross product investigation | The relationships between all connected products | Alerts and entities from every connected Defender product and Entra ID Protection | Incident investigation, Advanced Hunting, automated response, attack disruption |
| **Defender for Endpoint** | Endpoint detection, response, and prevention | Devices: Windows, macOS, Linux, mobile | Process, file, registry, network, and logon telemetry | Investigate device compromise, isolate devices, hunt for malware |
| **Defender for Office 365** | Email and collaboration threat protection | Exchange Online, Teams, SharePoint, OneDrive | Message, sender, URL, and attachment analysis | Investigate phishing, remediate malicious email at scale |
| **Defender for Identity** | Detect attacks against on premises Active Directory | Domain controllers, AD DS, AD FS, AD CS | Kerberos, NTLM, LDAP, and directory activity | Investigate credential theft, lateral movement, domain compromise |
| **Defender for Cloud Apps** | Cloud Access Security Broker (CASB) for SaaS visibility and control | Cloud and SaaS applications | API connected app activity, network logs, OAuth grants | Investigate Shadow IT, control risky cloud sessions |
| **Defender for Cloud** | Cloud security posture and workload protection | Cloud infrastructure and workloads (Azure, AWS, GCP) | Configuration data, workload telemetry | Remediate misconfigurations, investigate workload attacks |
| **Defender for IoT** | Security for IoT and OT and industrial networks | IoT devices, OT and ICS networks | Network traffic from taps or mirrored switch ports | Investigate unauthorized OT devices, IT to OT pivot attempts |
| **Entra ID Protection** | Cloud identity risk detection | Microsoft Entra ID accounts and sign ins | Sign in behavior, location, device, leaked credential feeds | Investigate risky sign ins and risky users, drive Conditional Access |
| **Purview Insider Risk Management** | Detect and investigate risky behavior from trusted insiders | Organizational data and intellectual property | M365 activity, optional HR, device, and physical access signals | Investigate data theft or leakage by employees and contractors |

---

## 12. Which Product Should I Think Of?

```text
Endpoint                          → Defender for Endpoint
Email and collaboration           → Defender for Office 365
On premises Identity, AD, LDAP    → Defender for Identity
Cloud (SaaS) Applications         → Defender for Cloud Apps
Cloud Infrastructure and Workloads → Defender for Cloud
IoT and OT Devices                → Defender for IoT
Entra ID Risky Sign In or User    → Entra ID Protection
Trusted Insider or Data Risk      → Purview Insider Risk Management
Cross Product Correlation         → Microsoft Defender XDR
```

> **Refinement of this cheat sheet:** "Cross product Detection and Response" is best understood specifically as correlation, incident investigation, and Advanced Hunting across every other product's signals, not as a tenth data source of its own.

---

## 13. SC 200 Exam Quick Revision

* **Product purpose:** know the one line purpose of each product before memorizing details. A confused purpose leads to a wrong answer even when the detail knowledge is correct.
* **Data sources:** Defender for Endpoint uses device telemetry, Defender for Office 365 uses message and URL analysis, Defender for Identity uses domain controller authentication traffic, Defender for Cloud Apps uses API connections and network logs, Defender for Cloud uses configuration and workload telemetry, Defender for IoT uses network traffic from OT and IoT segments, Entra ID Protection uses sign in and account risk signals, and Purview Insider Risk Management uses Microsoft 365 activity plus optional HR and device signals.
* **Detection capabilities:** distinguish signature based detection (antivirus), behavioral detection (EDR, Defender for Identity), configuration analysis (CSPM), and risk scoring (Entra ID Protection, Insider Risk Management).
* **Alert generation:** every Defender product and Entra ID Protection generates its own alerts; Defender XDR correlates them into incidents rather than generating most alerts itself.
* **Incident correlation:** Defender XDR groups alerts that share entities, for example the same user, device, or mailbox, into one incident with a reconstructed attack story.
* **Investigation workflows:** know the standard building blocks: timeline, evidence, alerts, and assets inside an incident, plus Threat Explorer for email specific investigation and the device timeline for endpoint specific investigation.
* **Advanced Hunting:** KQL queries across Defender XDR tables, used both for reactive investigation and proactive hunting; queries can be saved as custom detection rules.
* **Microsoft Defender XDR integration:** every product covered in this note, with the partial exception of Insider Risk Management, feeds alerts into the unified Defender portal.
* **Automated investigation and response:** available in Defender for Endpoint and Defender for Office 365, and coordinated at the incident level by Defender XDR.
* **Threat intelligence:** used throughout Defender for Office 365 (sender or URL reputation), Defender XDR (threat analytics), and Defender for Cloud Apps (app risk scoring).
* **Identity risk:** split between Entra ID Protection (cloud identity, Entra ID) and Defender for Identity (on premises Active Directory). This is one of the most heavily tested distinctions on the exam.
* **Endpoint detection:** EDR, antivirus, attack surface reduction, and live response are all part of Defender for Endpoint.
* **Email threats:** phishing, BEC, malware attachments, and malicious URLs are handled by Defender for Office 365 using Safe Attachments, Safe Links, and anti-phishing policies.
* **Cloud application visibility:** handled by Defender for Cloud Apps through Cloud Discovery, the App Catalog, and Conditional Access App Control.
* **Cloud posture and workload protection:** handled by Defender for Cloud through CSPM and CWP, distinct from Defender for Cloud Apps.
* **IoT security:** handled by Defender for IoT using network level visibility for devices that cannot run traditional agents.
* **Insider risk:** handled by Microsoft Purview Insider Risk Management, a compliance capability rather than a Defender security product.
* **Relevant portals:** the unified Defender portal at `security.microsoft.com` for Defender XDR and all connected Defender products plus Entra ID Protection signals, the Microsoft Purview compliance portal at `purview.microsoft.com` for Insider Risk Management, and the Microsoft Entra admin center for identity and Conditional Access configuration.

---

## 14. Key Differences Between Commonly Confused Products

### Defender for Endpoint versus Defender for IoT

Both protect devices, but the deployment model is different. Defender for Endpoint relies on installing a sensor directly on a device capable of running one, such as a Windows laptop or a Linux server. Defender for IoT is used precisely when a device cannot run that kind of agent, such as an industrial PLC, so it relies on passive network traffic analysis instead. If the scenario describes an agent installed on the device, think Defender for Endpoint. If the scenario describes a device that cannot run an agent, think Defender for IoT.

### Defender for Office 365 versus Defender for Cloud Apps

Defender for Office 365 protects the delivery channel: email, links, and attachments arriving through Microsoft 365 messaging and collaboration tools. Defender for Cloud Apps protects the broader use of cloud and SaaS applications after a user is already working inside them, including applications entirely unrelated to Microsoft 365. If the scenario is about a malicious email or a malicious link, think Defender for Office 365. If the scenario is about how an application is being used, or discovering an unknown application, think Defender for Cloud Apps.

### Defender for Identity versus Entra ID Protection

Both are described as identity security products, but they protect different identity systems. Defender for Identity protects on premises Active Directory, monitoring domain controllers for Kerberos, NTLM, and LDAP based attacks. Entra ID Protection protects Microsoft Entra ID, Microsoft's cloud identity platform, monitoring sign ins and accounts for risk indicators such as impossible travel or leaked credentials. If the scenario mentions a domain controller or Active Directory, think Defender for Identity. If it mentions a cloud sign in or Conditional Access risk policy, think Entra ID Protection.

### Defender for Cloud versus Defender XDR

Defender for Cloud protects cloud infrastructure and workloads, focusing on configuration posture (CSPM) and active workload threats (CWP). Defender XDR is the correlation and investigation platform that brings alerts from many products, including Defender for Cloud's workload protection alerts, into a single incident view. Defender for Cloud is a data source about cloud resources; Defender XDR is where that data source's alerts get correlated with everything else.

### Defender XDR versus the individual Defender products

Each individual Defender product (Endpoint, Office 365, Identity, Cloud Apps) is a specialized sensor and console for one part of the environment, with its own deep, product specific investigation tools. Defender XDR does not replace those consoles. It sits above them, correlating their alerts into incidents and providing a shared investigation experience through Advanced Hunting, automated investigation and response, and attack disruption.

### Defender for Cloud Apps versus Defender for Cloud

The names are similar, but the protected surface is different. Defender for Cloud Apps protects SaaS application usage: who is using which application and how data moves through it. Defender for Cloud protects cloud infrastructure: virtual machines, storage, databases, containers, and their configuration and runtime security. A simple memory aid: Defender for Cloud Apps equals applications people use; Defender for Cloud equals infrastructure that runs workloads.

### Microsoft Purview Insider Risk Management versus Defender XDR

Defender XDR is a security operations platform focused on correlating and responding to external and internal technical threats detected by Defender products. Insider Risk Management is a data governance and compliance capability inside Microsoft Purview, focused on the behavior of trusted users with legitimate access, such as data theft by a departing employee. Insider Risk Management cases are managed separately in the Purview compliance portal, and are not automatically part of the Defender XDR incident queue, even though both concepts involve identifying risk.

---

## 15. End to End SOC Scenario

This scenario shows a realistic, multistage attack and how each product contributes to detection, correlation, investigation, and response.

```text
Initial Access
      │
      ▼
Phishing or Malicious Email
      │
      ▼
User Interaction
      │
      ▼
Endpoint Compromise
      │
      ▼
Credential Theft
      │
      ▼
Identity Based Activity
      │
      ▼
Lateral Movement
      │
      ▼
Cloud Application Activity
      │
      ▼
Data Access or Exfiltration
      │
      ▼
Microsoft Defender XDR
      │
      ▼
Correlation
      │
      ▼
Incident Investigation
      │
      ▼
Response and Remediation
```

| Stage | Product Responsible | Telemetry or Signal Generated |
|---|---|---|
| Phishing or malicious email | **Defender for Office 365** | Malicious sender, malicious URL, or malicious attachment identified through Safe Links or Safe Attachments |
| User interaction | **Defender for Office 365** | Click event recorded, or attachment opened by the recipient |
| Endpoint compromise | **Defender for Endpoint** | Suspicious process tree, for example an Office application spawning a script host, followed by payload download and persistence |
| Credential theft | **Defender for Endpoint** and **Defender for Identity** | Credential dumping behavior on the device, followed by abnormal authentication activity against the domain controller |
| Identity based activity | **Defender for Identity** or **Entra ID Protection** | Suspicious Kerberos or NTLM activity on premises, or a risky cloud sign in if the stolen credential is used against Entra ID |
| Lateral movement | **Defender for Identity** | Reconnaissance queries and authentication attempts against additional systems, consistent with Pass-the-Hash or Pass-the-Ticket behavior |
| Cloud application activity | **Defender for Cloud Apps** | Unusual application access, mass file access, or an OAuth grant from a compromised account |
| Data access or exfiltration | **Defender for Cloud Apps**, with **Purview Insider Risk Management** relevant if the activity resembles a trusted user misusing legitimate access | Mass download, unusual sharing, or upload to an external destination |
| Correlation | **Microsoft Defender XDR** | All prior alerts, sharing the same user and device entities, are automatically grouped into a single incident |
| Incident investigation | **SOC Analyst using Defender XDR** | The analyst reviews the reconstructed attack story, the device timeline, Threat Explorer data for the original email, and the identity's sign in and authentication history |
| Response and remediation | **Defender for Endpoint, Defender for Office 365, Defender for Identity or Entra ID Protection, Defender for Cloud Apps** | Isolate the device, remove the malicious email from all mailboxes, disable or reset the compromised account and revoke sessions, and revoke risky OAuth grants or block the cloud application |

This scenario demonstrates the core exam concept: no single product sees the whole attack. Defender for Office 365 sees the beginning, Defender for Endpoint and Defender for Identity see the middle, Defender for Cloud Apps sees the end, and Microsoft Defender XDR is what turns these separate observations into one investigable incident with a coordinated response.
