# Microsoft Security Solutions: SC 200 Study Notes

This note covers nine Microsoft security solutions that a Security Operations Analyst works with day to day. Each product is explained on its own, then the note shows how all nine work together inside Microsoft Defender XDR and Microsoft Sentinel to detect, investigate, and respond to real attacks.

> **A note on accuracy.** This note corrects a few points that are easy to get wrong. Microsoft Entra ID (the identity platform) and Microsoft Entra ID Protection (the risk detection service that runs on top of it) are two different things and are treated separately below. Microsoft 365 Defender was renamed **Microsoft Defender XDR** in 2023, so that is the name used throughout. The classic standalone portals for Defender for Identity and Defender for Cloud Apps have been retired; both products now live inside the Microsoft Defender portal. Microsoft Sentinel and Defender XDR now share a single interface called the unified security operations platform, hosted at the Microsoft Defender portal.

---

## Quick Map: Nine Products, Nine Jobs

| # | Product | One line job |
|---|---|---|
| 1 | Microsoft Defender XDR | Correlates signals from the other Defender products into unified incidents |
| 2 | Defender for Endpoint | Protects devices (EDR and antivirus) |
| 3 | Defender for Office 365 | Protects email and collaboration content |
| 4 | Defender for Identity | Protects on premises Active Directory |
| 5 | Defender for Cloud Apps | Gives visibility and control over SaaS applications (CASB) |
| 6 | Defender for Cloud | Protects cloud infrastructure and workloads (CSPM and CWPP) |
| 7 | Defender for IoT | Protects IoT and OT/industrial devices and networks |
| 8 | Entra ID Protection | Detects risky users and risky sign ins in Microsoft Entra ID |
| 9 | Purview Insider Risk Management | Detects risky behavior by people already inside the organization |

---

## 1. Microsoft Defender XDR

### What it is
Microsoft Defender XDR is Microsoft's extended detection and response (XDR) platform. It is not a sensor that sits on a device or a mailbox; it is the correlation and investigation layer that sits above the other Defender products. Think of it as the brain that receives signals from many sensors and turns them into a single, connected story of an attack. It was previously called Microsoft 365 Defender; the current name is Microsoft Defender XDR, and it is accessed through the Microsoft Defender portal at security.microsoft.com.

### Why it is used
A modern attack rarely stays in one place. It might start as an email, move to a device, then to a user identity, then to a cloud application. If every product raised its own separate alert, an analyst would have to manually connect dozens of unrelated alerts to see the full picture. Defender XDR automatically links these alerts into one incident so the analyst sees the whole attack chain at once, instead of isolated fragments.

### What it protects
Defender XDR itself does not generate raw telemetry. It protects the organization by protecting the analyst's ability to see the full attack: across identities, endpoints, email, cloud apps, and (through native integration) cloud workloads.

### How it works
Each connected Defender product sends its alerts and raw events into a shared data platform. Defender XDR applies correlation logic and machine learning to group related alerts (for example, a phishing email, the device that opened it, and the account that was later used to sign in from an unusual location) into a single incident. Analysts investigate the incident as one unit rather than as separate, disconnected alerts.

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

### Key capabilities and features
* **Incidents**: automatically grouped collections of related alerts, entities, and evidence.
* **Advanced Hunting**: proactive threat hunting using Kusto Query Language (KQL) across all connected data sources.
* **Automated investigation and response (AIR)**: automatically investigates certain alert types and can take remediation actions.
* **Attack disruption**: automatically contains high confidence, in progress attacks (for example ransomware or business email compromise) by disabling an account or isolating a device, even before an analyst reviews the incident.
* **Threat analytics**: reports written by Microsoft threat researchers about active threat actors and campaigns, with related detections and exposure.
* **Custom detection rules**: analyst written KQL queries that run on a schedule and generate alerts automatically.
* **Unified role based access control (RBAC)** across the connected workloads.
* **Hunting graphs and timelines** for visualizing multistage attacks entity by entity.

### Data, signals, and telemetry
Defender XDR does not collect its own primary telemetry. It ingests and correlates telemetry already collected by Defender for Endpoint, Defender for Office 365, Defender for Identity, Entra ID Protection, and Defender for Cloud Apps, and (through the unified platform) can also bring in Defender for Cloud alerts and Microsoft Sentinel data.

### How it detects threats
Detection at the Defender XDR layer is mostly about correlation rather than first detection. It uses graph based analysis, shared threat intelligence, and machine learning to recognize that separate alerts belong to the same campaign, and it can also generate its own correlation based alerts when a pattern across products matches a known attack technique.

### Alerts and incidents it can generate
Defender XDR consumes alerts from the connected products and produces **incidents**: a single case containing every related alert, affected user, affected device, and piece of evidence, along with an automatically generated severity and a suggested story of what happened.

### Integration with Microsoft Defender XDR
This product is the platform, so this heading does not apply in the usual sense. Every other product in this note reports into Defender XDR.

### How it relates to the other products
Defender XDR is the hub. The other eight products (apart from Purview Insider Risk Management, which mostly lives in a separate compliance portal) either feed data into it directly or have their alerts and portals unified inside it.

### Realistic SOC scenario
An analyst opens the Microsoft Defender portal and sees one incident called "Multistage attack involving email, endpoint, and identity." Inside it are a phishing alert from Defender for Office 365, a suspicious PowerShell alert from Defender for Endpoint, and a risky sign in alert from Entra ID Protection, all linked to the same user and the same time window. Instead of triaging three separate alerts, the analyst investigates one incident with the full picture already assembled.

### Important SC 200 exam concepts
* Defender XDR is a correlation and response platform, not a separate sensor.
* Know the difference between an **alert** (one detection) and an **incident** (a group of correlated alerts and entities).
* Advanced Hunting uses **KQL** and runs across shared tables such as `DeviceProcessEvents`, `EmailEvents`, `IdentityLogonEvents`, and `CloudAppEvents`.
* Automated investigation and response (AIR) and attack disruption are distinct: AIR investigates and recommends or performs remediation on a per alert basis; attack disruption automatically contains an entire attack in progress with very high confidence.
* Custom detection rules run on a schedule and can generate new alerts and incidents.

### Key terms to remember
Incident, alert, Advanced Hunting, KQL, automated investigation and response (AIR), attack disruption, threat analytics, custom detection rule, unified RBAC, Microsoft Defender portal, unified security operations platform.

---

## 2. Microsoft Defender for Endpoint

### What it is
Microsoft Defender for Endpoint (MDE) is Microsoft's endpoint protection platform. It combines endpoint detection and response (EDR) with preventive capabilities such as antivirus, attack surface reduction, and vulnerability management.

### Why it is used
Devices (laptops, servers, mobile devices) are one of the most common places where an attack becomes visible: malware execution, suspicious scripts, credential theft tools, and ransomware all run on a device at some point. MDE gives the SOC visibility into what is happening on that device in near real time and gives analysts the tools to stop it.

### What it protects
* Windows client computers and Windows servers
* macOS
* Linux
* iOS and Android (mobile threat defense)
* Network devices, through device discovery capabilities

### How it works
A lightweight sensor built into the operating system (or a lightweight agent on non Windows platforms) continuously reports process, file, network, and user activity to the cloud. Microsoft's cloud analytics compare this behavior against known attack patterns, threat intelligence, and machine learning models, and generate alerts when suspicious behavior is found.

### Key capabilities and features
* **Threat and vulnerability management**: finds missing patches and risky configurations before they are exploited.
* **Attack surface reduction (ASR) rules**: block specific risky behaviors, such as Office applications creating child processes.
* **Next generation protection**: Microsoft Defender Antivirus, using signature and cloud based machine learning detection.
* **Endpoint detection and response (EDR)**: records detailed activity so analysts can see exactly what a threat did.
* **Automated investigation and remediation**: can automatically investigate common alert types and remediate them.
* **Device isolation and live response**: lets an analyst cut a device off the network or run commands on it remotely during an investigation.
* **Threat and Microsoft Threat Experts**: managed hunting service for organizations that want expert assistance.

### Data, signals, and telemetry
Process creation and command line activity, file creation and modification, registry changes, network connections, DNS queries, logon events, PowerShell and script execution, driver loading, and memory level behaviors associated with exploitation or persistence.

### How it detects threats
MDE combines signature based antivirus detection, cloud based machine learning, behavioral analytics on the recorded activity, and threat intelligence matching. It looks for patterns of behavior (for example, an Office application launching a script interpreter, which then downloads and runs a file) rather than relying only on a single malicious file signature.

### Alerts and incidents it can generate
Alerts range from a single malware detection to a full chain of suspicious activity, such as "suspicious process injection" or "ransomware behavior detected." Related alerts on the same device or in the same attack chain are grouped automatically into an incident inside Defender XDR.

### Integration with Microsoft Defender XDR
MDE alerts and raw telemetry feed directly into Defender XDR. Device level detections are automatically correlated with related email, identity, and cloud app activity to build a complete incident.

### How it relates to the other products
MDE is the endpoint layer, complementary to Defender for Identity (which watches the domain controller side of authentication rather than the device) and to Defender for IoT (which covers devices that generally cannot run an MDE sensor at all, such as industrial controllers). MDE's Enterprise IoT discovery feature can also spot unmanaged IoT devices, such as printers and cameras, on the corporate network using the same sensors already deployed for endpoint protection.

### Simple workflow diagram
```text
Malicious document opened by user
            │
            ▼
        WINWORD.EXE
            │
            ▼
       powershell.exe (encoded command)
            │
            ▼
     Suspicious network connection
            │
            ▼
        Payload downloaded
            │
            ▼
   Defender for Endpoint generates alert
            │
            ▼
     Alert sent to Defender XDR
```

### Realistic SOC scenario
An employee opens a malicious attachment. Defender for Endpoint observes WINWORD.EXE launching PowerShell with an encoded command, which then reaches out to an external IP address and downloads a second stage payload. The analyst opens the process tree in the Microsoft Defender portal, confirms the chain is malicious, isolates the device, stops the malicious process, and uses Advanced Hunting to search the whole organization for the same command line pattern on other devices, so any additional compromised machines can be found and contained.

### Important SC 200 exam concepts
* Understand attack surface reduction rules and what behaviors they can block.
* Know the difference between automated investigation and remediation (per device, per alert) and attack disruption (organization wide, high confidence containment run by Defender XDR).
* Device isolation, live response, and file quarantine are core remediation actions an analyst should know how and when to use.
* Threat and vulnerability management findings feed into an organization's exposure and Secure Score.

### Key terms to remember
EDR, attack surface reduction, threat and vulnerability management, device isolation, live response, automated investigation and remediation, process tree, Enterprise IoT discovery.

---

## 3. Microsoft Defender for Office 365

### What it is
Microsoft Defender for Office 365 (MDO) is Microsoft's security solution for protecting email and collaboration content in Microsoft 365 from phishing, malware, and other threats delivered through messages, links, and files.

### Why it is used
Email remains the most common way attackers gain initial access into an organization. MDO exists to catch malicious messages, links, and attachments before, during, and after delivery, and to give analysts a way to investigate what happened to those messages afterward.

### What it protects
* Exchange Online mailboxes (email)
* Links and URLs shared anywhere in Microsoft 365, including inside the message body
* Attachments and files
* Microsoft Teams messages and shared files
* SharePoint Online and OneDrive for Business content

### How it works
Every inbound message and every collaboration file is evaluated using sender reputation, content analysis, URL analysis, and file analysis before it reaches the user, and continues to be monitored after delivery so a link or file that becomes malicious later can still be blocked or removed.

```text
Incoming email
      │
      ▼
Sender / URL / Attachment analysis
      │
      ▼
Threat intelligence + machine learning
      │
      ▼
Risk decision
   ┌──────┼───────┐
   ▼      ▼       ▼
 Allow  Quarantine  Block
```

### Key capabilities and features
* **Safe Attachments**: opens suspicious attachments in an isolated, protected environment (detonation) to see what they actually do before delivering them to the user.
* **Safe Links**: rewrites and checks URLs at the time they are clicked, not just at delivery time, so a link that was safe when the email arrived but becomes malicious later can still be blocked.
* **Anti phishing protection**: detects impersonation of users and domains, spoofing, and unusual sender behavior; includes mailbox intelligence that learns a user's normal contacts.
* **Zero hour auto purge (ZAP)**: removes a message from mailboxes after delivery if it is later found to be malicious.
* **Threat Explorer**: an investigation and search tool for email related threats across the whole tenant.
* **Automated investigation and response (AIR)**: automatically investigates alerts such as a reported phishing message, finds every related message sent to other users, and recommends or takes remediation action.
* **Attack simulation training**: lets security teams run realistic phishing simulations against their own users for awareness training.

MDO comes in two license tiers. Plan 1 provides the core protection technologies (Safe Links, Safe Attachments, anti phishing, real time detections). Plan 2 adds the investigation and hunting tools that a SOC actually uses day to day: Threat Explorer, automated investigation and response, threat trackers, and campaign views.

### Data, signals, and telemetry
Sender reputation and authentication signals (SPF, DKIM, DMARC), message content and metadata, URL reputation and detonation results, attachment detonation results, user click behavior, and organization wide mail flow patterns.

### How it detects threats
MDO does not rely on message text alone. It combines sender analysis, URL reputation and detonation, attachment detonation in a sandboxed environment, machine learning models trained on phishing patterns, and Microsoft's broader threat intelligence to decide whether a message, link, or file is dangerous.

### Alerts and incidents it can generate
Alerts include phishing detected, malware detected in an attachment, a user clicked a malicious URL, and a suspicious impersonation attempt. Because phishing campaigns often target many users with the same message, MDO can generate a single alert covering the whole campaign rather than one alert per mailbox.

### Integration with Microsoft Defender XDR
MDO alerts flow directly into Defender XDR, where a phishing email alert can be automatically linked to the device that opened the attachment and to the identity that was later used to sign in, producing one connected incident.

### How it relates to the other products
MDO protects the email and collaboration layer, which is a different layer from Defender for Cloud Apps, which protects SaaS application usage more broadly (see the comparison below). MDO commonly hands off to Defender for Endpoint once a malicious attachment is opened, and to Entra ID Protection or Defender for Identity if stolen credentials from a phishing message are later used to sign in.

### Realistic SOC scenario
Dozens of employees report the same suspicious email through the built in report button. The analyst opens Threat Explorer, searches for the sender and subject, and finds that the same message was delivered to 40 mailboxes across three departments. Using AIR, the analyst confirms the message is malicious and approves an organization wide purge, removing it from every mailbox, including ones where it had not yet been reported.

### Important SC 200 exam concepts
* Know the difference between **Safe Links** (protects against malicious URLs) and **Safe Attachments** (protects against malicious files).
* Understand **zero hour auto purge (ZAP)**: it removes already delivered malicious mail.
* Threat Explorer (sometimes called Explorer) is the primary investigation tool for email threats; know what questions it can answer (who received a message, who clicked a link, was it delivered or quarantined).
* Automated investigation and response for email can find and remediate every copy of a malicious message across the tenant, not just the reported one.

### Key terms to remember
Safe Links, Safe Attachments, zero hour auto purge, Threat Explorer, anti phishing policy, mailbox intelligence, business email compromise (BEC), impersonation protection, attack simulation training.

---

## 4. Microsoft Defender for Identity

### What it is
Microsoft Defender for Identity (MDI) is Microsoft's security solution for monitoring and protecting **on premises Active Directory**. It watches authentication and directory activity around domain controllers to detect identity based attacks.

### Why it is used
Active Directory is the backbone of identity in most enterprise networks, and it is a favorite target for attackers who want to move laterally and eventually gain domain level control. Traditional endpoint tools do not see the full picture of directory queries, Kerberos activity, and authentication patterns across the domain; MDI is built specifically to watch that layer.

### What it protects
On premises Active Directory Domain Services (AD DS), including domain controllers, Active Directory Federation Services (AD FS) servers, and Active Directory Certificate Services (AD CS) servers where supported.

### How it works
A Defender for Identity sensor is installed directly on domain controllers (and supported AD FS or AD CS servers). The sensor observes authentication traffic and directory activity without needing an agent on every client computer, and sends the relevant signals to the Microsoft Defender portal for analysis.

```text
User authentication
        │
        ▼
   Domain Controller
        │
        ▼
   MDI sensor observes:
     Kerberos / NTLM / LDAP activity
     Account and group activity
     Reconnaissance queries
        │
        ▼
   Microsoft Defender XDR
        │
        ▼
   Behavioral analysis → Alert if suspicious
```

### Key capabilities and features
* Detection of reconnaissance activity, such as an account enumerating domain admins, computers, or groups.
* Detection of credential theft techniques, including Pass the Hash and Pass the Ticket.
* Detection of Kerberoasting, an attack that targets service accounts with weak passwords through Kerberos service tickets.
* Detection of Golden Ticket and other domain dominance techniques, which rely on stealing the KRBTGT account hash to forge Kerberos tickets.
* Detection of lateral movement patterns between machines using stolen credentials.
* Security posture assessments for Active Directory, highlighting risky configurations.

### Data, signals, and telemetry
Kerberos and NTLM authentication events, LDAP queries, logon events, directory replication activity, and behavioral baselines of normal user, device, and account activity across the domain.

### How it detects threats
MDI does not look for a single malicious command. It builds a behavioral profile for each user, device, and resource in the environment and flags activity that deviates from that normal pattern, combined with detection logic for specific known attack techniques (such as Kerberoasting or Golden Ticket abuse).

### Alerts and incidents it can generate
Alerts include suspicious authentication, account enumeration and reconnaissance, lateral movement, privilege escalation, and domain dominance activity such as DCSync style replication requests from an unexpected source.

### Integration with Microsoft Defender XDR
MDI no longer has its own separate portal; it is fully integrated into the Microsoft Defender portal, so its alerts are automatically part of Defender XDR incidents alongside endpoint, email, and cloud identity signals.

### How it relates to the other products
This is one of the most tested distinctions on the SC 200 exam.

| | Defender for Identity | Entra ID Protection |
|---|---|---|
| Watches | On premises Active Directory | Microsoft Entra ID (cloud identity) |
| Deployed as | Sensor on domain controllers | Cloud service, no sensor to install |
| Typical detections | Kerberoasting, Pass the Hash, Golden Ticket, AD reconnaissance | Risky sign in, leaked credentials, impossible travel |
| Think of it when the question mentions | Domain controller, LDAP, Kerberos, NTLM, domain admin | Risky user, risky sign in, Conditional Access, Entra ID |

### Simple workflow diagram
See the diagram in the "How it works" section above.

### Realistic SOC scenario
An attacker compromises a low privileged employee account and starts querying Active Directory for the members of the Domain Admins group, then attempts to authenticate to several servers they have never touched before. MDI flags the reconnaissance and the unusual authentication pattern, generates alerts, and Defender XDR links them into a single incident showing the account moving from reconnaissance to lateral movement. The analyst disables the account and forces a password reset while checking whether the KRBTGT account needs to be reset twice, following standard Golden Ticket remediation guidance.

### Important SC 200 exam concepts
* MDI protects **on premises AD**, not Entra ID; this is the single most common point of confusion on the exam.
* Know the sensor deployment model: sensors run on domain controllers (and supported AD FS or AD CS servers), not on every endpoint.
* Be able to recognize Pass the Hash, Pass the Ticket, Kerberoasting, and Golden Ticket by their description, not just by name.
* MDI's classic standalone portal has been retired; everything is managed from the Microsoft Defender portal now.

### Key terms to remember
Domain controller, AD DS, Kerberos, NTLM, LDAP, Pass the Hash, Pass the Ticket, Kerberoasting, Golden Ticket, KRBTGT, lateral movement, domain dominance, reconnaissance.

---

## 5. Microsoft Defender for Cloud Apps

### What it is
Microsoft Defender for Cloud Apps (MDCA) is Microsoft's Cloud Access Security Broker (CASB). Its job is visibility and control over how the organization's SaaS and cloud applications are actually being used.

### Why it is used
Employees use many cloud applications beyond Microsoft 365, sometimes without IT's knowledge (Shadow IT). Security teams need to know which applications are being used, whether sensitive data is flowing into or out of them, and whether an account is behaving suspiciously inside one of those applications.

### What it protects
SaaS applications and cloud services used by the organization, for example Microsoft 365, Salesforce, Google Workspace, Dropbox, and Box, along with the sanctioned and unsanctioned traffic flowing to them.

### How it works
MDCA works through four pillars: it discovers which cloud apps are in use, investigates and scores the risk of those apps, controls access to them, and protects data and accounts inside sanctioned apps through policies.

```text
Firewall / proxy logs or Defender for Endpoint signals
            │
            ▼
      Cloud Discovery
            │
            ▼
   App Catalog risk scoring
            │
            ▼
   Sanction / unsanction decision
            │
            ▼
   Conditional Access App Control (session control)
            │
            ▼
   Activity policies / anomaly detection
```

### Key capabilities and features
* **Cloud Discovery**: analyzes network traffic logs (or signals already collected by Defender for Endpoint) to build an inventory of every cloud app being used, including unsanctioned Shadow IT apps.
* **Cloud App Catalog**: scores thousands of cloud apps on security and compliance characteristics so admins can decide whether to sanction or block them.
* **Conditional Access App Control**: works with Microsoft Entra Conditional Access to apply real time, session level controls, such as blocking a download or forcing read only access, without requiring a full app connector.
* **App connectors (API based protection)**: connect directly to sanctioned apps such as Microsoft 365, Salesforce, or Box for deeper visibility and control, including retroactive scanning.
* **Activity policies and anomaly detection**: flag unusual behavior such as impossible travel between two cloud app sign ins, mass download activity, or unusual file sharing.
* **OAuth app governance**: reviews and can restrict permissions granted to third party applications connected to Microsoft 365.
* **SaaS Security Posture Management (SSPM)**: assesses the security configuration of connected SaaS apps and recommends improvements.

### Data, signals, and telemetry
Firewall and proxy logs (for Cloud Discovery), API data pulled directly from sanctioned applications through app connectors, and session data captured through Conditional Access App Control's reverse proxy.

### How it detects threats
MDCA combines rule based activity policies with anomaly detection models (for example, detecting a sign in from two impossibly distant locations within a short time, or an account suddenly downloading far more files than normal) and threat intelligence about risky IP addresses and known malicious OAuth applications.

### Alerts and incidents it can generate
Alerts include impossible travel, mass download or mass deletion of files, unusual admin activity, malware detected in a connected cloud storage app, and risky OAuth application consent grants.

### Integration with Microsoft Defender XDR
MDCA's classic standalone portal was retired in 2024; its alerts, policies, and Cloud Discovery data are now fully part of the Microsoft Defender portal, so its alerts are automatically correlated with endpoint, email, and identity alerts inside Defender XDR incidents.

### How it relates to the other products
MDCA is often confused with two other products; both distinctions matter for the exam.

* **MDO vs MDCA**: MDO protects the email and collaboration content path (a message, a link, an attachment). MDCA protects the broader pattern of how SaaS applications are used and accessed, across many apps, not just Microsoft 365 content.
* **MDCA vs Defender for Cloud**: MDCA protects SaaS **applications** (what users do inside apps like Salesforce or Dropbox). Defender for Cloud protects cloud **infrastructure and workloads** (virtual machines, containers, databases). The names are similar; the layers are completely different.

### Realistic SOC scenario
An analyst receives an anomaly detection alert: a user account downloaded 300 files from SharePoint within ten minutes, then signed in from a country the user has never visited, all within the same hour. The analyst pivots into MDCA's activity log, confirms the pattern matches account compromise rather than normal behavior, and uses Conditional Access App Control to immediately restrict the session while the account is investigated and its credentials are reset.

### Important SC 200 exam concepts
* Know the four pillars: discover, investigate, control, protect.
* Cloud Discovery can work from existing Defender for Endpoint signals, without needing separate firewall log uploads.
* Conditional Access App Control provides real time, session level protection and does not require an API connector to the app.
* Shadow IT and impossible travel are classic exam scenario keywords for this product.

### Key terms to remember
CASB, Cloud Discovery, Shadow IT, Cloud App Catalog, Conditional Access App Control, app connector, OAuth app governance, SSPM, impossible travel, anomaly detection policy.

---

## 6. Microsoft Defender for Cloud

### What is it
Microsoft Defender for Cloud is Microsoft's cloud security posture and workload protection platform. It secures cloud infrastructure and workloads themselves, across Azure and, through connectors, other clouds such as AWS and GCP, as well as on premises servers connected through Azure Arc.

### Why it is used
Cloud environments are made of many moving parts: virtual machines, storage accounts, databases, containers, and Kubernetes clusters. Misconfigurations (like an exposed storage account) and active attacks against running workloads both need to be found quickly, and Defender for Cloud is built to do both.

### What it protects
Azure virtual machines, Azure SQL and other databases, storage accounts, containers and Kubernetes (AKS), and, through multicloud connectors, workloads running in AWS and Google Cloud, plus on premises servers registered through Azure Arc.

### How it works
Defender for Cloud continuously assesses the configuration of connected resources against security best practices and benchmarks, and separately monitors running workloads for signs of active attacks, combining both views into a single risk picture. Together, these two capabilities are often described using the industry term **CNAPP** (Cloud Native Application Protection Platform).

### Key capabilities and features
Two concepts matter most for the exam.

**CSPM (Cloud Security Posture Management)**: answers the question "how securely is my cloud environment configured?" It continuously scans resource configurations and produces prioritized security recommendations and a Secure Score.

```text
Storage Account
   ├── Public access enabled   → risky recommendation
   ├── Encryption enabled      → compliant
   └── Logging enabled         → compliant
```

**CWPP (Cloud Workload Protection Platform)**: answers the question "is my cloud workload actively being attacked?" It monitors running workloads such as VMs, containers, databases, and storage for real time threats and generates security alerts.

```text
Azure VM
   ↓
Suspicious process detected
   ↓
Alert generated
```

Other capabilities include regulatory compliance dashboards, DevSecOps tooling that finds misconfigurations in code before deployment, and workload specific protection plans (Defender for Servers, Defender for Storage, Defender for Containers, Defender for SQL, Defender for Key Vault, Defender for APIs, and others).

### Data, signals, and telemetry
Resource configuration data collected from the cloud platform itself, workload level telemetry from the Defender for Endpoint sensor deployed on protected servers, network and process activity inside containers, and cloud platform audit logs.

### How it detects threats
Posture issues are found by continuously comparing resource configuration against security baselines and compliance standards. Active threats are found using behavioral analytics and threat intelligence applied to workload telemetry, similar in spirit to how Defender for Endpoint analyzes device activity, but scoped to cloud resources.

### Alerts and incidents it can generate
Security recommendations for posture issues (for example, a publicly exposed storage account or missing encryption) and security alerts for active threats (for example, a suspicious process running on a VM, or an unusual sign in to a management plane).

### Integration with Microsoft Defender XDR
Defender for Cloud integrates with the Microsoft Defender portal and the wider Microsoft security ecosystem, so its alerts can be correlated with other Defender XDR signals as part of a unified investigation, giving a SOC analyst visibility from a cloud workload alert all the way to an identity or endpoint alert in the same incident.

### How it relates to the other products
The most important distinction to remember: Defender for Cloud protects cloud **infrastructure and workloads**. Defender for Cloud Apps protects **SaaS application usage**. Defender XDR is the correlation platform that both can feed into; Defender for Cloud is not itself a correlation engine.

```text
Defender for Cloud       →  Cloud infrastructure and workloads (VMs, storage, containers, databases)
Defender for Cloud Apps  →  SaaS applications and cloud application usage (Salesforce, Dropbox, M365)
```

### Realistic SOC scenario
A cloud administrator accidentally leaves a storage account open to public access. Defender for Cloud raises a high severity security recommendation. The recommendation is prioritized and assigned to the cloud team, who remediate the misconfiguration. Separately, in the same week, Defender for Cloud detects a suspicious process running on an internet facing VM and raises a security alert; the SOC analyst investigates the alert, confirms it as a coin mining process, and isolates the VM.

### Important SC 200 exam concepts
* Know the difference between CSPM (posture, "how secure is my configuration?") and CWPP (workload protection, "am I being attacked right now?").
* Defender for Cloud is multicloud capable through connectors, not Azure only.
* Secure Score and security recommendations are CSPM concepts; security alerts are CWPP concepts.

### Key terms to remember
CSPM, CWPP, CNAPP, Secure Score, security recommendation, regulatory compliance, Azure Arc, multicloud, DevSecOps.

---

## 7. Microsoft Defender for IoT

### What is it
Microsoft Defender for IoT is Microsoft's security solution for Internet of Things (IoT) and Operational Technology (OT) environments, including industrial control systems and SCADA networks.

### Why it is used
Many IoT and OT devices, such as programmable logic controllers (PLCs), sensors, cameras, and medical devices, cannot run a traditional security agent. Without network level visibility, these devices are effectively invisible to the SOC, even though a compromise on one of them can be extremely damaging (for example, disrupting a factory floor).

### What it protects
Two distinct scenarios, and this distinction is important for the exam.

* **OT and industrial networks**: PLCs, SCADA systems, sensors, and industrial equipment, typically monitored through dedicated network sensors that passively watch OT network traffic.
* **Enterprise IoT devices**: everyday connected devices on the corporate network, such as printers, VoIP phones, and smart cameras, discovered using the existing Defender for Endpoint sensor already deployed for endpoint protection, without needing a separate OT style sensor.

### How it works
For OT environments, a network sensor is deployed to passively observe OT network traffic (commonly through a mirrored network port), since installing an agent directly on a PLC is usually not possible. The sensor builds a device inventory and baseline of normal communication, then flags anomalies. For Enterprise IoT, Defender for Endpoint's existing network discovery capability identifies IoT devices already reachable from managed endpoints.

```text
OT / IoT Network
        │
   ┌────┴────┐
   ▼         ▼
  PLC      Sensor (network device)
   │         │
   └────┬────┘
        ▼
Defender for IoT network sensor
        │
        ▼
Device inventory + anomaly detection
        │
        ▼
Alert sent to SOC (via Defender portal)
```

### Key capabilities and features
* Passive, agentless network monitoring for OT and industrial protocols.
* Automatic device inventory and asset discovery for OT and IoT devices.
* Vulnerability assessment for discovered devices.
* Detection of unauthorized devices, unusual protocol activity, and known OT specific attack techniques.
* Enterprise IoT discovery integrated with Defender for Endpoint, requiring no separate OT sensor for typical office IoT devices.

### Data, signals, and telemetry
Network traffic captured through port mirroring or network taps on OT networks, industrial protocol activity (for example, protocols used by PLCs and SCADA systems), and device level metadata such as make, model, and firmware version.

### How it detects threats
Detection relies heavily on baselining normal device communication patterns on the OT network and flagging deviations, alongside signatures for known OT specific attack techniques and vulnerability data about discovered devices.

### Alerts and incidents it can generate
Alerts include newly discovered or unauthorized devices, unusual communication between an IT network and an OT network, known malicious traffic patterns, and vulnerable device configurations.

### Integration with Microsoft Defender XDR
Defender for IoT alerts, particularly Enterprise IoT alerts generated through the Defender for Endpoint sensor, surface in the Microsoft Defender portal and can be correlated with other Defender XDR signals, extending Defender XDR's protection into OT and IoT environments.

### How it relates to the other products
This is another commonly tested distinction.

| | Defender for Endpoint | Defender for IoT |
|---|---|---|
| Deployment | Software sensor installed on the device's operating system | Passive network sensor watching traffic (OT), or existing MDE sensor discovery (Enterprise IoT) |
| Typical device | Windows, macOS, Linux computers and servers that can run an agent | PLCs, SCADA systems, cameras, medical devices, and other devices that usually cannot run an agent |
| Visibility source | Direct OS level telemetry | Network traffic patterns and industrial protocol analysis |

### Realistic SOC scenario
An attacker compromises a workstation on the corporate network and attempts to reach a PLC on the isolated OT network. Defender for IoT's network sensor observes unexpected traffic from the corporate segment into the OT segment, using a protocol that the PLC does not normally receive from that source, and raises an alert. The analyst uses this visibility to confirm lateral movement toward the OT environment and works with the operations team to block the traffic at the network boundary.

### Important SC 200 exam concepts
* Know that OT monitoring is agentless and network based, because most OT devices cannot run a security agent.
* Enterprise IoT discovery reuses the Defender for Endpoint sensor and does not require a dedicated OT sensor for ordinary office IoT devices.
* Defender for IoT extends Defender XDR visibility into environments that endpoint and identity products cannot reach directly.

### Key terms to remember
OT, SCADA, PLC, network sensor, port mirroring, agentless monitoring, Enterprise IoT, device inventory, industrial protocol.

---

## 8. Microsoft Entra ID Protection

### Context: Microsoft Entra ID vs Entra ID Protection
Before covering Entra ID Protection, it helps to be precise about what Microsoft Entra ID itself is, since the two are often blended together in study material and they are not the same thing.

**Microsoft Entra ID** (formerly Azure Active Directory) is Microsoft's cloud based identity and access management platform. It manages users, groups, applications, service principals, and devices, and it provides authentication, authorization, single sign on, and Conditional Access. Entra ID is the identity **platform**; it is not, by itself, a threat detection product.

**Microsoft Entra ID Protection** is the risk detection service that runs on top of Entra ID. It is the product that actually corresponds to this section of the note.

### What it is
Microsoft Entra ID Protection is Microsoft's identity risk detection service for **cloud identities** in Microsoft Entra ID. It continuously evaluates sign ins and user accounts and assigns them a risk level.

### Why it is used
Stolen or compromised cloud credentials are one of the most common ways attackers gain access to Microsoft 365 and other cloud resources. Entra ID Protection exists to spot the signs of compromise, such as impossible travel or leaked credentials, and to feed that risk information into access decisions automatically.

### What it protects
Cloud identities in Microsoft Entra ID: user accounts and the sign in sessions associated with them.

### How it works
Entra ID Protection analyzes every sign in and every account against a large set of risk signals, using Microsoft's threat intelligence and machine learning, and produces two separate risk scores: **user risk** (how likely it is that this account itself is compromised) and **sign in risk** (how likely it is that this specific sign in attempt is not the legitimate user).

```text
User
  │  Sign in attempt
  ▼
Microsoft Entra ID
  │
  ├── Username / password
  ├── Location
  ├── Device state
  ├── Risk signals (leaked credentials, anomalous travel, malware linked IP, unfamiliar properties)
  ▼
Entra ID Protection risk evaluation
  │
  ▼
Conditional Access decision → Allow / Require MFA / Block
```

### Key capabilities and features
* **Risky user detection**: flags accounts showing signs of compromise, such as leaked credentials found in a breach data set.
* **Risky sign in detection**: flags individual sign in attempts, based on signals such as impossible travel, sign ins from anonymous IP addresses or IP addresses linked to malware, and unfamiliar sign in properties.
* **Risk based Conditional Access policies**: automatically require multifactor authentication, force a password change, or block access entirely based on the calculated risk level, without an analyst having to intervene manually.
* **Risk investigation reports**: dashboards that let analysts review risky users and risky sign ins, confirm or dismiss risk, and see the reasoning behind a risk score.

### Data, signals, and telemetry
Sign in logs, IP address reputation and geolocation, known leaked credential data sets, device compliance state, and behavioral baselines of a user's typical sign in patterns.

### How it detects threats
Entra ID Protection combines Microsoft's global threat intelligence about compromised credentials and malicious IP addresses with machine learning models that learn what normal sign in behavior looks like for each user, then flags deviations as risky.

### Alerts and incidents it can generate
Risky user alerts, risky sign in alerts, and (through Conditional Access integration) automatic enforcement actions such as forcing MFA or blocking a sign in outright.

### Integration with Microsoft Defender XDR
Entra ID Protection risk detections are surfaced in the Microsoft Defender portal and are correlated with other Defender XDR signals, so a risky sign in can be automatically linked to a related phishing email or endpoint compromise in the same incident.

### How it relates to the other products
The clearest comparison is with Defender for Identity, shown in the table in section 4 above: Defender for Identity watches on premises Active Directory through a sensor on domain controllers, while Entra ID Protection watches cloud identity sign ins with no sensor required.

### Realistic SOC scenario
A user's credentials are leaked in a third party data breach. Entra ID Protection flags the account as a risky user. Days later, a sign in attempt occurs from a country the user has never accessed the system from, immediately after a sign in from their normal location, which is flagged as an impossible travel risky sign in. Because a risk based Conditional Access policy is in place, the suspicious sign in is automatically blocked before the analyst even opens the alert; the analyst then confirms the account was compromised and forces a password reset and session revocation.

### Important SC 200 exam concepts
* Distinguish **user risk** (about the account) from **sign in risk** (about a specific sign in attempt); these are separate scores.
* Risk based Conditional Access policies can act automatically, without waiting for analyst review.
* Entra ID Protection covers Entra ID (cloud identity) only, never on premises Active Directory.
* Common risk detections to recognize by description: impossible travel, anonymous IP address, malware linked IP address, leaked credentials, unfamiliar sign in properties.

### Key terms to remember
User risk, sign in risk, risky user, risky sign in, impossible travel, leaked credentials, Conditional Access, risk based policy, Microsoft Entra admin center.

---

## 9. Microsoft Purview Insider Risk Management

### What it is
Microsoft Purview Insider Risk Management (IRM) is a compliance solution that identifies, investigates, and helps manage potentially risky activity performed by people who are already inside the organization, meaning people who already have legitimate access.

### Why it is used
Not every risk comes from an external attacker. An employee preparing to leave the company might download large amounts of sensitive data before their last day. A well meaning employee might accidentally send confidential files to the wrong external recipient. A privileged user's account might be compromised and used to exfiltrate data in a way that looks like insider activity from a technical standpoint. IRM exists to detect these patterns, which are often invisible to purely technical, adversary focused security tools.

### What it protects
People and data: it protects the organization from data leakage, intellectual property theft, and policy violations carried out (intentionally or not) by employees, contractors, or other insiders, including insiders whose accounts have been compromised.

### How it works
IRM correlates signals from across Microsoft 365 (file activity, email, Teams sharing) with contextual signals such as HR data (for example, an upcoming resignation date) and endpoint activity, then runs this combined signal set through machine learning models and built in risk indicators to score users and surface risky sequences of behavior. Policies define which users are in scope and which indicators to watch for. Users are pseudonymized by default, so an analyst investigating an early stage alert sees an anonymized identifier rather than the real name, until the case is escalated to someone with the appropriate permission to reveal identity. This is a deliberate privacy by design control.

```text
User activity
   ├── SharePoint / OneDrive file activity
   ├── Exchange email activity
   ├── Microsoft Teams activity
   ├── Endpoint activity (device indicators)
   └── HR signals (for example, resignation date)
           │
           ▼
   Microsoft Purview Insider Risk Management
           │
           ▼
   Risk scoring against policy indicators
           │
           ▼
   Alert (pseudonymized) → Case → Investigation → Action
```

### Key capabilities and features
* **Policy templates**: prebuilt scenarios such as data theft by departing employees, data leaks, and security policy violations.
* **Sequence detection**: recognizes multi step patterns, for example a user downloading files, renaming or obfuscating them, then uploading them to personal cloud storage shortly before their resignation date.
* **Adaptive Protection**: automatically applies stricter data loss prevention (DLP) controls to a user whose insider risk level rises, tightening enforcement without a manual policy change.
* **Content explorer**: lets authorized investigators review the specific files and messages associated with an alert.
* **Third party data connectors**: can import pre processed insider risk indicators from other systems, including Microsoft Sentinel, to extend coverage beyond native Microsoft 365 signals.
* **Pseudonymization and role based access**: protects user privacy during early stage triage.

### Data, signals, and telemetry
SharePoint and OneDrive file activity, Exchange Online email activity, Microsoft Teams sharing activity, device level indicators from Microsoft Defender for Endpoint, Microsoft Entra organizational data such as resignation dates (when the organization agrees to share it), and imported third party indicators.

### How it detects threats
IRM combines rule based policy indicators (defined thresholds and behaviors) with machine learning based sequence detection that recognizes multi step patterns of risky behavior, rather than flagging a single action in isolation.

### Alerts and incidents it can generate
Alerts and cases for potential data theft, data leakage, and security policy violations, each built from a correlated sequence of user activity rather than one isolated event.

### Integration with Microsoft Defender XDR
This is an important distinction for the exam. Insider Risk Management is managed and investigated in the **Microsoft Purview portal**, a compliance focused portal, and it is not one of the workloads that natively generates Defender XDR incidents in the same way Defender for Endpoint or Defender for Office 365 do. It does share underlying signals with the Microsoft 365 ecosystem, and Microsoft has been unifying parts of the alert and investigation experience, but a SOC analyst should think of IRM as running alongside Defender XDR, in its own governance workflow, rather than inside a Defender XDR incident by default.

### How it relates to the other products
Purview Insider Risk Management is fundamentally different in purpose from the Defender product family.

* The **Defender** products are primarily built to detect and respond to **external adversary techniques**: malware, phishing, credential theft, lateral movement, and cloud attacks, mostly from a technical, security operations point of view.
* **Purview Insider Risk Management** is built to detect **risky behavior and intent by people who already have legitimate access**, which is as much a compliance, HR, and legal concern as it is a security concern, and it is investigated by a different (though sometimes overlapping) set of stakeholders.
* The two can intersect: a compromised account being used to exfiltrate data might trigger both a Defender for Cloud Apps or Defender for Endpoint alert (technical compromise) and an Insider Risk Management case (data exfiltration pattern), and in that situation the security and compliance teams typically collaborate.

### Realistic SOC scenario
An employee who submitted their resignation two weeks ago begins downloading unusually large volumes of files from SharePoint, then uploads several of them to a personal cloud storage account. IRM's sequence detection recognizes the pattern (recent resignation, plus bulk download, plus external upload) and raises a case. Because the user is pseudonymized at this stage, the assigned investigator reviews the behavioral pattern without seeing the employee's real identity, then escalates the case to someone with permission to reveal the identity and involve HR and legal for next steps.

### Important SC 200 exam concepts
* IRM is a **Purview** compliance capability, managed in the Purview portal, not a Defender XDR workload in the same sense as the other Defender products.
* Understand pseudonymization: it protects user privacy during early investigation stages and is a deliberate design choice, not a limitation.
* Adaptive Protection dynamically tightens DLP enforcement based on a user's current risk level.
* Insider risk is not only about malicious intent; it explicitly includes accidental data leakage and compromised accounts.

### Key terms to remember
Insider risk, pseudonymization, Adaptive Protection, policy indicator, sequence detection, Content explorer, Microsoft Purview portal, data exfiltration.

---

## Overall Architecture: How These Products Work Together

```text
        Users / Devices / Applications / Email / Identity / Cloud / IoT / OT
                                     │
                                     ▼
                        Microsoft Security Signals
                                     │
     ┌───────────┬───────────┬──────┴───────┬──────────────┬──────────────┐
     ▼           ▼           ▼              ▼              ▼              ▼
 Defender    Defender    Defender      Entra ID       Defender       Defender
   for          for          for       Protection       for            for
 Endpoint    Office 365   Identity   (cloud identity)  Cloud Apps     Cloud / IoT
 (devices)    (email)   (on prem AD)                    (SaaS)     (workloads / OT)
     │           │           │              │              │              │
     └───────────┴───────────┴──────┬───────┴──────────────┴──────────────┘
                                     ▼
                       Microsoft Defender XDR
                    (correlation, incidents, hunting)
                                     │
                                     ▼
              Microsoft Sentinel (unified security operations platform)
           adds broader log sources, SIEM detection rules, workbooks
                                     │
                                     ▼
                          Correlated Incident
                                     │
                                     ▼
                          SOC Investigation
                     (Advanced Hunting, incident graph, entities)
                                     │
                       ┌─────────────┴─────────────┐
                       ▼                            ▼
          Response / Remediation          Escalation to Purview
       (isolate device, disable account,   Insider Risk Management
        block sender, revoke sessions,     (when a case involves
        require MFA)                       insider intent or data
                                            governance concerns)
```

Microsoft Purview Insider Risk Management sits slightly apart from this diagram on purpose: it lives in the Purview compliance portal and focuses on human behavior and data governance rather than adversary technique detection, but it draws on some of the same underlying Microsoft 365 and endpoint signals and can be triggered in parallel with a Defender XDR incident.

---

## 1. Product Comparison Table

| Product | Primary Purpose | Protects | Main Signals/Data | Key SOC Use |
|---|---|---|---|---|
| Microsoft Defender XDR | Correlate alerts into unified incidents and support hunting | The analyst's visibility across the whole environment | Alerts and telemetry from every connected Defender product | Investigate incidents, run Advanced Hunting, review automated response actions |
| Defender for Endpoint | Endpoint detection and response, antivirus, vulnerability management | Windows, macOS, Linux, mobile devices, servers | Process, file, registry, network, and logon activity on devices | Investigate process trees, isolate devices, remediate malware |
| Defender for Office 365 | Protect email and collaboration content | Exchange Online, Teams, SharePoint, OneDrive | Message content, URLs, attachments, sender reputation, click data | Investigate phishing campaigns, purge malicious mail, review Threat Explorer |
| Defender for Identity | Detect attacks against on premises Active Directory | Domain controllers, AD DS, AD FS, AD CS | Kerberos, NTLM, and LDAP activity from domain controller sensors | Investigate reconnaissance, lateral movement, and domain compromise |
| Defender for Cloud Apps | CASB visibility and control over SaaS applications | SaaS applications and cloud application usage | Cloud Discovery logs, app connector API data, session data | Investigate Shadow IT, anomalous SaaS activity, restrict risky sessions |
| Defender for Cloud | Cloud security posture management and workload protection | Cloud infrastructure and workloads (VMs, storage, containers, databases) | Resource configuration data, workload telemetry, platform audit logs | Remediate misconfigurations, investigate active workload attacks |
| Defender for IoT | Protect IoT and OT/industrial devices and networks | PLCs, SCADA systems, sensors, enterprise IoT devices | Network traffic, industrial protocol activity, device inventory | Investigate unauthorized OT devices and traffic crossing IT to OT boundary |
| Entra ID Protection | Detect risky users and risky sign ins in cloud identity | Microsoft Entra ID user accounts and sign ins | Sign in logs, IP reputation, leaked credential data, behavior baselines | Investigate risky sign ins, confirm compromised accounts, enforce Conditional Access |
| Purview Insider Risk Management | Detect risky behavior by people with legitimate access | People and organizational data | SharePoint, OneDrive, Exchange, Teams, endpoint, and HR signals | Investigate potential data theft or leakage by insiders, coordinate with HR and legal |

---

## 2. Which Product Should I Think Of?

```text
Endpoint compromise                → Defender for Endpoint
Email / phishing / malicious link  → Defender for Office 365
On premises Identity / AD attacks  → Defender for Identity
SaaS / cloud application usage     → Defender for Cloud Apps
Cloud infrastructure / workloads   → Defender for Cloud
IoT and OT / industrial devices    → Defender for IoT
Cloud identity risk (Entra ID)     → Entra ID Protection
Insider / data exfiltration risk   → Purview Insider Risk Management
Cross product correlation / hunt   → Microsoft Defender XDR
```

A refinement worth remembering: "identity" splits into two separate products depending on where the identity lives. If the question mentions a domain controller, Kerberos, NTLM, or LDAP, think Defender for Identity. If it mentions Entra ID, risky sign in, or Conditional Access, think Entra ID Protection.

---

## 3. SC 200 Exam Quick Revision

**Product purpose and scope**
* Know each product's one line job from the quick map at the top of this note before anything else.
* The exam frequently tests whether you can tell two similarly named products apart based on a short scenario description rather than the product name.

**Data sources and detection**
* Defender for Endpoint: device level telemetry, behavioral and machine learning detection.
* Defender for Office 365: message, URL, and attachment analysis, detonation based detection.
* Defender for Identity: domain controller sensor telemetry, behavioral analytics on authentication and directory activity.
* Defender for Cloud Apps: Cloud Discovery logs and app connector API data, anomaly detection.
* Defender for Cloud: resource configuration data and workload telemetry, posture and behavioral detection.
* Defender for IoT: passive network traffic analysis, protocol and baseline anomaly detection.
* Entra ID Protection: sign in logs and threat intelligence, risk scoring.
* Purview Insider Risk Management: Microsoft 365 activity plus HR context, sequence and pattern detection.

**Alert generation and incident correlation**
* An **alert** is one detection from one product; an **incident** is a correlated group of related alerts across products, automatically assembled by Defender XDR.
* Correlation is based on shared entities: the same user, device, mailbox, or IP address appearing across multiple alerts.

**Investigation workflows and Advanced Hunting**
* Advanced Hunting uses KQL and runs across shared tables in the Microsoft Defender portal, for example `DeviceProcessEvents`, `EmailEvents`, `IdentityLogonEvents`, and `CloudAppEvents`.
* Custom detection rules are saved hunting queries that run on a schedule and automatically generate alerts.

**Automated investigation and response**
* AIR investigates and remediates specific alert types, most commonly discussed for Defender for Endpoint and Defender for Office 365.
* Attack disruption is a Defender XDR wide capability that automatically contains a high confidence, in progress, multistage attack, such as ransomware or business email compromise, even before an analyst reviews it.

**Threat intelligence**
* Threat analytics in Defender XDR provides Microsoft researcher written reports on active threat actors and campaigns, mapped to related detections in your own environment.

**Identity risk**
* Two separate products cover identity: Defender for Identity for on premises AD, Entra ID Protection for cloud identity risk (user risk and sign in risk).

**Endpoint detection**
* Know attack surface reduction rules, device isolation, live response, and the difference between prevention (antivirus, ASR) and detection and response (EDR).

**Email threats**
* Know Safe Links vs Safe Attachments, zero hour auto purge, and Threat Explorer as the primary investigation tool.

**Cloud application visibility**
* Know the four MDCA pillars: discover, investigate, control, protect, and Conditional Access App Control for session level enforcement.

**Cloud posture and workload protection**
* Know CSPM (configuration posture, Secure Score) versus CWPP (active workload threat detection), and that Defender for Cloud is multicloud capable.

**IoT security**
* Know that OT monitoring is agentless and network based, while Enterprise IoT discovery reuses the Defender for Endpoint sensor.

**Insider risk**
* Know that Purview Insider Risk Management lives in the Purview portal, uses pseudonymization by default, and covers both malicious and accidental insider activity, including compromised accounts.

**Relevant portals**

| Product | Primary portal |
|---|---|
| Defender XDR | Microsoft Defender portal (security.microsoft.com), also hosts the unified security operations platform with Microsoft Sentinel |
| Defender for Endpoint | Microsoft Defender portal |
| Defender for Office 365 | Microsoft Defender portal |
| Defender for Identity | Microsoft Defender portal (classic standalone portal retired) |
| Defender for Cloud Apps | Microsoft Defender portal (classic standalone portal retired in 2024) |
| Defender for Cloud | Azure portal, with alerts and recommendations also visible in the Microsoft Defender portal |
| Defender for IoT | Azure portal, for OT sensor management; alerts also visible in the Microsoft Defender portal |
| Entra ID Protection | Microsoft Entra admin center, with risk data also visible in the Microsoft Defender portal |
| Purview Insider Risk Management | Microsoft Purview portal |

---

## 4. Key Differences

**Defender for Endpoint vs Defender for IoT**
Defender for Endpoint installs a software sensor on devices that can run an operating system agent, such as Windows, macOS, and Linux computers and servers. Defender for IoT covers devices that usually cannot run an agent, such as PLCs and SCADA systems, using passive network monitoring instead, and separately discovers everyday office IoT devices (like printers and cameras) through the Defender for Endpoint sensor already installed on managed endpoints.

**Defender for Office 365 vs Defender for Cloud Apps**
Defender for Office 365 protects the email and collaboration content path: messages, attachments, links, and files shared through Teams, SharePoint, and OneDrive. Defender for Cloud Apps protects the broader pattern of SaaS application usage across many applications, including but not limited to Microsoft 365, focusing on discovery, access control, and account behavior rather than message content specifically.

**Defender for Identity vs Entra ID Protection**
Defender for Identity protects on premises Active Directory through a sensor deployed on domain controllers, detecting attacks like Kerberoasting and Pass the Hash. Entra ID Protection protects cloud identities in Microsoft Entra ID with no sensor to deploy, detecting risky users and risky sign ins such as impossible travel or leaked credentials.

**Defender for Cloud vs Defender XDR**
Defender for Cloud is a workload and posture protection product scoped to cloud infrastructure: virtual machines, storage, containers, and databases. Defender XDR is the correlation and investigation platform that unifies alerts from multiple products, including, where connected, Defender for Cloud, into a single incident view. Defender for Cloud generates signals; Defender XDR correlates them alongside signals from the other products.

**Defender XDR and the individual Defender products**
The individual Defender products (Endpoint, Office 365, Identity, Cloud Apps) are sensors and detection engines, each focused on one layer of the environment. Defender XDR does not replace them; it sits above them, receiving their alerts and telemetry and assembling related alerts into unified incidents so an analyst can investigate one connected story instead of many disconnected alerts.

**Defender for Cloud Apps vs Defender for Cloud**
Despite the similar names, these protect completely different layers. Defender for Cloud Apps protects SaaS **applications** and how they are accessed and used (a CASB). Defender for Cloud protects cloud **infrastructure and workloads** (a CSPM and CWPP platform). A simple test: if the scenario mentions Salesforce, Dropbox, or Shadow IT, think Defender for Cloud Apps. If it mentions a virtual machine, a storage account, or Kubernetes, think Defender for Cloud.

**Microsoft Purview Insider Risk Management vs Microsoft Defender XDR**
Defender XDR is built to detect and respond to technical attack techniques, generally associated with external adversaries or compromised accounts acting like an adversary. Purview Insider Risk Management is built to detect risky patterns of behavior by people who already have legitimate access, which is as much a compliance and governance concern as a security one, and it is investigated inside the Purview portal rather than as a native Defender XDR incident. The two can be used together when a case has both a technical compromise element and a data risk element.

---

## 5. End to End SOC Scenario

This scenario walks through a realistic, multistage attack and shows which product detects each stage, what telemetry is generated, and how Defender XDR ties it all together.

```text
Initial Access
      │
      ▼
Phishing / Malicious Email        →  Defender for Office 365
      │
      ▼
User Interaction (click / open)   →  Defender for Office 365 (Safe Links time of click check)
      │
      ▼
Endpoint Compromise               →  Defender for Endpoint
      │
      ▼
Credential Theft                  →  Defender for Endpoint (local) + Defender for Identity (domain)
      │
      ▼
Identity Based Activity           →  Defender for Identity + Entra ID Protection
      │
      ▼
Lateral Movement                  →  Defender for Identity + Defender for Endpoint
      │
      ▼
Cloud Application Activity        →  Defender for Cloud Apps
      │
      ▼
Data Access or Exfiltration       →  Defender for Cloud Apps + Purview (DLP / Insider Risk if pattern matches)
      │
      ▼
Microsoft Defender XDR            →  Ingests every alert above
      │
      ▼
Correlation                       →  Groups alerts by shared user, device, and time window
      │
      ▼
Incident Investigation            →  SOC analyst reviews incident graph and runs Advanced Hunting
      │
      ▼
Response and Remediation          →  Contain, remove access, and recover
```

**Stage by stage detail**

1. **Phishing email delivered.** Defender for Office 365 analyzes the sender, message content, and attachment. In this scenario, the attachment is not immediately flagged as malicious, so it is delivered, but Safe Links continues to monitor the embedded URL.

2. **User interaction.** The employee opens the attached document. Because Safe Links checks links again at the time of click, the analyst can later confirm exactly when and whether the user clicked anything.

3. **Endpoint compromise.** Defender for Endpoint observes WINWORD.EXE launching PowerShell with an encoded command, which downloads a second stage payload and creates a persistence mechanism. This generates a device based alert with a full process tree.

4. **Credential theft.** The payload attempts to access credential material stored in memory on the device. Defender for Endpoint flags this locally, and when the stolen credentials are used to authenticate against a domain controller, Defender for Identity flags the unusual authentication.

5. **Identity based activity.** Defender for Identity observes the compromised account performing reconnaissance queries against Active Directory (for example, enumerating Domain Admins). If the attacker also uses the stolen credentials against Microsoft Entra ID, Entra ID Protection flags a risky sign in, for example due to an unfamiliar location.

6. **Lateral movement.** Using the stolen credentials, the attacker moves from the original device to a second device. Defender for Identity flags the unusual authentication pattern across machines, and Defender for Endpoint flags remote execution activity on the second device.

7. **Cloud application activity.** The attacker uses the compromised identity to access Microsoft 365 and other connected SaaS applications. Defender for Cloud Apps flags anomalous activity, such as a sign in from an unusual location shortly after mass file access.

8. **Data access or exfiltration.** The attacker downloads a large volume of files and uploads them to an external cloud storage service. Defender for Cloud Apps flags the mass download and unusual upload destination; if the behavior pattern also resembles insider style data staging, this may separately surface in Purview for data governance review.

9. **Microsoft Defender XDR ingests every alert above** from Defender for Office 365, Defender for Endpoint, Defender for Identity, Entra ID Protection, and Defender for Cloud Apps.

10. **Correlation.** Defender XDR recognizes that all these alerts share the same user account, the same two devices, and a continuous time window, and automatically groups them into a single incident with a clear attack story from initial email to data access.

11. **Incident investigation.** The SOC analyst opens the incident, reviews the automatically generated attack story and entity graph, and runs Advanced Hunting queries across `EmailEvents`, `DeviceProcessEvents`, `IdentityLogonEvents`, and `CloudAppEvents` to confirm the full scope, including whether any other users or devices were affected.

12. **Response and remediation.** The analyst isolates both compromised devices, disables and resets the compromised account, revokes its active sessions and tokens, blocks the malicious sender and purges the phishing email organization wide, and, if the account's Entra ID risk indicates ongoing compromise, forces a risk based Conditional Access response. If data governance implications exist, the analyst loops in the Purview investigators to assess data exposure and required notifications.

This scenario shows the core idea behind the whole architecture: no single product sees the entire attack, but Defender XDR turns each product's partial view into one connected incident that a SOC analyst can investigate and act on efficiently.
