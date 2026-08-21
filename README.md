# SC-200: Microsoft Security Operations Analyst - Study Notes

Personal study notes for the Microsoft Learn course **"Defend against cyberthreats with Microsoft's security operations platform"**, organized to support preparation for the **SC-200: Microsoft Security Operations Analyst** certification exam.

> 📌 These are personal notes taken while working through the official Microsoft Learn curriculum. They're meant as a study companion, not a replacement for the official learning paths, hands-on labs, or Microsoft documentation.

---

## 📖 About the Certification

The **Microsoft Certified: Security Operations Analyst Associate** credential validates the skills needed to monitor, identify, investigate, and respond to threats using Microsoft Defender XDR, Microsoft Sentinel, Microsoft Entra ID, Microsoft Purview, and Microsoft Defender for Cloud — and to hunt for threats using KQL.

| | |
|---|---|
| **Exam** | SC-200: Microsoft Security Operations Analyst |
| **Certification earned** | Microsoft Certified: Security Operations Analyst Associate |
| **Format** | ~40–60 questions, 100 minutes |
| **Passing score** | 700 / 1000 |
| **Renewal** | Free annual renewal assessment on Microsoft Learn |

### Skills measured
| Functional group | Weight |
|---|---|
| Manage a security operations environment | 40–45% |
| Respond to security incidents | 35–40% |
| Perform threat hunting | 20–25% |

> Domain weights and objectives are revised by Microsoft periodically — always check the [official SC-200 study guide](https://learn.microsoft.com/en-us/credentials/certifications/resources/study-guides/sc-200) for the current version before using this repo as your sole source of truth.

---

## 🗂️ Repository Structure

Notes are organized module-by-module, mirroring the Microsoft Learn learning paths that make up the course, plus a consolidated summary at the top level.

```
0. Main Note                 → condensed cross-module summary
0. Main Note v2               → revised / expanded summary
01. Mitigate threats using Microsoft Defender XDR
02. Mitigate threats using Microsoft Security Copilot
03. Mitigate threats using Microsoft Purview
04. Mitigate threats using Microsoft Defender for Endpoint
05. Mitigate threats using Microsoft Defender for Cloud
06. Create queries for Microsoft Sentinel using Kusto Query Language (KQL)
07. Configure your Microsoft Sentinel environment
08. Connect logs to Microsoft Sentinel
09. Create detections and perform investigations using Microsoft Sentinel
10. Perform threat hunting in Microsoft Sentinel
```

---

## 📚 Contents

### 0. Main Note
- Microsoft Security Ecosystem
- Microsoft Security Solutions – Detailed Study Notes
- Microsoft Security Solutions – Study Notes

### 0. Main Note v2
- Microsoft Security Solutions – Study Notes Short V2
- Microsoft Security Solutions Detailed V2

### 01. Mitigate threats using Microsoft Defender XDR
1. Microsoft Defender for Endpoint (MDE) Part 1
2. Microsoft Defender for Endpoint (MDE) Part 2
3. Mitigate incidents using Microsoft Defender
4. Remediate threats using Microsoft Defender
5. Manage Microsoft Entra Identity Protection
6. Safeguard your environment with Microsoft Defender for Identity
7. Secure your cloud apps and services with Microsoft Defender for Cloud Apps

### 02. Mitigate threats using Microsoft Security Copilot
1. Describe Microsoft Security Copilot
2. Describe the core features of Microsoft Security Copilot
3. Describe the embedded experiences of Microsoft Security Copilot

### 03. Mitigate threats using Microsoft Purview
1. Investigate and respond to Microsoft Purview Data Loss Prevention alerts
2. Investigate Insider Risk alerts and related activity
3. Search and investigate with Microsoft Purview Audit
4. Search for content with Microsoft Purview eDiscovery

### 04. Mitigate threats using Microsoft Defender for Endpoint
1. Protect against threats with Microsoft Defender for Endpoint
2. Deploy the Microsoft Defender for Endpoint environment
3. Implement Windows security enhancements with Microsoft Defender for Endpoint
4. Perform device investigations in Microsoft Defender for Endpoint
5. Perform actions on a device using Microsoft Defender for Endpoint
6. Perform evidence and entities investigations using Microsoft Defender for Endpoint
7. Configure and manage automation using Microsoft Defender for Endpoint
8. Configure alerts and detections in Microsoft Defender for Endpoint
9. Utilize Vulnerability Management in Microsoft Defender for Endpoint

### 05. Mitigate threats using Microsoft Defender for Cloud
1. Mitigate threats using Microsoft Defender for Cloud
2. Connect Azure assets to Microsoft Defender for Cloud
3. Connect non-Azure resources to Microsoft Defender for Cloud
4. Manage your cloud security posture management
5. Explain cloud workload protections in Microsoft Defender for Cloud
6. Remediate security alerts using Microsoft Defender for Cloud

### 06. Create queries for Microsoft Sentinel using KQL
1. Construct KQL statements for Microsoft Sentinel
2. Analyze query results using KQL
3. Build multi-table statements using KQL
4. Work with data in Microsoft Sentinel using Kusto Query Language

### 07. Configure your Microsoft Sentinel environment
1. Introduction to Microsoft Sentinel
2. Create and manage Microsoft Sentinel workspaces
3. Query logs in Microsoft Sentinel
4. Use watchlists in Microsoft Sentinel
5. Utilize threat intelligence in Microsoft Sentinel
6. Integrate Microsoft Defender XDR with Microsoft Sentinel

### 08. Connect logs to Microsoft Sentinel
1. Connect data to Microsoft Sentinel using data connectors
2. Connect Microsoft services to Microsoft Sentinel
3. Connect Microsoft Defender XDR to Microsoft Sentinel
4. Connect Windows hosts to Microsoft Sentinel
5. Connect Common Event Format logs to Microsoft Sentinel
6. Connect syslog data sources to Microsoft Sentinel
7. Connect threat indicators to Microsoft Sentinel

### 09. Create detections and perform investigations using Microsoft Sentinel
1. Threat detection with Microsoft Sentinel analytics
2. Automation in Microsoft Sentinel
3. Threat response with Microsoft Sentinel playbooks
4. Security incident management in Microsoft Sentinel
5. Identify threats with Behavioral Analytics
6. Data normalization in Microsoft Sentinel
7. Query, visualize, and monitor data in Microsoft Sentinel
8. Manage content in Microsoft Sentinel

### 10. Perform threat hunting in Microsoft Sentinel
1. Explain threat hunting concepts in Microsoft Sentinel
2. Threat hunting with Microsoft Sentinel
3. Use Search jobs in Microsoft Sentinel
4. Hunt for threats using notebooks in Microsoft Sentinel

---

## 🎯 How to Use This Repo
- All notes are plain Markdown, so they render cleanly right on GitHub — no extra tooling needed.
- New to the material? Start with **`0. Main Note v2`** for a condensed, cross-topic overview before drilling into individual modules.
- Each numbered top-level folder maps 1:1 to a module in the official learning path, and files within a folder follow the same unit order as Microsoft Learn.
- Use folders `06`–`10` as your KQL / Sentinel deep-dive block — this is the single largest exam domain.

---

## 🔗 Official Resources
- [Course: Defend against cyberthreats with Microsoft's security operations platform](https://learn.microsoft.com/en-us/training/courses/sc-200t00)
- [Certification: Microsoft Certified – Security Operations Analyst Associate](https://learn.microsoft.com/en-us/credentials/certifications/security-operations-analyst/)
- [Official SC-200 study guide (skills measured)](https://learn.microsoft.com/en-us/credentials/certifications/resources/study-guides/sc-200)

---

## ⚠️ Disclaimer
These are personal study notes and may contain simplifications, errors, or content that's fallen out of date as Microsoft's products and the exam's skills-measured outline evolve. Always cross-check against the official Microsoft Learn documentation and the current study guide before relying on this material for exam prep.

## 📄 License
Feel free to use these notes for your own studying. If you fork, redistribute, or adapt them, a link back to this repository is appreciated.
