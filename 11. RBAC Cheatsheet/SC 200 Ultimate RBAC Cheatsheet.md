# The Ultimate SC-200 RBAC Cheat Sheet
### Every role-based access question you'll face — Sentinel, Defender XDR, Entra ID, and Azure RBAC in one place

---

## 0. How to Approach ANY RBAC Question (Do This First)

Before picking an answer, ask these four questions in order:

```
1. WHICH PRODUCT/PORTAL is this about?
   → Sentinel? Defender for Endpoint? Defender for Office 365?
     Defender for Identity? Defender for Cloud Apps? Defender for Cloud?
     Or is it actually an Entra ID / Azure resource question?

2. WHICH RBAC SYSTEM governs that product?
   → Azure RBAC (resource-scoped) vs. Microsoft Entra ID role (tenant-scoped)
     vs. Microsoft Defender unified RBAC (cross-workload) vs. a legacy
     product-specific role group.

3. WHAT VERB is used?
   → View / Read → Reader-tier role
   → Triage / Manage / Respond → Responder/Operator-tier role
   → Create / Edit / Configure → Contributor/Admin-tier role

4. DOES THE QUESTION SAY "LEAST PRIVILEGE"?
   → If yes, always pick the lowest tier that satisfies the verb —
     never Contributor/Admin/Global Admin if a narrower role works.
```

---

## 1. The Big Picture: 5 RBAC Systems in Microsoft Security

SC-200 deliberately mixes these. Knowing *which system* a question lives in is half the battle.

| #   | System                                      | Scope                                                                                                                     | Where you assign it                      | Example roles                                                                                          |
| --- | ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| 1   | **Microsoft Entra ID roles**                | Whole tenant                                                                                                              | Entra admin center                       | Global Administrator, Security Administrator, Security Reader                                          |
| 2   | **Azure RBAC (resource roles)**             | Subscription/resource group/resource                                                                                      | Azure Portal → Access control (IAM)      | Sentinel Reader/Responder/Contributor, Log Analytics Contributor                                       |
| 3   | **Microsoft Defender unified RBAC (URBAC)** | Cross-workload (Defender for Endpoint, Office 365, Identity, Cloud Apps, Defender for Cloud, Sentinel-in-Defender-portal) | Defender portal → Permissions & roles    | Custom roles built from permission groups                                                              |
| 4   | **Legacy product-specific roles**           | Single product only, used before/instead of URBAC                                                                         | Inside that product's own settings       | DfE Basic permissions, Defender for Cloud Apps role groups, Defender for Identity Admins/Users/Viewers |
| 5   | **Exchange Online / EOP roles**             | Email & collaboration only                                                                                                | Exchange admin center or Defender portal | Organization Management, Security Administrator (EOP)                                                  |

> **Exam trap:** A question can hand you two dropdowns — "Azure role" and "Microsoft Entra role" — for the same scenario. These are **not interchangeable**. Don't mix them.

---

## 2. Microsoft Entra ID Roles — The Foundation Everything Else Builds On

These are tenant-wide and many of them **unlock or auto-grant** access into Sentinel/Defender products.

| Role | Think | Key capability |
|---|---|---|
| **Global Administrator** | 🔑 Everything | Full control of all Microsoft 365/Entra services. Reserved for emergencies only — never the "correct" least-privilege answer. |
| **Security Administrator** | 🛡️ Security config | Manage security settings across Defender, Sentinel, Entra ID Protection, Compliance center (read-only there). Auto-grants Full Access in Defender for Endpoint, Defender for Cloud Apps, and Defender for Identity Admin. |
| **Security Operator** | 🚨 Day-to-day SOC work | Manage alerts/incidents, view security info, but can't change security policy/settings. |
| **Security Reader** | 👀 Tenant-wide view | Read-only across security products. **Note:** in Defender for Endpoint, Security Reader does NOT see the device/machine inventory — that requires an assigned DfE role. |
| **Global Reader** | 👀 Everything, read-only | Read-only counterpart to Global Administrator — can see settings across all M365 services without changing anything. |
| **Compliance Administrator** | 📋 Compliance | Manage compliance-related features (DLP, retention, etc.) in Purview; read-only + alert management in Defender for Cloud Apps. |
| **Compliance Data Administrator** | 📋 Compliance data | Similar to Compliance Administrator, focused on data governance/discovery reports. |
| **Attack Simulation Administrator** | 🎣 Simulate attacks | Create and manage Attack Simulation Training in Defender for Office 365. |

**Memory hook:**
```
Global Admin      = everything, everywhere (avoid unless forced)
Security Admin    = configure security tools
Security Operator = manage day-to-day alerts, no config
Security Reader   = look only
Global Reader     = look at everything, tenant-wide
```

---

## 3. Microsoft Sentinel Roles (Azure RBAC)

### 3.1 The 5 Sentinel-specific roles

| Role | Think | Main capability |
|---|---|---|
| **Microsoft Sentinel Reader** | 👀 View | View Sentinel data, incidents, workbooks, recommendations |
| **Microsoft Sentinel Responder** | 🚨 Respond | Reader + manage incidents |
| **Microsoft Sentinel Contributor** | 🛠️ Configure | Responder + create/edit Sentinel resources, analytics rules, content |
| **Microsoft Sentinel Playbook Operator** | ▶️ Run playbook | List/view/manually run playbooks |
| **Microsoft Sentinel Automation Contributor** | ⚙️ Automation engine | Lets *automation rules* run playbooks; meant for the Sentinel **service account**, not a human analyst |

### 3.2 The ladder

```
Reader → Responder → Contributor
"LOOK"    "LOOK + INCIDENTS"    "INCIDENTS + CONFIGURE"
```

### 3.3 Exam mapping table

| Question says... | Choose |
|---|---|
| View incidents / Sentinel data / workbooks | Sentinel Reader |
| Triage / manage / assign incidents | Sentinel Responder |
| Create/edit analytics rules or Sentinel resources | Sentinel Contributor |
| Manually run a playbook | Playbook Operator |
| Create/edit a Consumption Logic App playbook | Logic App Contributor |
| Automation rules run playbooks | Automation Contributor (service account) |

### 3.4 🚨 Biggest trap: Responder vs Contributor
```
Manage incidents              → Responder  (NOT Contributor)
Create/edit analytics rules   → Contributor (now you're changing config)
```
**Memory hook:** Incident → Responder · Rule → Contributor

### 3.5 Playbook decision tree
```
              PLAYBOOK (Azure Logic App)
       ┌─────────┼──────────┐
    CREATE     MANUALLY   AUTOMATIC
     /EDIT       RUN        RUN
       │         │          │
 Logic App    Playbook    Automation
 Contributor   Operator    Contributor
```

### 3.6 ⚠️ Automation Contributor trap
Don't assign **Automation Contributor** to a human user just because the question mentions "automation rules." This role is applied to the **Sentinel service account** on the playbook's resource group so Sentinel itself can invoke playbooks — it's not for people.

### 3.7 Guest users + Sentinel incidents
```
Guest user manages/triages incidents
        ↓
Azure role: Sentinel Responder
   +
Entra ID role: Directory Readers
```
Directory Readers lets the guest identity read directory info needed during investigation/assignment.

### 3.8 Workbooks
| Need | Role |
|---|---|
| View workbook | Sentinel Reader |
| Create/delete workbook | Sentinel role **+** Workbook Contributor |

### 3.9 Least privilege quick check
| Need | Don't choose | Choose |
|---|---|---|
| View incidents only | ❌ Contributor | ✅ Reader |
| Manage incidents | ❌ Contributor | ✅ Responder |
| Create/edit analytics rules | — | ✅ Contributor |
| Manually run a playbook | — | ✅ Playbook Operator |

---

## 4. Microsoft Defender Unified RBAC (URBAC) — the cross-product model

This is the **newer, single permissions model** for the Defender portal (security.microsoft.com). It's replacing legacy per-product RBAC and is now the **default for new tenants** of Defender for Endpoint and Defender for Identity.

**Applies to:** Defender for Endpoint P2, Defender for Office 365 P2, Defender for Identity, Defender Vulnerability Management, Defender for Cloud, Microsoft Security Exposure Management, Defender for Cloud Apps, and Microsoft Sentinel (once a workspace is onboarded to the Defender portal).

### 4.1 Key facts

| Fact | Detail |
|---|---|
| Who can set it up | Global Administrator or Security Administrator in Entra ID |
| Where | Defender portal → Permissions & roles |
| Activation | **Per-workload** — you turn on URBAC for each product separately; Sentinel is activated **per-workspace** |
| Custom roles | Built from **permission groups**, not fixed templates |
| Managing roles without Entra global roles | Assign the **Authorization** permission inside URBAC to delegate role management |
| Global Admin behavior | Global Administrators keep their privileges even after URBAC is activated |

### 4.2 The two main permission groups (memorize these categories)

| Permission group | Covers |
|---|---|
| **Security operations → Security data** | Day-to-day work: view/investigate/manage alerts, incidents, and advisories |
| **Authorization and settings** | Manage security & system settings, and create/assign roles |
| **Security data (Sentinel/data lake specific)** | Managing Sentinel SIEM data and Sentinel data lake advanced analytics permissions |

### 4.3 Exam trap
> Just because a workload (e.g., Defender for Endpoint) is capable of URBAC doesn't mean it's *using* URBAC in the scenario — check whether the question says the tenant is "new" (URBAC by default) or has **existing** legacy roles (may still be on the old model until an admin activates URBAC for that workload).

---

## 5. Microsoft Defender for Endpoint — Legacy/Classic RBAC

If a question describes the **old (pre-URBAC) model**, know these two modes:

| Mode | Behavior |
|---|---|
| **Basic permissions** | Binary: Full access (Security Administrator/Global Administrator) or Read-only (Security Reader). Security Reader does **not** get device/machine inventory. |
| **Role-based access control (RBAC)** | Granular: create custom roles, assign Entra security groups, and scope access to specific **device groups**. |

### 5.1 Key traps
- Switching from Basic → RBAC is **irreversible**.
- After turning on RBAC, users who only had **Security Reader** (read-only) **lose portal access** until explicitly assigned a role.
- Only **Microsoft Entra Global Administrator or Security Administrator** can initially create/assign DfE roles.
- Users with admin rights are auto-assigned the built-in **Defender for Endpoint Administrator** role.
- Device group creation requires **Plan 1 or Plan 2**.

---

## 6. Microsoft Defender for Office 365

Two layers of roles apply here — don't confuse them:

| Layer | Roles |
|---|---|
| **Entra ID roles** | Global Administrator, Security Administrator, Security Reader — govern general Defender portal access |
| **Exchange Online / EOP roles** | Organization Management, Security Administrator (EOP-scoped), Security Reader (EOP-scoped) — govern mail-flow, quarantine, and anti-spam/anti-phishing policy management |

**Rule of thumb:** if the task is about **quarantine, mail flow rules, or anti-phishing policies**, think Exchange/EOP-scoped roles. If it's about **viewing/triaging alerts and incidents**, Entra/URBAC security roles are enough.

---

## 7. Microsoft Defender for Cloud Apps — Role Groups

| Role | Capability |
|---|---|
| **Global administrator (Cloud App Security Admin)** | Full access — same scope as Entra Global Administrator, but limited to Defender for Cloud Apps only |
| **Compliance administrator** | Read-only + manage alerts; create/modify file policies, file governance actions, view built-in reports; **cannot** access cloud security recommendations |
| **Compliance data administrator** | Read-only, create/modify file policies, view discovery reports; cannot access cloud security recommendations |
| **Security administrator** | Full access, same as Entra Security Administrator but scoped to this product |
| **Security operator / Security reader** | Read-only + manage alerts |
| **Global reader** | Full read-only access to everything in the product; no settings/actions |
| **App/Instance admin** | Scoped access to a *specific app or app instance* only (e.g., just the Box EU instance) |

**Who can grant access:** Global Administrators, Security Administrators, Compliance Administrators, Compliance Data Administrators, Security Operators, Security Readers, or Global Readers can *view* the Manage Admin Access page — but only **Security Administrator or higher** can *edit* it.

---

## 8. Microsoft Defender for Identity

| Model | Roles |
|---|---|
| **Legacy** | Admins (full management), Users (limited/day-to-day), Viewers (read-only) — the old "Azure ATP" group names |
| **Current (Unified RBAC, mandatory for new tenants since March 2025)** | Security Administrator = automatic Defender for Identity Admin (no extra config needed). Security Operator / Security Reader map to lower-tier access. |

### 8.1 Scoped access (exam-relevant nuance)
Defender for Identity supports **scoped access** by Active Directory domain/OU — built through a **custom role in Defender unified RBAC**, restricting a user/group's visibility to specific AD domains or OUs. Requires:
- Security Administrator role (or delegated Authorization permission via URBAC)
- The Identity workload activated in Defender unified RBAC

**Exception trap:** If Defender for Identity alerts were previously scoped through **Defender for Cloud Apps**, those scope settings do **not** automatically carry over — you must explicitly grant the "Security data basics (Read)" permission.

---

## 9. Microsoft Defender for Cloud (Azure Workload Protection)

This is Azure-resource-level, not Defender-portal-level RBAC.

| Role | Scope |
|---|---|
| **Security Reader** (Azure RBAC) | Read-only view of security recommendations, alerts, policies |
| **Security Admin** (Azure RBAC) | View + apply recommendations, dismiss alerts, edit security policy |
| **Owner / Contributor** (subscription or resource) | Broader Azure resource management rights; can also manage Defender for Cloud settings but is *not least-privilege* |
| **Reader** (subscription) | Needed just to *see* the underlying resources Defender for Cloud is protecting |

**Trap:** A user with only **Security Reader** can see recommendations but **cannot remediate** them — that needs Security Admin or resource-level Contributor.

---

## 10. Supporting Azure RBAC Roles (the Sentinel/Log Analytics ecosystem)

These aren't "Sentinel roles" but show up constantly in scenario questions about the underlying workspace.

| Role | Purpose |
|---|---|
| **Log Analytics Reader** | Read log/query data in the workspace (without Sentinel-specific rights) |
| **Log Analytics Contributor** | Configure workspace, manage data sources/solutions |
| **Workbook Reader / Workbook Contributor** | View / create-edit-delete workbooks |
| **Logic App Contributor** | Create/edit/manage Logic Apps (used as Sentinel playbooks) |
| **Azure Automation Contributor** ⚠️ | Manages **Azure Automation accounts/runbooks** — **different from** "Microsoft Sentinel Automation Contributor," which only lets automation rules invoke playbooks |
| **Monitoring Reader / Monitoring Contributor** | Broader Azure Monitor read/write access, sometimes required alongside Sentinel roles for full workspace visibility |

**Exam trap:** "Automation Contributor" appears in **two different contexts** — generic Azure Automation and Sentinel-specific. Read carefully whether the scenario is about runbooks (Azure Automation Contributor) or playbooks-via-automation-rules (Sentinel Automation Contributor).

---

## 11. Guest Users & Cross-Tenant Scenarios

| Scenario | Roles needed |
|---|---|
| Guest triages/manages Sentinel incidents | Sentinel Responder (Azure) **+** Directory Readers (Entra) |
| Guest needs any directory lookups during investigation | Directory Readers (Entra) |
| MSSP/external admin manages Defender for Cloud Apps | Invited as guest first, then assigned a role/App-Instance admin scope |

---

## 12. THE Master Verb → Role Lookup (All Products Combined)

| Verb / need | Product context | Role |
|---|---|---|
| View incidents/data | Sentinel | Sentinel Reader |
| Triage/manage/assign incidents | Sentinel | Sentinel Responder |
| Create/edit analytics rules or resources | Sentinel | Sentinel Contributor |
| Manually run playbook | Sentinel | Playbook Operator |
| Create/edit Consumption Logic App playbook | Sentinel/Logic Apps | Logic App Contributor |
| Automation rules run playbooks | Sentinel | Sentinel Automation Contributor (service account) |
| View/create/delete workbook | Sentinel | Reader / Reader+Workbook Contributor |
| Full tenant-wide security config | Entra ID | Security Administrator |
| Day-to-day alert management, no config | Entra ID | Security Operator |
| Tenant-wide read-only security view | Entra ID | Security Reader |
| Read-only across ALL M365 services | Entra ID | Global Reader |
| Manage Defender for Endpoint device inventory + actions | Defender for Endpoint | DfE Administrator / custom RBAC role |
| View DfE alerts, read-only | Defender for Endpoint | Security Reader (basic) — no device inventory |
| Manage quarantine/mail flow | Defender for Office 365 | EOP-scoped Security Administrator / Organization Management |
| Full Cloud Apps management | Defender for Cloud Apps | Cloud App Security Admin (Global administrator) |
| Cloud Apps access to one app only | Defender for Cloud Apps | App/Instance admin |
| Defender for Identity full admin | Defender for Identity | Security Administrator (auto) / legacy Admins group |
| Defender for Identity read-only | Defender for Identity | Security Reader / legacy Viewers group |
| Remediate Defender for Cloud recommendations | Defender for Cloud (Azure) | Security Admin (Azure RBAC) |
| View Defender for Cloud recommendations only | Defender for Cloud (Azure) | Security Reader (Azure RBAC) |
| Guest manages incidents | Sentinel + Entra | Responder + Directory Readers |
| Create/manage roles across Defender workloads | Defender XDR | URBAC Authorization permission (via Security Admin/Global Admin) |

---

## 13. Top 10 Exam Traps — Consolidated

1. **Responder vs Contributor** — incident management ≠ resource/rule configuration.
2. **Automation Contributor is for the service account**, not a human analyst — in both Sentinel and (separately) Azure Automation contexts.
3. **Guest + incidents = two roles**, not one (Azure role + Entra role).
4. **Azure role vs Entra ID role** dropdowns are never interchangeable.
5. **Security Reader ≠ device inventory access** in Defender for Endpoint basic permissions.
6. **Switching DfE from Basic → RBAC is irreversible**, and read-only users lose access until reassigned.
7. **Workbooks need an extra role** (Workbook Contributor) beyond the base Sentinel role to create/delete.
8. **URBAC activation is per-workload** (and per-workspace for Sentinel) — not all-or-nothing tenant-wide.
9. **Compliance Administrator ≠ Security recommendations access** in Defender for Cloud Apps.
10. **Least privilege always wins** — if a lower-tier role satisfies the verb in the question, that's the answer, even if a higher role would also technically work.

---

## 14. 30-Second Recall Test

Before answering, run through:
1. **Which product/portal?** (Sentinel / DfE / DfO365 / Defender for Identity / Cloud Apps / Defender for Cloud / Entra ID)
2. **View, respond, or configure?** → Reader / Responder-Operator / Contributor-Admin tier
3. **Playbook — create, run manually, or run automatically?** → Logic App Contributor / Playbook Operator / Automation Contributor
4. **Guest user involved?** → Add Directory Readers alongside the product role
5. **"Least privilege" in the question?** → Pick the lowest role that satisfies the requirement
