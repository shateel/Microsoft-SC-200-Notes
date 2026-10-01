# Microsoft Sentinel RBAC Cheat Sheet (SC-200)

A quick-reference guide for answering any Sentinel role-based access control question.

---

## 1. The 5 Sentinel-Specific Roles

| Role | Think | Main Capability |
|---|---|---|
| **Microsoft Sentinel Reader** | 👀 View | View Sentinel data, incidents, workbooks, recommendations |
| **Microsoft Sentinel Responder** | 🚨 Respond | Everything Reader can do + manage incidents |
| **Microsoft Sentinel Contributor** | 🛠️ Configure | Everything Responder can do + create/edit Sentinel resources, analytics rules, content |
| **Microsoft Sentinel Playbook Operator** | ▶️ Run playbook | List/view/manually run playbooks |
| **Microsoft Sentinel Automation Contributor** | ⚙️ Automation engine | Allows automation rules to run playbooks; intended for the Sentinel service, not normal users |

---

## 2. The Ladder — Easiest Way to Memorize

```
Reader
  ↓
Responder
  ↓
Contributor
```

- **Reader** — "I only need to LOOK."
- **Responder** — "I need to LOOK + MANAGE INCIDENTS."
- **Contributor** — "I need to MANAGE INCIDENTS + CREATE/EDIT SENTINEL RESOURCES."

**Shortcut:** Reader = View · Responder = Incidents · Contributor = Configuration

---

## 3. Exam Mapping Table (memorize near word-for-word)

| Question says... | Choose |
|---|---|
| View incidents | Sentinel Reader |
| View Sentinel data | Sentinel Reader |
| View workbooks | Sentinel Reader |
| Triage incidents | Sentinel Responder |
| Manage incidents | Sentinel Responder |
| Assign incidents | Sentinel Responder |
| Create/edit analytics rules | Sentinel Contributor |
| Manage analytics rules | Sentinel Contributor |
| Create/edit Sentinel resources | Sentinel Contributor |
| Manage Content Hub | Sentinel Contributor |
| Manually run a playbook | Playbook Operator |
| Create/edit a Consumption Logic App playbook | Logic App Contributor |
| Automation rules run playbooks | Automation Contributor |

---

## 4. 🚨 Biggest Trap: Responder vs. Contributor

**Manage/triage incidents → ✅ Responder** (not Contributor — least privilege applies)

```
Manage incidents → Responder
```

**Create/edit analytics rules → ✅ Contributor** (now you're changing Sentinel config)

```
Create/edit analytics rules → Sentinel Contributor
```

**Memory hook:**
> Incident → Responder
> Rule → Contributor

---

## 5. Playbook Questions — Memorize Separately

```
              PLAYBOOK
                 │
        Azure Logic App
                 │
       ┌─────────┼──────────┐
       ↓         ↓          ↓
    CREATE     MANUALLY   AUTOMATIC
     /EDIT       RUN        RUN
       │         │          │
       ↓         ↓          ↓
 Logic App    Playbook    Automation
 Contributor   Operator    Contributor
```

- **Create/edit** (Consumption Logic App) → **Logic App Contributor**
- **Manually run** → **Microsoft Sentinel Playbook Operator**
- **Automatically run** (via automation rules) → **Microsoft Sentinel Automation Contributor** (service account, not a normal user)

---

## 6. ⚠️ Don't Confuse Automation Contributor

Trap phrasing: *"User needs to configure automation rules to run a playbook."*

Don't reflexively assign **Automation Contributor** to the human user.

> Microsoft Sentinel Automation Contributor allows Microsoft Sentinel to add/run playbooks through automation rules and **isn't used for normal user accounts**. The Sentinel *service account* needs this role on the playbook's resource group.

```
Automation Contributor
        ↓
Sentinel's automation mechanism
        ↓
NOT usually the human analyst
```

---

## 7. Guest User Questions

If the question says: *"Guest user needs to triage/manage Sentinel incidents"* → you need **both**:

- **Azure role:** Microsoft Sentinel Responder
- **Microsoft Entra ID role:** Directory Readers

```
Guest + Sentinel incident management
              ↓
    Responder + Directory Readers
```

**Why:**
- *Responder* → allows Sentinel incident management
- *Directory Readers* → lets the guest identity read directory info needed during investigation/assignment

---

## 8. Azure Role vs. Entra ID Role

| Azure RBAC roles | Microsoft Entra ID roles |
|---|---|
| Microsoft Sentinel Reader | Directory Readers |
| Microsoft Sentinel Responder | Global Reader |
| Microsoft Sentinel Contributor | |
| Microsoft Sentinel Playbook Operator | |
| Microsoft Sentinel Automation Contributor | |

- **Azure RBAC** → controls access to Azure/Sentinel resources
- **Entra ID roles** → control access to Microsoft Entra directory information

⚠️ If a question has two dropdowns (Azure role / Entra role), **don't mix them up**.

---

## 9. Least Privilege Cheat Sheet

Whenever you see *"use the principle of least privilege"* — ask: **what's the smallest permission needed?**

| Need | Don't choose | Choose |
|---|---|---|
| View incidents only | ❌ Contributor | ✅ Reader |
| Manage incidents | ❌ Contributor | ✅ Responder |
| Create/edit analytics rules | — | ✅ Contributor |
| Manually run a playbook | — | ✅ Playbook Operator |

---

## 10. "Run Playbook" — Three Different Meanings

| Scenario | Who/What Acts | Role Needed |
|---|---|---|
| **Manually run** | Human analyst clicks "Run playbook" | Playbook Operator |
| **Automatically run** | Automation rule triggers on incident | Automation Contributor (service account) |
| **Create/edit playbook** | Building a Consumption Logic App | Logic App Contributor |

---

## 11. Analytics Rule Questions

```
Analytics Rule → Detection → Alert → Incident
```

If the question says **create / edit / manage analytics rules** → **Microsoft Sentinel Contributor** (you're modifying Sentinel resources).

---

## 12. Incident Questions

If the question says **investigate / triage / manage / assign incidents** → **Microsoft Sentinel Responder**

> Responder = Reader permissions + manage incidents.

---

## 13. Workbook Questions

| Need | Role |
|---|---|
| View workbook | Sentinel Reader |
| Create/delete workbook | Sentinel role **+** Workbook Contributor |

```
View workbook        → Sentinel Reader
Create/delete workbook → Sentinel role + Workbook Contributor
```

---

## 14. Playbook + Logic App Cheat Sheet

| Requirement | Role |
|---|---|
| View playbook | Playbook Operator |
| Manually run playbook | Playbook Operator |
| Create/edit Consumption Logic App playbook | Logic App Contributor |
| Run/manage Logic App | Logic App Contributor |
| Automatically invoke playbook via automation | Automation Contributor (Sentinel service account) |
| Attach playbook to analytics/automation rule | Sentinel Contributor |

---

## 15. Verb → Role Quick Lookup

| Verb in question | Think |
|---|---|
| View / Read | Reader |
| Triage | Responder |
| Manage incident | Responder |
| Assign incident | Responder |
| Create rule | Contributor |
| Edit rule | Contributor |
| Manage Sentinel resources | Contributor |
| Create/edit playbook | Logic App Contributor |
| Manually run playbook | Playbook Operator |
| Automatically run playbook | Automation Contributor / service account |
| Read Entra directory info | Directory Readers |

---

### 🎯 30-Second Recall Test
Before answering any Sentinel RBAC question, ask:
1. **View, incident, or config?** → Reader / Responder / Contributor
2. **Playbook — create, run manually, or run automatically?** → Logic App Contributor / Playbook Operator / Automation Contributor
3. **Guest user?** → Add Directory Readers alongside the Azure role
4. **Least privilege mentioned?** → Pick the lowest role that satisfies the need
