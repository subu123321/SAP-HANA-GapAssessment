# SAP HANA on Azure Security Gap Assessment

![PowerShell](https://img.shields.io/badge/PowerShell-7%2B-blue?logo=powershell)
![Azure](https://img.shields.io/badge/Microsoft_Azure-0089D6?logo=microsoftazure&logoColor=white)
![SAP](https://img.shields.io/badge/SAP-0FAA64?logo=sap&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)

A **client-ready PowerShell script** that performs an **automated security and best-practice gap assessment** of **SAP HANA workloads running on Azure Virtual Machines**.  

It checks **both Azure security posture** and **SAP-specific requirements** (VM size, disk type, networking, OS) — and outputs a **professional HTML report** with color-coded risks.

> ✅ **Zero-impact** — runs with **Reader access only**  
> ✅ **Auto-detects Log Analytics** — no manual input needed  
> ✅ Built for **real-world SAP environments**

---

## 🚀 Features

- 🔍 **SAP HANA-Specific Checks**:
  - VM size certification (M-series, Esv4, etc.)
  - Premium SSD requirement
  - Accelerated Networking
  - OS type (Linux expected)
- 🛡️ **Azure Security Posture**:
  - Disk encryption (customer-managed keys)
  - Backup protection (Azure Backup)
  - Just-in-Time (JIT) access
  - NSG rules (open SAP ports: 3xx, 3200, 3300, 50000+)
  - Missing security patches (via Log Analytics)
  - Defender for Cloud assessments
- 📊 **HTML Report** with:
  - Color-coded risk levels (🔴 High, 🟠 Medium, 🟢 Low)
  - Per-VM findings
  - Executive summary
- 🔐 **Read-only** — safe for client environments

---

## 🛠️ Prerequisites

### 1. **PowerShell 7+ (Required)**
> ⚠️ **Does NOT work reliably in Windows PowerShell 5.1** due to Microsoft Graph and Az module compatibility.

- Install **PowerShell 7.4+** from:  
  👉 [https://aka.ms/powershell-release](https://aka.ms/powershell-release)

### 2. **Required Permissions**
Your Azure account must have:
- **Reader** role on the subscription containing SAP VMs
- **Log Analytics Reader** (if LA is in a different subscription)

> 💡 No write permissions needed — fully non-intrusive.

### 3. **Install PowerShell Modules**
Open **PowerShell 7** and run:

```powershell
Install-Module -Name Az -Scope CurrentUser -Force -AllowClobber
