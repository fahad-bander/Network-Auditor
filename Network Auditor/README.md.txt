# Network Vulnerability Auditor 🛡️

A lightweight Python-based network security auditing tool designed to scan local networks for active hosts and identify critical exposed services (e.g., NetBIOS, SMB).

---

## 🌟 Features

- **Layer 2 Discovery:** Uses ARP requests via `Scapy` to discover active devices on the subnet.
- **Port Security Audit:** Scans critical infrastructure ports (TCP 139 NetBIOS & TCP 445 SMB).
- **Vulnerability Reporting:** Categorizes findings by severity (`HIGH`, `MEDIUM`) with remediation steps.
- **JSON Export:** Automatically exports audit results to `network_audit.json` for further analysis.

---

## 📋 Prerequisites

Before running the tool, ensure you have the following installed:

1. **Python 3.x**
2. **Npcap Driver (Windows Users):**
   - Download and install [Npcap](https://npcap.com/).
   - **Crucial:** During installation, check the option: `"Install Npcap in WinPcap API-compatible Mode"`.

---

## 🚀 Installation & Usage

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/YOUR_USERNAME/Network-Auditor.git](https://github.com/YOUR_USERNAME/Network-Auditor.git)
   cd Network-Auditor