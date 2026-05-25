# 📡 NetVector-Core v1.0
> **Network Exposure & Vector Core Audit Module**

![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Build](https://img.shields.io/badge/build-passing-brightgreen.svg)
![Stage](https://img.shields.io/badge/security-auditing-red.svg)

`NetVector-Core` is a high-performance, lightweight, terminal-based attack surface mapping and network footprinting utility. It empowers security administrators to probe public-facing network layers, grab protocol version banners, and verify web perimeter configurations directly from a command-line interface.

---

# 🏗️ Core Architecture & Pipeline

```text
  [ Target Host ] ───►  ( Phase 1: TCP Port Probing )   ───► [ Closed / Filtered ]
                             │
                             ├───► [ Open Port Found ]  ───► ( Phase 2: Active Banner Grabbing )
                             │                                    └───► Logs Software Version Signature
                             │
                             └───► ( Phase 3: Web Audit ) ───► Evaluates Security Header Hygiene
                                                                  └───► Evaluates CSP, XFO, & MIME configs
```

---

# 🛠️ Key Features

### ⚡ High-Speed Socket Probing
Utilizes non-blocking atomic TCP three-way handshake attempts (`socket.connect_ex`) with rigid timeout boundaries to efficiently map perimeter listening nodes.

### 🔍 Information Disclosure Auditing
Captures unencrypted stream banners from network sockets to expose version strings and software configurations.

### 🌐 Web Perimeter Hygiene Verification
Leverages a lightweight HTTP client abstraction layer to audit critical security response headers, flagging cross-site scripting (XSS) and clickjacking windows.

### 🧩 Remediation Mapping
Automatically maps discovered vulnerabilities to industry-standard risk classifications and pairs them with definitive remediation actions.

---

# 📋 Prerequisites

NetVector-Core is built natively on top of Python's standard library for maximum portability, requiring only a single third-party package for the web-layer auditing engine.

- **Operating System:** Linux, macOS, or Windows (CMD/PowerShell with ANSI support)
- **Python Engine:** Python 3.8 or higher
- **External Dependency:** `requests`

---

# 📦 Dependency Installation

Before booting the script, install the required package:

```bash
pip install requests
```

---

# 🚀 Running the Auditor

Running a complete vulnerability audit against an authorized perimeter target is simple and configuration-free.

## 1️⃣ Initialization

Execute the main script via your terminal:

```bash
python NetVector-Core.py
```

---

## 2️⃣ Execution Flow

### 🎯 Target Input
Provide a target domain or raw IPv4 structure when prompted.

Example:

```text
scanme.nmap.org
```

### 🌐 Network Phase
The tool resolves the host coordinates and automatically scans critical communication nodes.

### 🛡️ Perimeter Phase
The tool reaches out to the web service layer to verify passive configurations.

### 📊 Summary Compilation
Results are compiled and rendered instantly.

---

# 🧠 The Content-Adaptive Grid Engine

A major feature of NetVector-Core is its tailored **Content-Adaptive Report Generator**.

---

## ❌ The Problem with Standard CLI Layouts

Standard terminal scripts often rely on hardcoded tab spacing or padding rules such as:

```python
\t
```

or

```python
{text:<45}
```

This approach causes major formatting breaks when:

- A server banner or remediation description becomes exceptionally long.
- ANSI terminal color sequences are added.

Example ANSI sequence:

```python
\033[91m
```

Although invisible on-screen, Python still counts these characters internally, causing column deformation and broken table alignment.

---

## ✅ The Adaptive Grid Solution

NetVector-Core eliminates grid deformation through a smart two-step compilation process.

### 📏 Maximum Dimension Tracking

The engine performs a mathematical `max()` scan across every table element before rendering the final matrix.

This allows columns to dynamically expand or contract based on the longest content item.

---

### 🎨 ANSI Overhead Compensation

The renderer compensates for hidden ANSI color structures using adaptive padding mathematics:

```text
Target Padding Width =
Maximum Column Width +
(Length of Colored String − Length of Raw Text)
```

This guarantees perfectly synchronized table boundaries regardless of terminal styling.

---

# 🖥️ Render Preview

```text
===================================================================================================================
                                   VULNERABILITY ASSESSMENT SUMMARY
  Target Scope : scanme.nmap.org (45.33.32.156)
  Timestamp    : 2026-05-25 21:25:00
===================================================================================================================

┌─────────┬────────────────────┬───────────────────────────┬────────────┬───────────────────────────────────────────────┐
│ ID      │ CATEGORY           │ IDENTIFIED THREAT         │ SEVERITY   │ RECOMMENDED REMEDIATION                       │
├─────────┼────────────────────┼───────────────────────────┼────────────┼───────────────────────────────────────────────┤
│ NV-01   │ Network Exposure   │ Open Port 22              │ Low/Med    │ Close port if unused or restrict access via.  │
│ NV-02   │ Info Leak          │ Server Header Exposure    │ Medium     │ Disable or modify the 'Server' response header│
│ NV-03   │ Weak Config        │ Missing X-Frame-Options   │ Low        │ Add 'X-Frame-Options: SAMEORIGIN' header.     │
└─────────┴────────────────────┴───────────────────────────┴────────────┴───────────────────────────────────────────────┘

 [*] Total footprint observations logged: 3
===================================================================================================================
```

---

# ⚠️ Legal & Ethical Disclaimer

This application is engineered strictly for:

- Educational use
- Academic research
- Authorized defensive security auditing

Launching connection probes or vulnerability assessments against infrastructure without explicit prior authorization is illegal and may violate local or international cybercrime legislation.

The author assumes absolutely no liability for:

- Misuse
- Unauthorized scans
- Infrastructure disruption
- Operational downtime

Always obtain written permission before performing any security assessment.

---

# 📜 License

This project is distributed under the MIT License.

```text
MIT License © 2026 NetVector-Core
```
