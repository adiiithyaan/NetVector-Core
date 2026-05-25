# 📡 NetVector-Core v1.0
> **Network Exposure & Vector Core Audit Module**

![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Build](https://img.shields.io/badge/build-passing-brightgreen.svg)
![Stage](https://img.shields.io/badge/security-auditing-red.svg)

`NetVector-Core` is a high-performance, lightweight, terminal-based attack surface mapping and network footprinting utility. It empowers security administrators to probe public-facing network layers, grab protocol version banners, and verify web perimeter configurations directly from a command-line interface.

---

## 🏗️ Core Architecture & Pipeline

```text
  [ Target Host ] ───►  ( Phase 1: TCP Port Probing )   ───► [ Closed / Filtered ]
                             │
                             ├───► [ Open Port Found ]  ───► ( Phase 2: Active Banner Grabbing )
                             │                                    └───► Logs Software Version Signature
                             │
                             └───► ( Phase 3: Web Audit ) ───► Evaluates Security Header Hygiene
                                                                  └───► Evaluates CSP, XFO, & MIME configs
🛠️ Key FeaturesHigh-Speed Socket Probing: Utilizes non-blocking atomic TCP three-way handshake attempts (socket.connect_ex) with rigid timeout boundaries to efficiently map perimeter listening nodes.Information Disclosure Auditing: Captures unencrypted stream banners from network sockets to expose version strings and software configurations.Web Perimeter Hygiene Verification: Leverages a lightweight HTTP client abstraction layer to audit critical security response headers, flagging cross-site scripting (XSS) and clickjacking windows.Remediation Mapping: Automatically maps discovered vulnerabilities to industry-standard risk classifications and pairs them with definitive remediation actions.📋 PrerequisitesNetVector-Core is built natively on top of Python's standard library for maximum portability, requiring only a single third-party package for the web-layer auditing engine.Operating System: Linux, macOS, or Windows (CMD/PowerShell with ANSI support).Python Engine: Python 3.8 or higher.External Dependencies: requests library.Dependency InstallationBefore booting the script, install the required library package via pip:Bashpip install requests
🚀 Running the AuditorRunning a complete vulnerability audit against an authorized perimeter target is simple and configuration-free.1. InitializationExecute the main script via your terminal:Bashpython net_vector.py
2. Execution FlowTarget Input: Provide a target domain or raw IPv4 structure when prompted (e.g., scanme.nmap.org).Network Phase: The tool resolves the host coordinates and automatically scans critical communication nodes.Perimeter Phase: The tool reaches out to the web service layer to verify passive configurations.Summary Compilation: Results are compiled and rendered instantly.🧠 The Content-Adaptive Grid EngineA major feature of NetVector-Core is its tailored Content-Adaptive Report Generator.The Problem with Standard CLI LayoutsStandard terminal scripts often rely on hardcoded tab spacing or padding rules (e.g., \t or {text:<45}). This approaches causes major formatting breaks if:A server banner or remediation description is exceptionally long, forcing text to spill into adjacent columns.Hidden ANSI color escape sequences (like \033[91m) are added. While invisible on-screen, Python counts these escape tags as literal characters, pushing subsequent columns completely out of alignment.The Adaptive Grid SolutionNetVector-Core eliminates grid deformation through a smart two-step compilation process:Maximum Dimension Tracking: The engine runs a mathematical max() length scan over every element in the vulnerability tracking list before drawing the table matrix. This forces the column walls to adaptively stretch or contract to perfectly fit the longest finding.ANSI Overhead Compensation: It calculates the hidden length overhead of terminal color structures via mathematical offsets:$$\text{Target Padding Width} = \text{Maximum Column Width} + (\text{Length of Colored String} - \text{Length of Raw Text})$$This guarantees that grid boundaries remain perfectly locked and synchronized across all rows.Render PreviewPlaintext===================================================================================================================
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
⚠️ Legal & Ethical DisclaimerThis application is engineered strictly for educational, academic research, and authorized defensive auditing purposes. Launching connection probes or vulnerability assessments against network perimeters without explicit, prior written authorization from the infrastructure owner is strictly illegal and subject to local and international cybercrime legislation. The author assumes absolutely no liability for misuse, unauthorized scans, or operational downtime resulting from the execution of this source code.
