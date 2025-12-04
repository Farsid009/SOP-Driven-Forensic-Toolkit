# SOP-Driven Memory Acquisition & Automated Forensic Analysis Toolkit

##  Project Overview
**Master's Project**

Memory forensics is a critical component of incident response, enabling investigators to analyze volatile data such as active processes and network connections. However, manual workflows often lack standardization.

This project addresses these challenges by developing an **SOP-driven Memory Acquisition and Automated Forensic Analysis Toolkit** for Windows systems. The tool is designed to enforce procedural compliance (ISO 27037) and accelerate initial analysis by automating the interaction with **DumpIt** and **Volatility 3**.

## Key Features

### 1. Chain of Custody (CoC) & Authentication
* **Role-Based Access:** Secure login system using **PBKDF2** password hashing.
* **Evidence Logging:** Integrated **SQLite** database forces examiners to log Case ID, Evidence Type, and Examiner details before analysis begins.
* **Audit Trail:** Maintains a local database (`coc_records.db`) of all actions for accountability.

### 2. Automated Acquisition & Integrity
* **One-Click Acquisition:** Wrapper for **DumpIt** to capture RAM.
* **Instant Hashing:** Automatically generates **SHA-256** hashes immediately after acquisition to preserve forensic integrity.

### 3. Automated Analysis Engine
* **Volatility 3 Integration:** Automates the execution of key plugins (`pslist`, `netscan`, `malfind`, `cmdline`).
* **Smart IOC Detection:** A custom **Regex** engine scans raw logs for Indicators of Compromise (IoCs), such as:
    * Suspicious keywords (e.g., `mimikatz`, `meterpreter`).
    * Unsigned drivers.
    * Suspicious network connections.

### 4. Reporting
* Generates a comprehensive **HTML Report** containing:
    * Chain of Custody table.
    * Examiner Notes.
    * Automated Key Findings (Anomalies highlighted).
    * Full Volatility logs.

## Technical Stack
* **Language:** Python 3.x
* **GUI Framework:** PyQt5
* **Database:** SQLite3
* **Forensic Engine:** Volatility 3 Framework

