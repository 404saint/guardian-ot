# 🛡️ Guardian-OT

**Guardian-OT** is a hardware-aware forensic engine designed to validate the integrity of removable media before deployment in high-consequence **Industrial Control Systems (ICS)** and **Operational Technology (OT)** environments.

It moves beyond signature-based detection, focusing on **hardware identity**, **structural integrity**, and **entropy-based anomaly detection**.

---

## ⚡ Quick Look: Actionable Intelligence

<p align="center">
  <img src="https://raw.githubusercontent.com/404saint/guardian-ot/main/assets/dashboard.png" alt="Guardian-OT Dashboard Triage View" width="800">
</p>

*The Dashboard automatically filters 1,000+ assets into a prioritized triage list...*

---

## 🎯 The Problem: The "Stuxnet" Vector

In isolated industrial plants, USB drives remain the primary bridge across air-gaps. Standard AV solutions often overlook:

  * **Protocol-specific toolkits** (Modbus/S7/ENIP)
  * **High-entropy obfuscated payloads** hidden in "trusted" vendor drivers.
  * **BadUSB/Spoofing attacks** where the filesystem appears safe but the hardware is untrusted.

-----

## 🛠️ Core Forensic Pipeline

### 1\. Hardware-to-Vault Mapping

Guardian-OT fingerprints the physical **Device UUID**. If a drive has been cloned or replaced—even if the files are identical—the system rejects the hardware baseline.

### 2\. Recursive Integrity Auditing

Using a high-performance hashing engine, the tool establishes a "known-good" baseline of the entire file tree. Any "silent" modification (even a single bit flip in a `.dll` or `.bin`) triggers an immediate audit.

### 3\. Deep Analysis & Entropy Scoring

  * **YARA Integration:** Scans for industrial protocol strings and malicious logic.
  * **Entropy Analysis:** Files are scored from `0.0` to `8.0`. Anything above `7.8` is flagged as potentially encrypted or packed—a common indicator of malware payloads.
  * **Magic Number Validation:** Detects header-extension mismatches to stop disguised executables.

-----

## 📊 Researcher Dashboard

<p align="center">
  <img src="https://raw.githubusercontent.com/404saint/guardian-ot/main/assets/dashboard2.png" alt="Guardian-OT Dashboard Entropy Analysis" width="800">
</p>

The built-in **Streamlit** dashboard provides:

  * **Single Pane of Glass:** View anomalies across 5GB+ of data in seconds.
  * **Threat Distribution:** Real-time visualization of Critical vs. Standard assets.
  * **Forensic Export:** Generates structured JSON and human-readable Markdown for incident documentation.

-----

## 🚀 Getting Started

### Installation

```bash
git clone https://github.com/404saint/guardian-ot.git
cd guardian-ot
pip install -r requirements.txt
```

### Execution

**1. Field Audit:** Perform the deep scan on the mount point.

```bash
python main.py /mnt/usb_drive
```

**2. Analyze Findings:** Launch the triage interface.

```bash
streamlit run dashboard.py
```

-----

## 🛤️ Roadmap & 4-Year Journey

This project is a core component of my **4-year ICS/OT security roadmap**.

  * [x] **V1.0:** Core Forensics, YARA Integration, and Dashboard.
  * [ ] **V1.5:** Automated File Carving for suspicious `.zip` archives.
  * [ ] **V2.0:** Real-time PCAP analysis for USB-to-Network handshakes.

-----

## ⚖️ Ethical Use

Guardian-OT is built for **defensive security research** and **industrial maintenance**. It should only be used on hardware you own or have explicit authorization to audit.

**Developed by [404saint](https://www.google.com/search?q=https://github.com/404saint)**
