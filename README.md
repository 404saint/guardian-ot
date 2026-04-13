# 🛡️ Guardian-OT 
**Industrial Control Systems (ICS) USB Forensic & Integrity Suite**

Guardian-OT is a minimalist, high-signal forensic tool designed for OT researchers to audit and verify the integrity of removable media before they enter a sensitive plant environment.

## 🚀 Features
- **Hardware Fingerprinting:** Identifies devices via UUID to prevent spoofing.
- **Integrity Vault:** Uses Merkle-tree style hashing to detect any file modification.
- **Deep YARA Inspection:** Scans for ICS protocol strings (Modbus, S7Comm, Ethernet/IP).
- **Entropy Analysis:** Detects hidden or encrypted payloads (Entropy > 7.8).
- **Researcher Dashboard:** A Streamlit-based UI for rapid triage of high-signal threats.

## 🛠️ Tech Stack
- **Language:** Python 3.10+
- **Analysis:** YARA (yara-python)
- **Database:** SQLite
- **Visualization:** Streamlit, Pandas

## 📈 4-Year Journey
This project is part of a 4-6 year roadmap to mastering ICS/OT Security. 
Developed by **404saint**.