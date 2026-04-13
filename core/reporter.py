import json
import os
from datetime import datetime

def save_report(path, results, device_uuid):
    """
    Saves forensic scan reports in both JSON (for archives) and Markdown (for documentation).
    """
    report_dir = "reports"
    if not os.path.exists(report_dir):
        os.makedirs(report_dir)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"scan_{timestamp}_{device_uuid[:8]}"
    
    anomalies = [a for a in results if a['state'] != "UNCHANGED" or "SIG MATCH" in a['priority']]
    
    # --- Generate JSON Report ---
    json_path = os.path.join(report_dir, f"{base_name}.json")
    report_data = {
        "scan_info": {
            "timestamp": timestamp,
            "device_uuid": device_uuid,
            "target_path": path,
            "total_assets": len(results),
            "anomalies_found": len(anomalies)
        },
        "findings": anomalies
    }
    with open(json_path, "w") as f:
        json.dump(report_data, f, indent=4)

    # --- Generate Markdown Report ---
    md_path = os.path.join(report_dir, f"{base_name}.md")
    with open(md_path, "w") as f:
        f.write(f"# Guardian-OT Forensic Report\n\n")
        f.write(f"- **Target:** `{os.path.basename(path)}`\n")
        f.write(f"- **Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"- **Device UUID:** `{device_uuid}`\n")
        f.write(f"- **Total Scanned:** {len(results)}\n\n")
        
        if anomalies:
            f.write(f"## 🚩 High-Signal Findings ({len(anomalies)})\n\n")
            f.write("| Status | File Path | Entropy | Priority |\n")
            f.write("| :--- | :--- | :--- | :--- |\n")
            for a in anomalies:
                status_icon = "🛑" if "SIG MATCH" in a['priority'] else "⚠️"
                f.write(f"| {status_icon} {a['state']} | `{a['path']}` | {a['entropy']} | {a['priority']} |\n")
        else:
            f.write("## ✅ Integrity Check Passed\nNo anomalies or signature matches detected since last audit.\n")

    return json_path, md_path