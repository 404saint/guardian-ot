import sys
import os
from core.crawler import scan_usb
from core.database import init_db, get_volume_state, update_volume_state
from core.fingerprint import get_usb_uuid, generate_tree_hash
from core.reporter import save_report 

def main():
    init_db()

    if len(sys.argv) < 2:
        print("\n[!] Guardian-OT Error: No target path provided.")
        return

    path = sys.argv[1]
    if not os.path.exists(path):
        print(f"\n[!] Error: Path '{path}' not found.")
        return

    try:
        print(f"[*] Analyzing hardware identity...")
        device_uuid = get_usb_uuid(path)
        current_tree_hash = generate_tree_hash(path)
        known_tree_hash = get_volume_state(device_uuid)

        print(f"[*] Device UUID: {device_uuid}")

        # Baseline Check
        if known_tree_hash == current_tree_hash:
            print("\n" + "="*80)
            print(f" [+] TRUSTED: Hardware and File Tree match the Vault. Device is SAFE.")
            print("="*80 + "\n")
            return

        print(f"[*] Device state changed or new. Triggering Deep Scan...")
        results = scan_usb(path)
        
        # Update Vault with new fingerprint
        update_volume_state(device_uuid, current_tree_hash)
        
        # Filter for the report
        high_signal = [a for a in results if (
            a['state'] in ["NEW", "MODIFIED"] or 
            "SIG MATCH" in a['priority']
        )]
       
        unchanged_count = len([a for a in results if a['state'] == "UNCHANGED"])

        print("\n" + "="*80)
        print(f"       GUARDIAN-OT FORENSIC REPORT: {os.path.basename(path)}")
        print("="*80)

        if high_signal:
            for asset in high_signal:
                if "SIG MATCH" in asset['priority']:
                    tag, color = asset['priority'], "!!!"
                elif asset['state'] == "MODIFIED":
                    tag, color = "MODIFIED", "!!!"
                else:
                    tag, color = "NEW FILE", " + "

                print(f" [{color}] {tag}")
                print(f"       File:    {asset['path']}")
                print(f"       Entropy: {asset['entropy']} | State: {asset['state']}")
                if asset.get('signatures'):
                    print(f"       Threats: {', '.join(asset['signatures'])}")
                print("-" * 40)
        
        print(f"\n[*] {unchanged_count} assets verified and unchanged.")
        print(f"[*] Total Data: {sum(a['size_kb'] for a in results) / 1024:.2f} MB")

        # AUTO-EXPORT
        json_file, md_file = save_report(path, results, device_uuid)
        print(f"\n[*] Forensic JSON: {json_file}")
        print(f"[*] Documentation MD: {md_file}\n")

    except KeyboardInterrupt:
        sys.exit(0)

if __name__ == "__main__":
    main()