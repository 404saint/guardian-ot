import os
from .hasher import get_file_hash
from .database import check_asset_state, update_asset
from .signatures import SignatureScanner  # New Import

# OT-Specific file signatures
CRITICAL_EXTENSIONS = {'.pcl', '.bin', '.hex', '.dat', '.project', '.bak', '.wim', '.iso'}

def scan_usb(mount_path):
    """
    Recursively walk the USB and build the asset list with Differential Auditing.
    """
    assets = []
    
    # 1. Initialize the Signature Engine
    scanner = SignatureScanner()
    
    print(f"[*] Starting deep state-aware scan: {mount_path}")

    for root, dirs, files in os.walk(mount_path):
        # Skip noisy system folders
        dirs[:] = [d for d in dirs if not d.startswith('.') and d != 'System Volume Information']
        
        for file in files:
            full_path = os.path.join(root, file)
            rel_path = os.path.relpath(full_path, mount_path)
            
            print(f" [*] Analyzing: {rel_path[:50]}...", end="\r", flush=True)
            
            ext = os.path.splitext(file)[1].lower()
            
            # 2. Forensic Engine (Hashing, Entropy, Magic)
            forensics = get_file_hash(full_path)
            current_hash = forensics["sha256"]
            
            # 3. Database Engine: Compare current state to the Vault
            state = check_asset_state(rel_path, current_hash)
            
            # 4. Signature Engine: Check for malware/OT patterns
            matches = scanner.scan_file(full_path)
            
            # 5. Priority Logic
            priority = "standard"
            if ext in CRITICAL_EXTENSIONS:
                priority = "CRITICAL"
            
            # Catch Masquerading
            if forensics["magic"] == "4D5A" and ext not in {'.exe', '.dll', '.sys'}:
                priority = "CRITICAL (SPOOFED)"
            
            # Catch Encrypted/Packed payloads
            if forensics["entropy"] > 7.5 and ext not in {'.zip', '.7z', '.rar', '.iso'}:
                if "CRITICAL" not in priority:
                    priority = "SUSPICIOUS (HIGH ENTROPY)"

            # NEW: Handle YARA matches
            if matches:
                priority = f"CRITICAL (SIG MATCH: {', '.join(matches)})"

            if os.path.exists(full_path):
                size_kb = round(os.path.getsize(full_path) / 1024, 2)
            else:
                size_kb = 0

            asset_data = {
                "path": rel_path,
                "sha256": current_hash,
                "entropy": forensics["entropy"],
                "magic": forensics["magic"],
                "priority": priority,
                "size_kb": size_kb,
                "status": forensics["status"],
                "state": state,  # NEW, UNCHANGED, or MODIFIED
                "signatures": matches # Helpful for deep reporting later
            }

            # If it's new or modified, update the database
            if state != "UNCHANGED":
                update_asset(asset_data)

            assets.append(asset_data)
    
    print("\n" + " " * 75, end="\r") 
    return assets