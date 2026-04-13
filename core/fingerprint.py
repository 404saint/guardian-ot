import subprocess
import hashlib
import os

def get_usb_uuid(mount_path):
    """Retrieves the hardware UUID of the partition at mount_path."""
    try:
        # We use df to find the device source, then lsblk to get the UUID
        cmd = f"lsblk -no UUID $(df --output=source {mount_path} | tail -1)"
        uuid = subprocess.check_output(cmd, shell=True).decode().strip()
        return uuid if uuid else "UNKNOWN_DEVICE"
    except Exception:
        return "UNKNOWN_DEVICE"

def generate_tree_hash(mount_path):
    """Rapidly hashes the file structure (Path + Size)."""
    tree_data = []
    for root, dirs, files in os.walk(mount_path):
        # Ignore noisy system dirs
        dirs[:] = [d for d in dirs if not d.startswith('.') and d != 'System Volume Information']
        
        for f in sorted(files):
            full_path = os.path.join(root, f)
            if os.path.exists(full_path):
                # We use file size as a 'quick change' indicator
                size = os.path.getsize(full_path)
                tree_data.append(f"{f}:{size}")
    
    combined = "|".join(tree_data)
    return hashlib.sha256(combined.encode()).hexdigest()