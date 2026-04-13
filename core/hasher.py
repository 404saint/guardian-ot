import hashlib
import math
import os

def calculate_entropy(data):
    """
    Calculates Shannon Entropy. 
    Scales from 0 (empty/predictable) to 8 (encrypted/compressed/random).
    """
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = data.count(x) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return round(entropy, 2)

def get_file_hash(file_path):
    """
    Deep Analysis Engine:
    Returns a dictionary containing SHA-256, Entropy, and Magic Byte Headers.
    """
    sha256_hash = hashlib.sha256()
    full_data = b"" # Used for entropy and magic check
    
    try:
        # We read the whole file for entropy analysis. 
        # Note: For massive files (>2GB), we should chunk entropy, 
        # but for USB assets, this provides the most accurate 'Weapon' signature.
        with open(file_path, "rb") as f:
            # First 4 bytes tell us what the file REALLY is (Magic Bytes)
            header = f.read(4)
            magic_hex = header.hex().upper()
            
            # Reset and read for hashing
            f.seek(0)
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
                # To keep it efficient, we only calculate entropy on the first 10MB 
                # if the file is massive, which is plenty for signature detection.
                if len(full_data) < 10 * 1024 * 1024:
                    full_data += byte_block

        return {
            "sha256": sha256_hash.hexdigest(),
            "entropy": calculate_entropy(full_data),
            "magic": magic_hex,
            "status": "SUCCESS"
        }

    except PermissionError:
        return {"status": "PERMISSION_DENIED", "sha256": None, "entropy": 0, "magic": None}
    except Exception as e:
        return {"status": f"ERROR: {str(e)}", "sha256": None, "entropy": 0, "magic": None}