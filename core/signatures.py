import yara
import os

class SignatureScanner:
    def __init__(self, rules_dir="signatures"):
        self.rules_path = rules_dir
        self.rules = None
        self._load_rules()

    def _load_rules(self):
        """Compiles all .yar files in the signatures directory."""
        if not os.path.exists(self.rules_path):
            os.makedirs(self.rules_path)
            
        rule_files = {}
        for root, _, files in os.walk(self.rules_path):
            for f in files:
                if f.endswith(".yar") or f.endswith(".yara"):
                    rule_files[f] = os.path.join(root, f)

        if rule_files:
            try:
                self.rules = yara.compile(filepaths=rule_files)
                print(f"[*] Loaded {len(rule_files)} YARA rule files.")
            except yara.SyntaxError as e:
                print(f"[!] YARA Compilation Error: {e}")
        else:
            print("[!] No YARA rules found in /signatures. Skipping sig-check.")

    def scan_file(self, file_path):
        """Scans a file against the compiled YARA rules."""
        if not self.rules or not os.path.exists(file_path):
            return []
        
        try:
            matches = self.rules.match(file_path)
            # Return a list of rule names that matched
            return [str(match) for match in matches]
        except Exception:
            return []