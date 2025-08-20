# maldefender/signature_db.py
import json
from typing import Set, Tuple, Dict

from .app_config import config

class SignatureDatabase:
    """Enhanced signature database with SHA256 support"""
    
    def __init__(self):
        self.signatures: Dict[str, Set[str]] = {
            "md5": set(),
            "sha256": set()
        }
        self.load_signatures()
    
    def load_signatures(self):
        """Load signatures from JSON file"""
        if config.signatures_file.exists():
            try:
                with open(config.signatures_file) as f:
                    data = json.load(f)
                    self.signatures["md5"] = set(data.get("md5", []))
                    self.signatures["sha256"] = set(data.get("sha256", []))
            except Exception as e:
                print(f"Error loading signatures: {e}") # Basic logging
        else:
            # Initialize with default signatures (including EICAR)
            self.signatures = {
                "md5": {
                     "e10adc3949ba59abbe56e057f20f883e",
                     "5f4dcc3b5aa765d61d8327deb882cf99",
                     "098f6bcd4621d373cade4e832627b4f6",
                     "44d88612fea8a8f36de82e1278abb02f" 
                },
                "sha256": {
                    "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f",
                    "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
                    "bef57ec7f53a6d40beb640a780a639c83bc29ac8a9816f1fc6c5c6dcd93c4721",
                    "275a021bbfb64839a5b3c37b04c59101e1f78788c0cacb5fd425d2d6c39e44e5"  # EICAR SHA256
                }
            }
            self.save_signatures()
    
    def save_signatures(self):
        """Save signatures to JSON file"""
        try:
            data = {
                "md5": list(self.signatures["md5"]),
                "sha256": list(self.signatures["sha256"])
            }
            with open(config.signatures_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Error saving signatures: {e}") # Basic logging
    
    def add_signature(self, signature: str, hash_type: str = "sha256"):
        """Add a new signature"""
        if hash_type in self.signatures:
            self.signatures[hash_type].add(signature.lower())
            self.save_signatures()
    
    def is_malicious(self, md5_hash: str, sha256_hash: str) -> Tuple[bool, list]:
        """Check if hashes match any malicious signatures. Returns all matching types."""
        matches = []
        if md5_hash and md5_hash.lower() in self.signatures["md5"]:
            matches.append("MD5")
        if sha256_hash and sha256_hash.lower() in self.signatures["sha256"]:
            matches.append("SHA256")
        return (len(matches) > 0, matches)
