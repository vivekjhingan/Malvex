# maldefender/file_utils.py
import hashlib
from pathlib import Path
from typing import Tuple, Optional

class FileHasher:
    """File hashing utility with both MD5 and SHA256"""
    
    @staticmethod
    def get_hashes(file_path: Path) -> Tuple[Optional[str], Optional[str]]:
        """Calculate MD5 and SHA256 hashes of a file"""
        try:
            md5_hash = hashlib.md5()
            sha256_hash = hashlib.sha256()
            
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""): # Read in chunks
                    md5_hash.update(chunk)
                    sha256_hash.update(chunk)
            
            return md5_hash.hexdigest(), sha256_hash.hexdigest()
        except PermissionError:
            # print(f"Permission denied for hashing {file_path}") # Could be logged via Logger
            return None, None
        except Exception:
            # print(f"Error hashing file {file_path}: {e}") # Could be logged via Logger
            return None, None
