# malvex/archive_scanner.py
import time
import shutil
import zipfile
import rarfile # Ensure rarfile is handled in main installation check
from pathlib import Path
from typing import List, Dict, Optional

from .app_config import config
from .app_logger import Logger
from .signature_db import SignatureDatabase
from .file_utils import FileHasher

class ArchiveScanner:
    """Archive scanning for zip, rar, and other compressed files"""
    
    def __init__(self, logger: Logger, sig_db: SignatureDatabase):
        self.logger = logger
        self.sig_db = sig_db

    def _safe_extract_zip(self, zip_file: zipfile.ZipFile, extract_dir: Path) -> bool:
        """Safely extract zip archives, preventing path traversal."""
        for member in zip_file.namelist():
            member_path = extract_dir / member
            if not member_path.resolve().startswith(extract_dir.resolve()):
                self.logger.log(f"Blocked suspicious zip path: {member}", "WARNING")
                return False
        zip_file.extractall(extract_dir)
        return True

    def _safe_extract_rar(self, rar_file: rarfile.RarFile, extract_dir: Path) -> bool:
        """Safely extract rar archives, preventing path traversal."""
        for member in rar_file.infolist():
            member_path = extract_dir / member.filename
            if not member_path.resolve().startswith(extract_dir.resolve()):
                self.logger.log(f"Blocked suspicious rar path: {member.filename}", "WARNING")
                return False
        rar_file.extractall(extract_dir)
        return True
    
    def scan_archive(self, archive_path: Path) -> List[Dict]:
        """Scan files inside archives"""
        threats: List[Dict] = []
        temp_dir: Optional[Path] = None # Keep temp_dir optional
        
        try:
            # Create temporary extraction directory
            # Ensure temp_extract base directory exists
            temp_extract_base = config.base_dir / "temp_extract"
            temp_extract_base.mkdir(parents=True, exist_ok=True)
            temp_dir = temp_extract_base / str(int(time.time()))
            temp_dir.mkdir(parents=True, exist_ok=True)
            
            # Extract based on file type
            file_suffix_lower = archive_path.suffix.lower()
            extracted = False
            if file_suffix_lower == ".zip":
                with zipfile.ZipFile(archive_path, 'r') as zip_file:
                    if not self._safe_extract_zip(zip_file, temp_dir):
                        return threats
                extracted = True
            elif file_suffix_lower == ".rar":
                try:
                    with rarfile.RarFile(archive_path, 'r') as rar_file:
                        if not self._safe_extract_rar(rar_file, temp_dir):
                            return threats
                    extracted = True
                except rarfile.PasswordRequired:
                    self.logger.log(f"Archive {archive_path} is password protected and cannot be scanned.", "WARNING")
                except rarfile.RarCannotExec as e: # Handles missing unrar utility
                    self.logger.log(f"Cannot extract RAR {archive_path}. 'unrar' utility might be missing or not in PATH: {e}", "ERROR")
                except Exception as e: # Catch other rarfile specific errors
                    self.logger.log(f"Error extracting RAR {archive_path}: {e}", "ERROR")

            # Add more archive types if needed (e.g., .7z, .tar.gz)
            # For .7z: requires py7zr, import py7zr
            # For .tar, .tar.gz, .tar.bz2: requires tarfile, import tarfile

            else:
                self.logger.log(f"Unsupported archive type: {archive_path.suffix} for {archive_path}")
                return threats # Return empty list if not extracted
            
            if not extracted: # If extraction failed or was skipped
                 return threats

            # Scan extracted files
            for extracted_file_path in temp_dir.rglob("*"):
                if extracted_file_path.is_file():
                    # Pass the full path to get_hashes
                    md5_hash, sha256_hash = FileHasher.get_hashes(extracted_file_path)
                    if md5_hash and sha256_hash: # Ensure hashes were obtained
                        is_malicious, hash_type = self.sig_db.is_malicious(md5_hash, sha256_hash)
                        if is_malicious:
                            threats.append({
                                "file": str(extracted_file_path.relative_to(temp_dir)), # Store relative path within archive
                                "archive": str(archive_path),
                                "hash_type": hash_type,
                                "md5": md5_hash,
                                "sha256": sha256_hash
                            })
        
        except FileNotFoundError:
            self.logger.log(f"Archive file not found: {archive_path}", "ERROR")
        except zipfile.BadZipFile:
            self.logger.log(f"Invalid or corrupted ZIP file: {archive_path}", "ERROR")
        # rarfile exceptions are handled above
        except Exception as e:
            self.logger.log(f"Error scanning archive {archive_path}: {e}", "ERROR")
        
        finally:
            # Clean up temporary files
            if temp_dir and temp_dir.exists():
                try:
                    shutil.rmtree(temp_dir)
                except Exception as e:
                    self.logger.log(f"Error cleaning temp files at {temp_dir}: {e}", "WARNING")
        
        return threats