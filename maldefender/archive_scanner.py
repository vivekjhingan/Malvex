import time, shutil, zipfile, rarfile
from pathlib import Path
from typing import List, Dict, Optional
from .app_config import config
from .app_logger import Logger
from .signature_db import SignatureDatabase
from .file_utils import FileHasher

_MAX_ARCHIVE_FILES = 10_000
_MAX_EXTRACT_BYTES = 1_000_000_000
_MAX_FILE_BYTES = 200_000_000

class ArchiveScanner:
    def __init__(self, logger: Logger, sig_db: SignatureDatabase):
        self.logger = logger
        self.sig_db = sig_db

    @staticmethod
    def _is_safe_member(base: Path, target: Path) -> bool:
        try:
            target.resolve().relative_to(base.resolve())
            return True
        except Exception:
            return False

    def _extract_zip_safely(self, zf: zipfile.ZipFile, dest: Path) -> bool:
        total = 0
        infos = zf.infolist()
        if len(infos) > _MAX_ARCHIVE_FILES: return False
        for info in infos:
            member = Path(info.filename)
            out = dest / member
            if member.is_absolute() or any(p == ".." for p in member.parts) or not self._is_safe_member(dest, out):
                return False
            if info.file_size > _MAX_FILE_BYTES: return False
            total += info.file_size
            if total > _MAX_EXTRACT_BYTES: return False
        zf.extractall(dest)
        return True

    def _extract_rar_safely(self, rf: rarfile.RarFile, dest: Path) -> bool:
        total = 0
        infos = rf.infolist()
        if len(infos) > _MAX_ARCHIVE_FILES: return False
        for info in infos:
            member = Path(info.filename)
            out = dest / member
            if member.is_absolute() or any(p == ".." for p in member.parts) or not self._is_safe_member(dest, out):
                return False
            if info.file_size and info.file_size > _MAX_FILE_BYTES: return False
            if info.file_size:
                total += info.file_size
                if total > _MAX_EXTRACT_BYTES: return False
        rf.extractall(dest)
        return True

    def scan_archive(self, archive_path: Path) -> List[Dict]:
        threats: List[Dict] = []
        temp_dir: Optional[Path] = None
        try:
            base = config.base_dir / "temp_extract"
            base.mkdir(parents=True, exist_ok=True)
            temp_dir = base / str(int(time.time()))
            temp_dir.mkdir(parents=True, exist_ok=True)

            extracted = False
            suf = archive_path.suffix.lower()
            if suf == ".zip":
                with zipfile.ZipFile(archive_path, 'r') as zf:
                    extracted = self._extract_zip_safely(zf, temp_dir)
            elif suf == ".rar":
                try:
                    with rarfile.RarFile(archive_path, 'r') as rf:
                        extracted = self._extract_rar_safely(rf, temp_dir)
                except rarfile.PasswordRequired:
                    self.logger.log(f"Password-protected archive: {archive_path}", "WARNING")
                except rarfile.RarCannotExec as e:
                    self.logger.log(f"'unrar' missing for {archive_path}: {e}", "ERROR")
            else:
                self.logger.log(f"Unsupported archive type: {archive_path}", "INFO")
                return threats

            if not extracted:
                return threats

            for p in temp_dir.rglob("*"):
                if p.is_file():
                    md5_hash, sha256_hash = FileHasher.get_hashes(p)
                    if md5_hash and sha256_hash:
                        is_mal, hash_types = self.sig_db.is_malicious(md5_hash, sha256_hash)
                        if is_mal:
                            threats.append({
                                "file": str(p.relative_to(temp_dir)),
                                "archive": str(archive_path),
                                "hash_types": hash_types,
                                "md5": md5_hash,
                                "sha256": sha256_hash,
                            })
        finally:
            if temp_dir and temp_dir.exists():
                try: shutil.rmtree(temp_dir)
                except Exception as e: self.logger.log(f"Temp cleanup failed {temp_dir}: {e}", "WARNING")
        return threats
