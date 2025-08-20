# maldefender/cli.py
import argparse
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any

from .app_config import config
from .app_logger import Logger
from .malware_scanner import MalwareScanner


class CommandLineInterface:
    def __init__(self):
        self.logger = Logger()
        self.scanner = MalwareScanner(self.logger)
        # Real-time detections should also prompt in CLI:
        self.scanner.notify_threat = self._notify_threat_cli  # NEW

    def _notify_threat_cli(self, result: Dict) -> None:
        file_path = Path(str(result["file"]))
        is_archive = file_path.suffix.lower() in config.archive_types

        if is_archive:
            detail = f"{file_path.name} (archive contains threat(s))"
        else:
            t = (result.get("threats") or [{}])[0]
            ht = t.get("hash_types") or [t.get("hash_type", "N/A")]
            if not isinstance(ht, list): ht = [ht]
            detail = f"{file_path.name} | Type(s): {', '.join(ht)}"

        self.logger.log(f"\n[REAL-TIME] Threat detected: {file_path}\n  {detail}", "WARNING")
        while True:
            choice = input("[REAL-TIME] Action? [Q]uarantine / [D]elete / [I]gnore (default=I): ").strip().lower()
            if choice in {"q", "d", "i", ""}:
                break
            print("Please enter Q, D, I, or press Enter for Ignore.")

        if choice in {"", "i"}:
            self.logger.log(f"[REAL-TIME] Ignored by user: {file_path}", "INFO")
            return

        if choice == "q":
            ok, msg = self.scanner.quarantine_path(file_path)
            self.logger.log(f"[REAL-TIME] {'Quarantined' if ok else 'Failed to quarantine'}: {file_path}", "WARNING" if ok else "ERROR")
        elif choice == "d":
            ok, msg = self.scanner.delete_path(file_path)
            self.logger.log(f"[REAL-TIME] {'Deleted' if ok else 'Failed to delete'}: {file_path}", "WARNING" if ok else "ERROR")

    def run(self, args: Optional[List[str]] = None) -> None:
        """Run CLI commands. Expects sys.argv[1:] or a custom list."""
        if args is None:
            args = sys.argv[1:]

        parser = argparse.ArgumentParser(
            description=f"{config.app_name} v{config.version} - Command Line Interface",
            epilog="Examples:\n"
                   "  run_maldefender.py --scan ~/Downloads\n"
                   "  run_maldefender.py ~/Downloads --auto-action quarantine\n",
            formatter_class=argparse.RawTextHelpFormatter,
        )
        parser.add_argument(
            "path_to_scan", nargs="?",
            help="File or directory to scan. If omitted and no other action is specified, help is shown."
        )
        parser.add_argument(
            "--scan", dest="scan_path_explicit", metavar="PATH",
            help="Explicitly specify a file or directory to scan."
        )
        parser.add_argument(
            "--realtime", choices=["start", "stop"],
            help="Control real-time protection service."
        )
        parser.add_argument(
            "--add-signature", metavar="HASH",
            help="Add a new malware signature (hash) to the database."
        )
        parser.add_argument(
            "--hash-type", choices=["md5", "sha256"], default="sha256",
            help="Hash type for --add-signature. Default: sha256."
        )
        parser.add_argument(
            "--auto-action", choices=["quarantine", "delete"],
            help="Automatically act on detected threats (no prompt)."
        )
        parser.add_argument(
            "--version", action="version",
            version=f"{config.app_name} v{config.version}"
        )
        parser.add_argument(
            "--behavior", choices=["start", "stop"], 
            help="Control behavior monitor."
            )

        # Non-interactive + no args → show help and exit early
        if not args and not sys.stdin.isatty():
            parser.print_help()
            return
        # Interactive + no args → show help (GUI is launched via run_maldefender.py, not here)
        if not args and sys.stdin.isatty():
            self.logger.log("No CLI arguments provided. See options below.", "INFO")
            parser.print_help()
            return

        parsed = parser.parse_args(args=args)
        action_taken = False

        # ---- Signature management ----
        if parsed.add_signature:
            action_taken = True
            signature = parsed.add_signature.strip().lower()
            hash_type = parsed.hash_type.lower()

            valid = True
            if hash_type == "md5" and len(signature) != 32:
                self.logger.log("Invalid MD5: must be 32 hex chars.", "ERROR")
                valid = False
            elif hash_type == "sha256" and len(signature) != 64:
                self.logger.log("Invalid SHA256: must be 64 hex chars.", "ERROR")
                valid = False
            if valid and not all(c in "0123456789abcdef" for c in signature):
                self.logger.log("Invalid hash characters: expected hexadecimal.", "ERROR")
                valid = False

            if valid:
                if signature in self.scanner.sig_db.signatures[hash_type]:
                    self.logger.log(f"{hash_type.upper()} signature already exists.", "INFO")
                else:
                    self.scanner.sig_db.add_signature(signature, hash_type)
                    self.logger.log(f"Added {hash_type.upper()} signature: {signature}", "INFO")
            else:
                self.logger.log("Failed to add signature due to invalid format.", "ERROR")

        # ---- Real-time control ----
        if parsed.realtime:
            action_taken = True
            if parsed.realtime == "start":
                self.logger.log("Starting real-time protection...", "INFO")
                self.scanner.start_realtime_protection()
                self.scanner.start_behavior_monitor(self._notify_behavior_cli)
                if config.realtime_enabled:
                    self.logger.log("Real-time protection started.", "INFO")
                else:
                    self.logger.log("Real-time failed to start or no valid paths. Check logs.", "WARNING")
            else:
                self.logger.log("Stopping real-time protection...", "INFO")
                self.scanner.stop_realtime_protection()
                self.scanner.stop_behavior_monitor()
                self.logger.log("Real-time protection stopped.", "INFO")

        # ---- Scanning ----
        scan_target_str = parsed.scan_path_explicit or parsed.path_to_scan
        if scan_target_str:
            action_taken = True
            scan_target = Path(scan_target_str).resolve()
            if not scan_target.exists():
                self.logger.log(f"Scan path does not exist: {scan_target}", "ERROR")
                return

            self.logger.log(f"Starting scan on: {scan_target}", "INFO")
            if parsed.auto_action:
                self.logger.log(f"Automatic action for threats: {parsed.auto_action}", "WARNING")

            if scan_target.is_file():
                result = self.scanner.scan_file(scan_target, auto_action=parsed.auto_action)
                self.print_scan_result_cli(result)
                # Prompt only if infected and no auto-action was given
                if result.get("status") == "infected" and not parsed.auto_action:
                    self._prompt_actions_cli([result])
                self.logger.log(f"Scan of file {scan_target} complete. Stats: {self.scanner.scan_stats}", "INFO")

            elif scan_target.is_dir():
                results = self.scanner.scan_directory(scan_target)
                self.print_scan_summary_cli(results)
                # Prompt only if infections and no auto-action was given
                if not parsed.auto_action:
                    infected = [r for r in results if r.get("status") == "infected"]
                    self._prompt_actions_cli(infected)
                self.logger.log(f"Scan of directory {scan_target} complete. Overall Stats: {self.scanner.scan_stats}", "INFO")
            else:
                self.logger.log(f"Scan path is neither a file nor a directory: {scan_target}", "ERROR")

        # ---- No actionable flags ----
        if not action_taken:
            self.logger.log("No specific CLI action requested. Use --help for options.", "INFO")
            parser.print_help(sys.stderr)

    # --------- Helpers ---------
    def _prompt_actions_cli(self, infected_results: List[Dict]) -> None:
        """Interactive prompt per infected item when --auto-action is not provided."""
        if not infected_results:
            return

        for res in infected_results:
            file_path = Path(str(res["file"]))
            is_archive = file_path.suffix.lower() in config.archive_types

            # Build details line
            if is_archive:
                detail = f"{file_path.name} (archive contains threat(s))"
            else:
                t = (res.get("threats") or [{}])[0]
                ht = t.get("hash_types") or [t.get("hash_type", "N/A")]
                if not isinstance(ht, list):
                    ht = [ht]
                detail = f"{file_path.name} | Type(s): {', '.join(ht)}"

            while True:
                self.logger.log(f"\nThreat detected: {file_path}\n  {detail}", "WARNING")
                choice = input("Action? [Q]uarantine / [D]elete / [I]gnore (default=I): ").strip().lower()
                if choice in {"q", "d", "i", ""}:
                    break
                print("Please enter Q, D, I, or press Enter for Ignore.")

            if choice in {"", "i"}:
                self.logger.log(f"Ignored by user: {file_path}", "INFO")
                continue

            if choice == "q":
                ok, _ = self.scanner.quarantine_path(file_path)  # FIX
                if ok:
                    self.logger.log(f"Quarantined: {file_path}", "WARNING")
                else:
                    self.logger.log(f"Failed to quarantine: {file_path}", "ERROR")
            elif choice == "d":
                ok, _ = self.scanner.delete_path(file_path)  # FIX
                if ok:
                    self.logger.log(f"Deleted: {file_path}", "WARNING")
                else:
                    self.logger.log(f"Failed to delete: {file_path}", "ERROR")
                    
    def _notify_behavior_cli(self, incident: Dict[str, Any]) -> None:
        """CLI prompt when behavior incident fires."""
        proc = incident.get("process", {})
        exe = proc.get("exe") or "Unknown"
        pid = incident.get("pid")
        score = incident.get("score", 0)
        reasons = ", ".join([f"{rh['rule_id']}({rh['weight']})" for rh in incident.get("rule_hits", [])])

        self.logger.log(f"\n[BEHAVIOR] Incident score={score} PID={pid} EXE={exe}\n  Rules: {reasons}", "WARNING")

        while True:
            choice = input("[BEHAVIOR] Action? [K]ill / [Q]uarantine drops / [R]ollback recent / [I]gnore (default=I): ").strip().lower()
            if choice in {"k", "q", "r", "i", ""}:
                break
            print("Please enter K, Q, R, I or Enter for Ignore.")

        try:
            if choice == "k":
                try:
                    import psutil
                    psutil.Process(int(pid)).kill()
                    self.logger.log(f"[BEHAVIOR] Killed PID {pid}", "WARNING")
                except Exception as e:
                    self.logger.log(f"[BEHAVIOR] Kill failed for PID {pid}: {e}", "ERROR")
            elif choice == "q":
                # quarantine recently created executables/scripts
                cnt = self.scanner.behavior.rollback.rollback() if self.scanner.behavior else 0
                self.logger.log(f"[BEHAVIOR] Quarantined/removed {cnt} recent files (rollback).", "WARNING")
            elif choice == "r":
                cnt = self.scanner.behavior.rollback.rollback() if self.scanner.behavior else 0
                self.logger.log(f"[BEHAVIOR] Rollback handled {cnt} files.", "WARNING")
            else:
                self.logger.log(f"[BEHAVIOR] Ignored incident for PID {pid}", "INFO")
        except Exception as e:
            self.logger.log(f"[BEHAVIOR] action error: {e}", "ERROR")

    # --------- Output formatting ---------
    def print_scan_result_cli(self, result: Dict) -> None:
        """Print a single scan result to the console."""
        status = result.get("status", "clean")
        status_icon = (
            "🦠 INFECTED" if status == "infected" else
            ("⚠️ ERROR" if "error" in status else
             ("❔ SKIPPED" if "skipped" in status else "✅ CLEAN"))
        )
        self.logger.log(f"{status_icon} - {result['file']}", "RESULT")

        if status == "infected" and result.get("threats"):
            for threat in result["threats"]:
                # Normalize hash_types
                hash_types = threat.get("hash_types")
                if not hash_types:
                    ht = threat.get("hash_type")
                    hash_types = ht if isinstance(ht, list) else ([ht] if ht else [])
                hash_types = [str(x) for x in hash_types]

                if "archive" in threat:
                    msg = (f"  ➡️ Threat in archive '{Path(threat['archive']).name}': "
                           f"File: '{threat['file']}', Type(s): {', '.join(hash_types)} Match")
                else:
                    msg = f"  ➡️ Threat Type(s): {', '.join(hash_types)} Match"
                self.logger.log(msg, "RESULT")

        if result.get("action_taken"):
            self.logger.log(f"  ➡️ Action: {str(result['action_taken']).capitalize()}", "RESULT")

    def print_scan_summary_cli(self, results: List[Dict]) -> None:
        """Print a summary of multiple scan results to the console."""
        infected: List[Dict] = []
        for r in results:
            if r.get("status") == "infected":
                infected.append(r)
            elif "error" in r.get("status", "") or "skipped" in r.get("status", ""):
                self.print_scan_result_cli(r)

        stats = self.scanner.scan_stats
        self.logger.log("\n📊 Scan Summary:", "INFO")
        self.logger.log(f"  Total Items Processed (files/archives): {stats['files_scanned']}", "INFO")
        self.logger.log(f"  Archives Scanned: {stats['archives_scanned']}", "INFO")
        self.logger.log(f"  Total Threats Detected: {stats['threats_found']}", "INFO")
        self.logger.log(f"  Scan Errors: {stats['errors']}", "INFO")

        if infected:
            self.logger.log("\n🦠 Infected Item Details:", "WARNING")
            for res in infected:
                self.print_scan_result_cli(res)


if __name__ == "__main__":
    CommandLineInterface().run()
