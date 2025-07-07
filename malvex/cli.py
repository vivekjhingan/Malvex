# malvex/cli.py
import argparse
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional

# Relative imports for components within the 'malvex' package
from .app_config import config
from .app_logger import Logger
from .malware_scanner import MalwareScanner
# from .gui import AntivirusGUI # This will be imported in run_malvex.py if GUI is chosen

class CommandLineInterface:
    """Command line interface for headless operation"""    
    
    def __init__(self):
        # CLI uses its own logger instance, not tied to GUI callback here
        self.logger = Logger()
        self.scanner = MalwareScanner(self.logger, self.prompt_realtime_action_cli)

    def prompt_realtime_action_cli(self, file_path: Path, result: Dict) -> str:
        """Prompt user in console for action on real-time threats."""
        while True:
            choice = input(
                f"Threat detected: {file_path} (status: {result['status']}). Action? [i]gnore/[q]uarantine/[d]elete: "
            ).strip().lower()
            if choice in {"i", "ignore"}:
                return "ignore"
            if choice in {"q", "quarantine"}:
                return "quarantine"
            if choice in {"d", "delete"}:
                return "delete"
            print("Invalid choice. Please enter i, q, or d.")
    
    def run(self, args: Optional[List[str]] = None): # args can be None if called directly
        """Run CLI commands. Expects sys.argv[1:] or custom list."""
        if args is None: # If no args are passed (e.g. direct call), use sys.argv
            args = sys.argv[1:]

        parser = argparse.ArgumentParser(
            description=f"{config.app_name} v{config.version} - Command Line Interface",
            epilog="If no arguments are provided, the GUI will attempt to launch (if available)."
        )
        parser.add_argument(
            "path_to_scan", nargs="?", # Optional positional argument
            help="File or directory to scan. If omitted and no other action specified, GUI launches."
        )
        parser.add_argument(
            "--scan", dest="scan_path_explicit", metavar="PATH",
            help="Explicitly specify a file or directory to scan."
        )
        parser.add_argument(
            "--realtime", choices=["start", "stop"], 
            help="Control real-time protection service (if supported)."
        )
        parser.add_argument(
            "--add-signature", metavar="HASH",
            help="Add a new malware signature (hash) to the database."
        )
        parser.add_argument(
            "--hash-type", choices=["md5", "sha256"], default="sha256", 
            help="Specify hash type (md5 or sha256) for --add-signature. Default: sha256."
        )
        parser.add_argument(
            "--auto-action", choices=["quarantine", "delete"], 
            help="Automatic action for detected threats (use with caution): 'quarantine' or 'delete'."
        )
        parser.add_argument(
            "--version", action="version", 
            version=f"{config.app_name} v{config.version}"
        )
        # --gui flag is handled by run_malvex.py now.
        # If no other CLI specific args are given, run_malvex.py will try to launch GUI.

        # Handle case where only script name is run (no args) or --gui is passed
        # This logic is now primarily in run_malvex.py
        if not args and not sys.stdin.isatty(): # If running non-interactively with no args, show help
            parser.print_help()
            return
        
        # If args is empty and it's an interactive terminal, it implies GUI should launch (handled by main script)
        # If args are present, parse them.
        if not args and sys.stdin.isatty(): # For interactive, no args means GUI
            # This path should ideally be handled by the main launcher (run_malvex.py)
            # which decides to launch GUI or CLI. If CLI is explicitly run with no args:
            self.logger.log("No CLI arguments provided. For GUI, run without CLI specific commands.", "INFO")
            parser.print_help()
            return


        parsed_args = parser.parse_args(args=args) # Pass the argument list here
        
        action_taken = False

        if parsed_args.add_signature:
            action_taken = True
            signature = parsed_args.add_signature.strip().lower()
            hash_type = parsed_args.hash_type.lower()
            
            # Basic validation for hash length
            valid_hash = True
            if hash_type == "md5" and len(signature) != 32:
                self.logger.log("Invalid MD5 hash format. Must be 32 hex characters.", "ERROR")
                valid_hash = False
            elif hash_type == "sha256" and len(signature) != 64:
                self.logger.log("Invalid SHA256 hash format. Must be 64 hex characters.", "ERROR")
                valid_hash = False
            if valid_hash and not all(c in "0123456789abcdef" for c in signature):
                 self.logger.log("Invalid hash characters. Must be hexadecimal.", "ERROR")
                 valid_hash = False

            if valid_hash:
                if signature in self.scanner.sig_db.signatures[hash_type]:
                    self.logger.log(f"{hash_type.upper()} signature already exists.", "INFO")
                else:
                    self.scanner.sig_db.add_signature(signature, hash_type)
                    self.logger.log(f"Added {hash_type.upper()} signature: {signature}", "INFO")
            else:
                self.logger.log("Failed to add signature due to invalid format.", "ERROR")


        if parsed_args.realtime:
            action_taken = True
            if parsed_args.realtime == "start":
                self.logger.log("Attempting to start real-time protection via CLI...", "INFO")
                self.scanner.start_realtime_protection()
                # Log status based on config.realtime_enabled
                if config.realtime_enabled:
                     self.logger.log("Real-time protection started successfully.", "INFO")
                else:
                     self.logger.log("Real-time protection failed to start or no valid paths. Check logs.", "WARNING")

            elif parsed_args.realtime == "stop":
                self.logger.log("Attempting to stop real-time protection via CLI...", "INFO")
                self.scanner.stop_realtime_protection()
                self.logger.log("Real-time protection stopped.", "INFO")
        
        # Determine scan path from explicit --scan or positional argument
        scan_target_path_str = parsed_args.scan_path_explicit or parsed_args.path_to_scan
        
        if scan_target_path_str:
            action_taken = True
            scan_target_path = Path(scan_target_path_str).resolve() # Resolve to absolute path
            
            if not scan_target_path.exists():
                self.logger.log(f"Scan path does not exist: {scan_target_path}", "ERROR")
                return

            self.logger.log(f"Starting scan on: {scan_target_path}", "INFO")
            if parsed_args.auto_action:
                self.logger.log(f"Automatic action for threats: {parsed_args.auto_action}", "WARNING")

            if scan_target_path.is_file():
                result = self.scanner.scan_file(scan_target_path, parsed_args.auto_action)
                self.print_scan_result_cli(result)
                self.logger.log(f"Scan of file {scan_target_path} complete. Stats: {self.scanner.scan_stats}", "INFO")
            elif scan_target_path.is_dir():
                results = self.scanner.scan_directory(scan_target_path) # auto_action is handled by scan_file within scan_directory
                self.print_scan_summary_cli(results)
                self.logger.log(f"Scan of directory {scan_target_path} complete. Overall Stats: {self.scanner.scan_stats}", "INFO")
            else:
                self.logger.log(f"Scan path is neither a file nor a directory: {scan_target_path}", "ERROR")
        
        if not action_taken and not (len(args) == 1 and args[0] == "--gui"): # If no specific CLI action was performed by *this* module
            # This case should ideally be caught by run_malvex.py to launch GUI
            # If CLI is explicitly run (e.g. python -m malvex.cli) with no args:
            self.logger.log("No specific CLI action requested. Use --help for options.", "INFO")
            parser.print_help(sys.stderr) # Print help to stderr if no action

    def print_scan_result_cli(self, result: Dict):
        """Print a single scan result to the console."""
        status_icon = "🦠 INFECTED" if result["status"] == "infected" else \
                      ("⚠️ ERROR" if "error" in result["status"] else \
                      ("❔ SKIPPED" if "skipped" in result["status"] else "✅ CLEAN"))
        
        self.logger.log(f"{status_icon} - {result['file']}", "RESULT") # Using a custom level for direct output
        
        if result["status"] == "infected" and result.get("threats"):
            for threat in result["threats"]:
                if "archive" in threat:  # Threat found inside an archive
                    hash_types = threat.get("hash_types") or [threat.get("hash_type", "N/A")]
                    log_msg = (f"  ➡️ Threat in archive '{Path(threat['archive']).name}': "
                               f"File: '{threat['file']}', Type(s): {', '.join(hash_types)} Match")
                else:  # Threat is the file itself
                    hash_types = threat.get("hash_types") or [threat.get("hash_type", "N/A")]
                    log_msg = f"  ➡️ Threat Type(s): {', '.join(hash_types)} Match"
                self.logger.log(log_msg, "RESULT")
        
        if result.get("action_taken"):
            self.logger.log(f"  ➡️ Action: {result['action_taken'].capitalize()}", "RESULT")

    def print_scan_summary_cli(self, results: List[Dict]):
        """Print a summary of multiple scan results to the console."""
        
        infected_files_details: List[Dict] = []
        for r in results:
            if r["status"] == "infected":
                infected_files_details.append(r)
            elif "error" in r["status"] or "skipped" in r["status"]: # Also log errors/skipped files in summary
                 self.print_scan_result_cli(r)


        stats = self.scanner.scan_stats # Use the consolidated stats from MalwareScanner
        self.logger.log("\n📊 Scan Summary:", "INFO")
        self.logger.log(f"  Total Items Processed (files/archives): {stats['files_scanned']}", "INFO")
        self.logger.log(f"  Archives Scanned: {stats['archives_scanned']}", "INFO")
        self.logger.log(f"  Total Threats Detected: {stats['threats_found']}", "INFO")
        self.logger.log(f"  Scan Errors: {stats['errors']}", "INFO")

        if stats['threats_found'] > 0:
            self.logger.log("\n🦠 Infected Item Details:", "WARNING")
            for res in infected_files_details:
                self.print_scan_result_cli(res) # This will log details for each infected item

if __name__ == "__main__":
    CommandLineInterface().run()