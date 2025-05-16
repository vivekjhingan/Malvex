
#!/usr/bin/env python3
import os
import shutil
import hashlib
import time
import argparse
from datetime import datetime

# Configuration
QUARANTINE_DIR = "quarantine"
SIGNATURES_FILE = "signatures.txt"
SUPPORTED_TYPES = [".exe", ".dll", ".bat", ".ps1", ".sh", ".py", ".js"]
LOG_FILE = "malware_scan.log"

# Ensure directories exist
os.makedirs(QUARANTINE_DIR, exist_ok=True)

# Initialize signatures (in real app, this would be a database of known malware signatures)
DEFAULT_SIGNATURES = [
    "e10adc3949ba59abbe56e057f20f883e",  # Example signature 1
    "5f4dcc3b5aa765d61d8327deb882cf99",  # Example signature 2
    "098f6bcd4621d373cade4e832627b4f6",  # Example signature 3
]

def initialize_signatures():
    """Initialize the signatures file if it doesn't exist"""
    if not os.path.exists(SIGNATURES_FILE):
        with open(SIGNATURES_FILE, "w") as f:
            for sig in DEFAULT_SIGNATURES:
                f.write(f"{sig}\n")

def log_message(message, level="INFO"):
    """Log a message to the log file and print to console"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] [{level}] {message}"
    
    print(log_entry)
    
    with open(LOG_FILE, "a") as log_file:
        log_file.write(log_entry + "\n")

def get_file_hash(file_path):
    """Calculate MD5 hash of a file"""
    md5_hash = hashlib.md5()
    
    try:
        with open(file_path, "rb") as f:
            # Read file in chunks to handle large files
            for chunk in iter(lambda: f.read(4096), b""):
                md5_hash.update(chunk)
        return md5_hash.hexdigest()
    except Exception as e:
        log_message(f"Error hashing file {file_path}: {str(e)}", "ERROR")
        return None

def check_file_type(file_path):
    """Check if the file type is supported"""
    _, file_extension = os.path.splitext(file_path)
    is_supported = file_extension.lower() in SUPPORTED_TYPES
    
    if is_supported:
        log_message(f"File type {file_extension} is supported")
    else:
        log_message(f"File type {file_extension} is not supported")
    
    return is_supported

def signature_detection(file_path):
    """Check if the file matches any known malicious signatures"""
    file_hash = get_file_hash(file_path)
    
    if not file_hash:
        return False
    
    with open(SIGNATURES_FILE, "r") as f:
        signatures = [line.strip() for line in f.readlines()]
    
    is_malicious = file_hash in signatures
    
    if is_malicious:
        log_message(f"Malicious signature found in {file_path}", "WARNING")
    else:
        log_message(f"No malicious signature found in {file_path}")
    
    return is_malicious

def quarantine_file(file_path):
    """Move the file to quarantine directory"""
    try:
        filename = os.path.basename(file_path)
        quarantine_path = os.path.join(QUARANTINE_DIR, f"{filename}.{int(time.time())}")
        shutil.move(file_path, quarantine_path)
        log_message(f"File quarantined: {file_path} -> {quarantine_path}")
        log_message(f"Quarantine successful for {file_path}")
        print(f"🔒 File quarantined: {quarantine_path}")
        return True
    except Exception as e:
        log_message(f"Quarantine failed for {file_path}: {str(e)}", "ERROR")
        return False

def remove_malware(file_path):
    """Attempt to remove the malware"""
    try:
        os.remove(file_path)
        log_message(f"File removed: {file_path}")
        print(f"🗑️ Removed malicious file: {file_path}")
        return True
    except Exception as e:
        log_message(f"Removal failed for {file_path}: {str(e)}", "ERROR")
        print(f"❌ Failed to remove malicious file: {file_path}")
        return False

def scan_file(file_path, auto_fix=False):
    """Scan a single file for malware"""
    log_message(f"Scanning file: {file_path}")
    print(f"🔍 Scanning: {file_path}")
    
    # Step 1: Check file type
    if not check_file_type(file_path):
        log_message(f"Unsupported file type: {file_path}")
        print(f"⚠️ Unsupported file type, scanning anyway...")
    
    # Step 2: Signature-based detection
    is_malicious = signature_detection(file_path)
    
    if is_malicious:
        log_message(f"Malicious file detected: {file_path}")
        
        if auto_fix:
            action = "remove"
        else:
            print(f"\n⚠️ THREAT FOUND in {file_path} ⚠️")
            print("What would you like to do?")
            print("1. Remove the file")
            print("2. Quarantine the file")
            print("3. Ignore the threat")
            
            choice = input("\nEnter your choice (1-3): ")
            
            actions = {
                "1": "remove",
                "2": "quarantine",
                "3": "ignore"
            }
            action = actions.get(choice, "ignore")
        
        if action == "remove":
            success = remove_malware(file_path)
            if success:
                log_message(f"Successfully removed: {file_path}")
            else:
                log_message(f"Failed to remove: {file_path}", "ERROR")
        
        elif action == "quarantine":
            success = quarantine_file(file_path)
            if success:
                log_message(f"Successfully quarantined: {file_path}")
            else:
                log_message(f"Failed to quarantine: {file_path}", "ERROR")
        
        else:  # ignore
            log_message(f"User chose to ignore threat: {file_path}")
            print(f"🚨 Warning: Ignoring potential threat in {file_path}")
    
    else:
        log_message(f"File is clean: {file_path}")
        print(f"✅ Clean: No threats found in {file_path}")

def scan_directory(directory_path, auto_fix=False):
    """Recursively scan a directory for malware"""
    log_message(f"Starting scan of directory: {directory_path}")
    print(f"🔍 Scanning directory: {directory_path}")
    
    file_count = 0
    threat_count = 0
    
    for root, _, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            file_count += 1
            
            # Check if file is malicious
            if signature_detection(file_path):
                threat_count += 1
            
            # Process the file
            scan_file(file_path, auto_fix)
    
    log_message(f"Scan completed. Scanned {file_count} files, found {threat_count} threats.")
    print(f"\n✅ Scan completed. Scanned {file_count} files, found {threat_count} threats.")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Simple Malware Scanner CLI")
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument("--auto-fix", action="store_true", help="Automatically remove threats")
    parser.add_argument("--add-signature", help="Add a new malware signature")
    
    args = parser.parse_args()
    
    # Initialize signatures
    initialize_signatures()
    
    # Add new signature if requested
    if args.add_signature:
        with open(SIGNATURES_FILE, "a") as f:
            f.write(f"{args.add_signature}\n")
        log_message(f"Added new signature: {args.add_signature}")
        print(f"✅ Added new signature: {args.add_signature}")
    
    # Scan the specified path
    scan_path = args.path
    
    if os.path.isfile(scan_path):
        scan_file(scan_path, args.auto_fix)
    elif os.path.isdir(scan_path):
        scan_directory(scan_path, args.auto_fix)
    else:
        log_message(f"Invalid path: {scan_path}", "ERROR")
        print(f"❌ Error: Invalid path '{scan_path}'")

if __name__ == "__main__":
    main()