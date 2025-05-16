````markdown
# Maltector – Simple Signature-Based Antivirus Scanner

Maltector is a lightweight, terminal-based antivirus scanner built in Python. It performs a **signature-based scan** of files in a directory and can **quarantine or delete malicious files** based on known MD5 hashes.

---

## Features

- **Directory Scanning**: Recursively scans a given directory for files.
- **Signature-Based Detection**: Compares file hashes (MD5) with entries in `signatures.txt`.
- **Threat Handling Options**:
  - Delete malicious file
  - Quarantine file
  - Ignore and proceed
- **Quarantine System**:
  - Moves infected files to a `quarantine/` folder with a timestamped filename.
- **Verbose Logging**:
  - Logs every scan event to `malware_scan.log` with timestamps and threat details.
- **Supported File Types**:
  - By default: `.exe`, `.py`
  - Unsupported types are scanned but flagged.

---

## Usage

```bash
python maltector.py /path/to/scan
````

### Example:

```bash
python maltector.py ~/Documents/scripting/antivirus
```

---

## Signature Format

All signatures must be stored in `signatures.txt`, one **MD5 hash** per line.

```txt
d078256bad223e8644a074e6b7f34b7b
a63e0b5e124bdb7280dbed55bfae3ad0
```

To generate an MD5 hash for a file:

```bash
md5sum filename
```

---

## Cross-Platform Compatibility

* ✅ Works on **Linux** and **Windows**
* 🛠️ Ensure you're **not using hardcoded Unix paths** (e.g., `/home/user/`)
* ✅ Use `Path` from `pathlib` to make the script OS-independent
* ⚠️ On Windows, administrative rights may be required to move or delete `.exe` files

---

## Output

* **Logs**: `malware_scan.log` contains a record of every scan
* **Quarantine**: Infected files are stored with timestamps in `/quarantine/`

---

## Limitations

* **Not heuristic**: Can’t detect unknown or polymorphic malware — only exact MD5 matches.
* **No unpacking**: Doesn’t scan inside zip, rar, or installer packages.
* **No real-time protection**: This is an *on-demand* scanner, not a background daemon.
* **False Positives**: Files with a matching MD5 will be flagged, even if they’re safe.
* **Duplicate scans**: Currently, the scanner will re-scan files placed in quarantine if the `quarantine/` folder is inside the scanned directory.

---

## Recommendation

Keep your `quarantine/` folder **outside the main scanning directory** to avoid redundant scans of already quarantined malware:

```bash
.
├── maltector.py
├── signatures.txt
├── malware_scan.log
├── quarantine/     ← move this elsewhere if needed
```

Or, modify the script to ignore the quarantine path during scanning.

---

## Future Improvements

* Add SHA256 support
* Support zip/rar scanning
* Real-time file system monitoring
* Ignore quarantine folder by default
* GUI using Tkinter, PyQt, or whatever's convenient

```
---