# MalDefender

MalDefender Pro is a cross-platform, modern antivirus and malware scanner with both GUI and CLI interfaces. It supports real-time protection, archive scanning, and custom signature management.

## Features

- **Modern GUI** (Tkinter-based) and full-featured CLI
- **Real-time protection** for user-specified folders
- **Signature-based scanning** (supports MD5 and SHA256)
- **Archive scanning** (`.zip`, `.rar` supported)
- **Quarantine and restore** for detected threats
- **Custom signature management** (add your own hashes)
- **Cross-platform** (Windows, Linux, macOS)

## Installation

1. **Clone the repository:**

   ```sh
   git clone https://github.com/yourusername/maldefender.git
   cd maldefender
   ```

2. **(Optional) Create a virtual environment:**

   ```sh
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Run the application:**

   ```sh
   python run_maldefender.py
   ```

   The script will check for required dependencies (`watchdog`, `rarfile`) and install them if missing.

## Usage

### GUI Mode

- **Launch the GUI:**  
  Simply run:

  ```sh
  python run_maldefender.py
  ```

  The GUI will launch by default if Tkinter is available.

- **Scan a Folder:**  
  Use the GUI to select a folder and start a scan. Detected threats will be listed, and you can choose to quarantine or ignore them.

- **Manage Signatures:**  
  Add or remove custom malware signatures directly from the GUI.

- **Configure Real-Time Protection:**  
  Specify folders to monitor for real-time protection.

### CLI Mode

- **Scan a Directory:**

  ```sh
  python run_maldefender.py --scan /path/to/scan
  ```

- **Add a Signature:**

  ```sh
  python run_maldefender.py --add-signature <HASH> --hash-type sha256
  ```

- **Enable Real-Time Protection:**

  ```sh
  python run_maldefender.py --monitor /path/to/folder
  ```

- **Restore from Quarantine:**

  ```sh
  python run_maldefender.py --restore <FILENAME>
  ```

- **View Help:**

  ```sh
  python run_maldefender.py --help
  ```

### General Tips

- Always run the application with appropriate permissions to access all files and folders you wish to scan.
- For best results, keep your custom signature database up to date.

## Configuration

- Configuration and logs are stored in:
  - **Windows:** `%APPDATA%\MalDefender`
  - **Linux/macOS:** `~/.maldefender`

## Dependencies

- Python 3.7+
- [watchdog](https://pypi.org/project/watchdog/)
- [rarfile](https://pypi.org/project/rarfile/)
- Tkinter (usually included with Python)

## Project Structure

```bash
run_maldefender.py
README.md
maldefender/
├── __init__.py
├── app_config.py
├── app_logger.py
├── archive_scanner.py
├── cli.py
├── file_utils.py
├── gui.py
├── malware_scanner.py
├── realtime_monitor.py
├── signature_db.py
```

## Recommendations

- **Do not use MalDefender Pro as your only line of defense.**  
  Always use a reputable, up-to-date antivirus solution alongside this tool.
- **Update your operating system and software regularly** to reduce vulnerabilities.
- **Be cautious with files from unknown sources.**  
  Even with scanning, avoid opening suspicious attachments or downloads.
- **Back up important data** before quarantining or deleting files, in case of false positives.
- **Review the logs** after scans to ensure no critical files were affected.
- **Contribute new signatures** if you discover new malware samples to help improve detection for all users.

## Security Notice

- This tool is for educational and research purposes.
- Do not rely on it as your sole line of defense against malware.
- Always keep your system and software up to date.

## Limitations

- Detection is based on static signatures (MD5/SHA256 hashes); it cannot detect unknown or polymorphic malware.
- Real-time protection is limited to user-specified folders and may not cover all system locations.
- Archive scanning is supported for `.zip` and `.rar` files only; other formats are not extracted.
- The application does not provide behavioral or heuristic analysis.
- Some features (e.g., real-time monitoring) may require additional permissions or dependencies on certain platforms.
- Password-protected or corrupted archives cannot be scanned.
- Not a replacement for a professional, fully-featured antivirus solution.
