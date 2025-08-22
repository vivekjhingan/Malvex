# Malvex

Malvex is a work-in-progress, cross-platform, modern antivirus and malware scanner with both GUI and CLI interfaces. It supports real-time protection, archive scanning, and custom signature management.

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
   git clone https://github.com/Abdul040722/Antivirus-Software.git
   cd maldefender
   ```

2. **(Optional) Create a virtual environment:**

   ```sh
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Run the application:**

   ```sh
   python run_malvex.py
   ```

   This will auto-install dependencies like `watchdog` and `rarfile` if missing.

## Usage

### GUI Mode

```sh
python run_malvex.py
```

- Launches the Tkinter-based GUI  
- Select folders to scan  
- View and quarantine detected threats  
- Manage your signature database  
- Enable real-time protection  

### CLI Mode

```sh
python run_malvex.py --scan /path/to/scan
python run_malvex.py --add-signature <HASH> --hash-type sha256
python run_malvex.py --monitor /path/to/folder
python run_malvex.py --restore <FILENAME>
python run_malvex.py --help
```

>  **Tip**: Run with appropriate permissions to scan protected directories effectively.

## Project Structure

```bash
run_malvex.py
README.md
maldefender/
├── __init__.py
├── app_config.py
├── app_logger.py
├── archive_scanner.py
├── behavior_engine.py
├── cli.py
├── emailer.py
├── file_utils.py
├── gui.py
├── malware_scanner.py
├── realtime_monitor.py
├── reputation_cache.py
├── rollback_journal.py
├── scheduler.py
├── send_weekly.py
├── signature_db.py
├── visualizer.py
├── yara_scanner.py
```

## Configuration & Logs

- **Windows**: `%APPDATA%\MalDefender`  
- **Linux/macOS**: `~/.maldefender`  

## Dependencies

- Python 3.7+
- `watchdog`
- `rarfile`
- Tkinter (usually pre-installed)

## Security Notice

- This tool is for **educational and research** purposes only.  
- Not meant to replace commercial antivirus solutions.  
- Keep your system and software updated at all times.

## Limitations

- Only static signature-based detection (MD5/SHA256)  
- Cannot detect polymorphic/unknown malware  
- Archive support limited to `.zip` and `.rar`   
- Real-time protection limited to specific folders  
- No support for password-protected or corrupted archives  

## Recommendations

- Use alongside a reputable antivirus tool  
- Be cautious with files from unknown sources  
- Backup data before quarantining  
- Regularly update your OS and app  
- Contribute new malware hashes to strengthen detection  
