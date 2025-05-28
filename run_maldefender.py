# run_maldefender.py
import sys
import subprocess
import os # For checking if running in a virtual environment

def running_in_virtualenv():
    """Check if running inside a virtual environment."""
    return (hasattr(sys, 'real_prefix') or
            (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix))

def ensure_packages():
    """Install required packages if not available."""
    required_packages = ["watchdog", "rarfile"] # tkinter is usually standard
    
    # Check if pip is available, especially if not in a venv, user might not want global installs
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("Error: 'pip' command not found or not executable. Please ensure pip is installed and in your PATH.")
        print("Cannot proceed with automatic package installation.")
        # Ask user if they want to continue without automatic installation
        if input("Do you want to attempt to run the application anyway? (y/n): ").lower() != 'y':
            sys.exit(1)
        return # Skip package installation attempt

    packages_to_install = []
    for package in required_packages:
        try:
            __import__(package)
            print(f"Package '{package}' already installed.")
        except ImportError:
            print(f"Package '{package}' not found.")
            packages_to_install.append(package)
            
    if packages_to_install:
        print(f"Attempting to install missing packages: {', '.join(packages_to_install)}")
        # Warn if not in a venv
        if not running_in_virtualenv():
            print("\nWARNING: You are not in a Python virtual environment.")
            print("Installing packages globally can affect other Python projects and system Python.")
            if input("Are you sure you want to proceed with global installation? (y/n): ").lower() != 'y':
                print("Installation cancelled by user. Please install packages manually or use a virtual environment.")
                sys.exit(1)
        
        for package in packages_to_install:
            print(f"Installing {package}...")
            try:
                # Using subprocess.run for more control if needed, but check_call is fine for this.
                subprocess.check_call([sys.executable, "-m", "pip", "install", package])
                print(f"Successfully installed {package}.")
            except subprocess.CalledProcessError as e:
                print(f"Failed to install {package}. Error: {e}")
                print(f"Please try installing it manually: pip install {package}")
                if package == "rarfile" and sys.platform != "win32":
                     print("Note: 'rarfile' may also require the 'unrar' utility to be installed on your system (e.g., via apt, yum, brew).")
                # Optionally, exit if a critical package fails, or try to continue
                # For now, we'll let it try to import again later, which will fail more gracefully.
            except FileNotFoundError: # Should be caught by initial pip check, but good to have.
                print(f"Error: 'pip' command not found during installation of {package}.")
                sys.exit(1)
        # Re-check after installation attempt
        for package in packages_to_install:
            try:
                __import__(package)
            except ImportError:
                 print(f"FATAL: Package '{package}' could not be imported even after attempting installation.")
                 sys.exit(1)


def main():
    """Main entry point for MalDefender."""
    
    # Step 1: Ensure core Tkinter is available if GUI is a possibility
    # (This is more of a pre-check for a good user experience)
    gui_possible = True
    try:
        import tkinter
    except ImportError:
        print("Warning: Tkinter module not found. GUI will not be available.")
        gui_possible = False

    # Step 2: Ensure other packages (watchdog, rarfile)
    # This will attempt to install them if missing.
    ensure_packages()

    # Step 3: Import our application modules (now that packages should be present)
    try:
        from maldefender.cli import CommandLineInterface
        from maldefender.app_config import config # For version info or direct config access if needed
        # GUI import is conditional
    except ImportError as e:
        print(f"Fatal error: Could not import application components: {e}")
        print("This might be due to a failed package installation or an issue with the application structure.")
        sys.exit(1)

    # Step 4: Decide to launch CLI or GUI
    # If '--gui' is explicitly passed, or if no arguments are given and GUI is possible
    if "--gui" in sys.argv or (len(sys.argv) == 1 and gui_possible):
        if gui_possible:
            try:
                # GUI related imports should be here, after package checks.
                import tkinter as tk # Re-import for clarity in this block
                from maldefender.gui import AntivirusGUI
                
                root = tk.Tk()
                app_gui = AntivirusGUI(root)
                # Logger is initialized within AntivirusGUI
                app_gui.logger.log(f"{config.app_name} GUI started.", "INFO")
                if config.realtime_enabled: # Check if config has it enabled by default
                    try:
                        app_gui.scanner.start_realtime_protection()
                        app_gui.update_realtime_status_display()
                    except Exception as e:
                        app_gui.logger.log(f"Failed to auto-start real-time protection: {e}", "ERROR")
                
                root.mainloop()
                # Cleanup is handled by AntivirusGUI.on_closing -> cleanup_and_destroy

            except ImportError as e: # Should not happen if gui_possible is true and ensure_packages worked
                 print(f"Error launching GUI: Required modules missing. {e}")
                 print("Attempting to fall back to CLI mode if other arguments were provided.")
                 if len(sys.argv) > 1 and "--gui" not in sys.argv : # If other args were present
                     cli_app = CommandLineInterface()
                     cli_app.run(sys.argv[1:])
                 else: # Only --gui or no args, and GUI failed
                     print("Cannot start GUI. Exiting.")
                     sys.exit(1)

            except Exception as e:
                print(f"An unexpected error occurred while starting or running the GUI: {e}")
                import traceback
                traceback.print_exc()
                sys.exit(1)
        else:
            print("GUI cannot be launched because Tkinter is not available.")
            if len(sys.argv) == 1: # No other arguments, and GUI failed
                print("No CLI arguments provided. Use --help for CLI options. Exiting.")
                sys.exit(1)
            else: # Other arguments might be present for CLI
                print("Proceeding with CLI mode based on other arguments.")
                cli_app = CommandLineInterface()
                cli_app.run(sys.argv[1:])

    else: # Launch CLI
        cli_app = CommandLineInterface()
        cli_app.run(sys.argv[1:]) # Pass all args except script name

if __name__ == "__main__":
    # For development, you might want to set PYTHONPATH=.
    # Example: export PYTHONPATH="${PYTHONPATH}:/path/to/maldefender_project"
    # Or run as a module from parent directory: python -m maldefender_project.run_maldefender --scan .
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user (main level).")
        sys.exit(0)
    except Exception as e: # Catch-all for truly unexpected errors at the top level
        print(f"A critical unexpected error occurred in main: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)