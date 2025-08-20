# run_malvex.py
import sys
import subprocess
import os # For checking if running in a virtual environment

def running_in_virtualenv():
    """Check if running inside a virtual environment."""
    return (hasattr(sys, 'real_prefix') or
            (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix))
def ensure_packages():
    """Install required packages if not available."""
    required_packages = ["watchdog", "rarfile", "yara-python"]
    non_interactive = not sys.stdin.isatty()

    # Ensure pip exists
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "--version"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        print("Error: pip not available.")
        if non_interactive:
            sys.exit(1)
        if input("Run anyway without installing deps? (y/n): ").lower() != "y":
            sys.exit(1)
        return

    to_install = []
    for pkg in required_packages:
        try:
            __import__(pkg)
        except ImportError:
            to_install.append(pkg)

    if not to_install:
        return

    if not running_in_virtualenv() and non_interactive:
        print("Not in venv; refusing global install in non-interactive mode.")
        sys.exit(1)

    if not running_in_virtualenv() and not non_interactive:
        print("\nWARNING: Not in a virtual environment.")
        if input("Proceed with global install? (y/n): ").lower() != "y":
            sys.exit(1)

    for pkg in to_install:
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])
        except subprocess.CalledProcessError as e:
            print(f"Failed to install {pkg}: {e}")
            sys.exit(1)

def main():
    """Main entry point for Malvex."""

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
        from malvex.cli import CommandLineInterface
        from malvex.app_config import config # For version info or direct config access if needed
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
                from malvex.gui import AntivirusGUI
                
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
    # Example: export PYTHONPATH="${PYTHONPATH}:/path/to/malvex_project"
    # Or run as a module from parent directory: python -m malvex_project.run_malvex --scan .
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