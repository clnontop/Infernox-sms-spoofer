#!/usr/bin/env python3
"""
Infernox - Advanced SMS Spoofing Framework
Kali Linux Optimized Version
"""

import os
import sys
import subprocess
import logging
from pathlib import Path
import signal
import time

# ASCII Art Banner
BANNER = """
\033[91m
██╗███╗   ██╗███████╗███████╗██████╗ ███╗   ██╗ ██████╗ ██╗  ██╗
██║████╗  ██║██╔════╝██╔════╝██╔══██╗████╗  ██║██╔═══██╗╚██╗██╔╝
██║██╔██╗ ██║█████╗  █████╗  ██████╔╝██╔██╗ ██║██║   ██║ ╚███╔╝ 
██║██║╚██╗██║██╔══╝  ██╔══╝  ██╔══██╗██║╚██╗██║██║   ██║ ██╔██╗ 
██║██║ ╚████║██║     ███████╗██║  ██║██║ ╚████║╚██████╔╝██╔╝ ██╗
╚═╝╚═╝  ╚═══╝╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝
\033[0m
\033[93m          Advanced SMS Spoofing Framework v2.0\033[0m
\033[92m        Optimized for Kali Linux & Penetration Testing\033[0m
\033[91m              ⚠️  AUTHORIZED USE ONLY ⚠️\033[0m
"""

def print_banner():
    """Print the Infernox banner"""
    print(BANNER)
    print("\033[96m" + "="*65 + "\033[0m")

def check_kali_environment():
    """Check if running on Kali Linux"""
    try:
        with open('/etc/os-release', 'r') as f:
            content = f.read()
            if 'kali' in content.lower():
                print("\033[92m✅ Kali Linux detected\033[0m")
                return True
            else:
                print("\033[93m⚠️  Not running on Kali Linux (but that's okay)\033[0m")
                return True
    except:
        print("\033[93m⚠️  Could not detect OS (continuing anyway)\033[0m")
        return True

def check_root_privileges():
    """Check if running with appropriate privileges"""
    if os.geteuid() == 0:
        print("\033[91m⚠️  Running as root - be careful!\033[0m")
    else:
        print("\033[92m✅ Running as regular user\033[0m")

def setup_kali_environment():
    """Setup Kali-specific environment"""
    # Create directories
    directories = ['logs', 'data', 'reports']
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
        print(f"\033[92m✅ Directory: {directory}\033[0m")
    
    # Copy Kali config if .env doesn't exist
    env_file = Path('.env')
    kali_env = Path('.env.kali')
    
    if not env_file.exists() and kali_env.exists():
        print("\033[93m📝 Creating .env from Kali template...\033[0m")
        import shutil
        shutil.copy(kali_env, env_file)
        print("\033[92m✅ Kali configuration applied\033[0m")

def check_gsm_devices():
    """Check for GSM modems on Kali"""
    print("\033[96m🔍 Scanning for GSM devices...\033[0m")
    
    # Check common USB serial devices
    usb_devices = ['/dev/ttyUSB0', '/dev/ttyUSB1', '/dev/ttyACM0', '/dev/ttyACM1']
    found_devices = []
    
    for device in usb_devices:
        if Path(device).exists():
            found_devices.append(device)
            print(f"\033[92m✅ Found device: {device}\033[0m")
    
    if not found_devices:
        print("\033[93m⚠️  No GSM devices found (USB modems)\033[0m")
        print("\033[96m💡 Tip: Connect GSM modem and run 'lsusb' to check\033[0m")
    
    return found_devices

def install_dependencies():
    """Install Python dependencies"""
    print("\033[96m📦 Installing dependencies...\033[0m")
    
    try:
        subprocess.check_call([
            sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt', '--quiet'
        ])
        print("\033[92m✅ Dependencies installed\033[0m")
        return True
    except subprocess.CalledProcessError:
        print("\033[91m❌ Failed to install dependencies\033[0m")
        print("\033[96m💡 Try: sudo apt update && sudo apt install python3-pip\033[0m")
        return False

def show_network_info():
    """Show network information"""
    print("\033[96m🌐 Network Configuration:\033[0m")
    
    # Get IP addresses
    try:
        import socket
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        print(f"\033[92m   Hostname: {hostname}\033[0m")
        print(f"\033[92m   Local IP: {local_ip}\033[0m")
    except:
        print("\033[93m   Could not determine network info\033[0m")
    
    print(f"\033[92m   Access URL: http://127.0.0.1:5000/api\033[0m")

def show_usage_info():
    """Show usage information"""
    print("\n\033[96m" + "="*65 + "\033[0m")
    print("\033[93m📋 INFERNOX USAGE GUIDE\033[0m")
    print("\033[96m" + "="*65 + "\033[0m")
    
    print("\033[92m🔐 Default Credentials:\033[0m")
    print("   Username: \033[93madmin\033[0m")
    print("   Password: \033[93minfernox123!\033[0m")
    
    print("\n\033[92m🌐 API Endpoints:\033[0m")
    print("   Login:    \033[96mPOST /api/auth/login\033[0m")
    print("   Send SMS: \033[96mPOST /api/sms/send\033[0m")
    print("   Status:   \033[96mGET  /api/system/status\033[0m")
    
    print("\n\033[92m📱 Quick SMS Test:\033[0m")
    print("\033[96m   curl -X POST http://127.0.0.1:5000/api/auth/login \\\033[0m")
    print("\033[96m        -H 'Content-Type: application/json' \\\033[0m")
    print("\033[96m        -d '{\"username\":\"admin\",\"password\":\"infernox123!\"}'\033[0m")
    
    print("\n\033[92m⚙️  Configuration:\033[0m")
    print("   Edit \033[93m.env\033[0m file to add SMS provider API keys")
    print("   GSM Modem: Configure \033[93mGSM_MODEM_PORT\033[0m in .env")
    
    print("\n\033[91m⚠️  LEGAL REMINDER:\033[0m")
    print("   • \033[93mAUTHORIZED TESTING ONLY\033[0m")
    print("   • \033[93mObtain proper permission before testing\033[0m")
    print("   • \033[93mComply with local laws and regulations\033[0m")
    
    print("\033[96m" + "="*65 + "\033[0m")

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    print("\n\033[93m\n👋 Infernox stopped by user\033[0m")
    print("\033[96m📊 Check logs/ directory for audit trails\033[0m")
    sys.exit(0)

def main():
    """Main function"""
    # Set up signal handler
    signal.signal(signal.SIGINT, signal_handler)
    
    # Clear screen and show banner
    os.system('clear')
    print_banner()
    
    # Environment checks
    print("\033[96m🔧 System Checks:\033[0m")
    check_kali_environment()
    check_root_privileges()
    
    # Setup environment
    print("\n\033[96m⚙️  Environment Setup:\033[0m")
    setup_kali_environment()
    
    # Check for GSM devices
    print("\n\033[96m📡 Hardware Detection:\033[0m")
    gsm_devices = check_gsm_devices()
    
    # Install dependencies
    print("\n\033[96m📦 Dependencies:\033[0m")
    if not install_dependencies():
        print("\033[91m❌ Cannot continue without dependencies\033[0m")
        return False
    
    # Show network info
    print("\n\033[96m🌐 Network:\033[0m")
    show_network_info()
    
    # Load environment
    from dotenv import load_dotenv
    load_dotenv()
    
    # Show usage information
    show_usage_info()
    
    # Start the application
    print(f"\n\033[92m🚀 Starting Infernox SMS Framework...\033[0m")
    print(f"\033[96m💡 Press Ctrl+C to stop\033[0m\n")
    
    try:
        from app import create_app
        app = create_app()
        
        # Run with Kali-optimized settings
        app.run(
            host='127.0.0.1',
            port=5000,
            debug=False,
            threaded=True
        )
    except ImportError as e:
        print(f"\033[91m❌ Import error: {e}\033[0m")
        print("\033[96m💡 Make sure all Python files are in the same directory\033[0m")
        return False
    except Exception as e:
        print(f"\033[91m❌ Failed to start: {e}\033[0m")
        return False
    
    return True

if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)
