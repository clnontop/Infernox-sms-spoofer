#!/usr/bin/env python3
"""
SMS Spoofing System Startup Script
Handles initialization, dependency checks, and system startup
"""

import os
import sys
import subprocess
import logging
from pathlib import Path

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 8):
        print("❌ Error: Python 3.8 or higher is required")
        print(f"Current version: {sys.version}")
        return False
    print(f"✅ Python version: {sys.version.split()[0]}")
    return True

def check_dependencies():
    """Check if required dependencies are installed"""
    required_packages = [
        'flask', 'flask-cors', 'requests', 'python-dotenv',
        'cryptography', 'pyjwt', 'sqlalchemy', 'flask-sqlalchemy',
        'bcrypt', 'pyserial'
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
            print(f"✅ {package}")
        except ImportError:
            missing_packages.append(package)
            print(f"❌ {package} - Missing")
    
    if missing_packages:
        print(f"\n📦 Installing missing packages: {', '.join(missing_packages)}")
        try:
            subprocess.check_call([
                sys.executable, '-m', 'pip', 'install'
            ] + missing_packages)
            print("✅ All dependencies installed successfully")
            return True
        except subprocess.CalledProcessError:
            print("❌ Failed to install dependencies")
            print("Please run: pip install -r requirements.txt")
            return False
    
    return True

def setup_directories():
    """Create necessary directories"""
    directories = ['logs', 'archives', 'templates']
    
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
        print(f"✅ Directory: {directory}")

def setup_environment():
    """Setup environment configuration"""
    env_file = Path('.env')
    env_example = Path('.env.example')
    
    if not env_file.exists() and env_example.exists():
        print("📝 Creating .env file from template...")
        
        # Copy example file
        with open(env_example, 'r') as src, open(env_file, 'w') as dst:
            content = src.read()
            
            # Generate some default values
            import secrets
            secret_key = secrets.token_urlsafe(32)
            jwt_key = secrets.token_urlsafe(32)
            
            content = content.replace('your-secret-key-here', secret_key)
            content = content.replace('your-jwt-secret-key-here', jwt_key)
            
            dst.write(content)
        
        print("✅ .env file created with default values")
        print("⚠️  Please edit .env file to configure your SMS providers")
    elif env_file.exists():
        print("✅ .env file exists")
    else:
        print("❌ No .env.example file found")
        return False
    
    return True

def initialize_database():
    """Initialize the database"""
    try:
        from app import create_app
        
        app = create_app()
        with app.app_context():
            # Database will be created automatically when first accessed
            print("✅ Database initialized")
        return True
    except Exception as e:
        print(f"❌ Database initialization failed: {e}")
        return False

def check_ports():
    """Check if required ports are available"""
    import socket
    
    def is_port_available(port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(('localhost', port))
                return True
            except OSError:
                return False
    
    port = int(os.environ.get('PORT', 5000))
    if is_port_available(port):
        print(f"✅ Port {port} is available")
        return True
    else:
        print(f"❌ Port {port} is already in use")
        print(f"Please change the PORT in .env file or stop the service using port {port}")
        return False

def display_startup_info():
    """Display startup information"""
    port = os.environ.get('PORT', '5000')
    host = os.environ.get('HOST', '127.0.0.1')
    
    print("\n" + "="*60)
    print("🚀 SMS SPOOFING SYSTEM STARTING")
    print("="*60)
    print(f"🌐 Web Interface: http://{host}:{port}")
    print(f"🔐 Login Page: http://{host}:{port}/login")
    print(f"📊 Dashboard: http://{host}:{port}/dashboard")
    print(f"🔧 API Base: http://{host}:{port}/api")
    print("\n📋 Default Credentials:")
    print("   Username: admin")
    print("   Password: admin123!@#")
    print("\n⚠️  IMPORTANT SECURITY NOTES:")
    print("   • Change default password immediately")
    print("   • This system is for AUTHORIZED TESTING ONLY")
    print("   • Ensure compliance with local laws")
    print("   • Configure SMS providers in .env file")
    print("="*60)

def main():
    """Main startup function"""
    print("🔧 SMS Spoofing System - Initialization")
    print("="*50)
    
    # Check Python version
    if not check_python_version():
        return False
    
    # Setup directories
    print("\n📁 Setting up directories...")
    setup_directories()
    
    # Check dependencies
    print("\n📦 Checking dependencies...")
    if not check_dependencies():
        return False
    
    # Setup environment
    print("\n⚙️  Setting up environment...")
    if not setup_environment():
        return False
    
    # Load environment variables
    from dotenv import load_dotenv
    load_dotenv()
    
    # Check ports
    print("\n🔌 Checking ports...")
    if not check_ports():
        return False
    
    # Initialize database
    print("\n💾 Initializing database...")
    if not initialize_database():
        return False
    
    # Display startup info
    display_startup_info()
    
    # Start the application
    print("\n🚀 Starting SMS Spoofing System...")
    try:
        from app import main as app_main
        app_main()
    except KeyboardInterrupt:
        print("\n\n👋 SMS Spoofing System stopped by user")
    except Exception as e:
        print(f"\n❌ Failed to start system: {e}")
        return False
    
    return True

if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)
