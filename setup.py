#!/usr/bin/env python3
"""
Installation and setup script for XSS Scanner
"""

import subprocess
import sys
import os
from pathlib import Path

def install_requirements():
    """Install required packages"""
    requirements_file = Path(__file__).parent / "requirements.txt"
    
    if not requirements_file.exists():
        print("Error: requirements.txt not found!")
        return False
    
    try:
        print("Installing required packages...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", str(requirements_file)])
        print("✅ All packages installed successfully!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error installing packages: {e}")
        return False

def create_directories():
    """Create necessary directories"""
    directories = ["reports", "payloads", "logs"]
    
    for directory in directories:
        dir_path = Path(directory)
        dir_path.mkdir(exist_ok=True)
        print(f"📁 Created directory: {directory}")

def create_sample_payload_file():
    """Create a sample custom payload file"""
    payload_file = Path("payloads") / "custom_payloads.txt"
    
    sample_payloads = [
        "<script>alert('Custom XSS')</script>",
        "<img src=x onerror=alert('Custom')>",
        "<svg onload=alert('Custom')>",
        "javascript:alert('Custom')",
        "'><script>alert('Custom')</script>",
        "\"><script>alert('Custom')</script>",
        "<iframe src=javascript:alert('Custom')>",
        "<body onload=alert('Custom')>",
        "<div onmouseover=alert('Custom')>Test</div>",
        "<input onfocus=alert('Custom') autofocus>"
    ]
    
    with open(payload_file, 'w') as f:
        for payload in sample_payloads:
            f.write(payload + '\n')
    
    print(f"📝 Created sample payload file: {payload_file}")

def check_chrome_installation():
    """Check if Chrome is installed (required for Selenium)"""
    try:
        import shutil
        chrome_path = shutil.which('chrome') or shutil.which('google-chrome') or shutil.which('google-chrome-stable')
        if chrome_path:
            print("✅ Chrome browser found")
            return True
        else:
            print("⚠️  Chrome browser not found. Please install Google Chrome for DOM-based XSS testing.")
            print("   You can download it from: https://www.google.com/chrome/")
            return False
    except Exception:
        print("⚠️  Could not check Chrome installation")
        return False

def main():
    print("🚀 Setting up XSS Vulnerability Scanner...")
    print("=" * 50)
    
    # Install requirements
    if not install_requirements():
        print("❌ Setup failed during package installation")
        return False
    
    # Create directories
    print("\n📁 Creating directories...")
    create_directories()
    
    # Create sample files
    print("\n📝 Creating sample files...")
    create_sample_payload_file()
    
    # Check Chrome installation
    print("\n🌐 Checking browser installation...")
    check_chrome_installation()
    
    print("\n" + "=" * 50)
    print("✅ Setup completed successfully!")
    print("\n📖 Usage examples:")
    print("   Basic scan:")
    print("   python enhanced_xss_scanner.py -u https://example.com")
    print("\n   Advanced scan with subdomains:")
    print("   python enhanced_xss_scanner.py -u https://example.com --subdomains --aggressive")
    print("\n   Custom output format:")
    print("   python enhanced_xss_scanner.py -u https://example.com --output report --format html")
    print("\n   Using custom payloads:")
    print("   python enhanced_xss_scanner.py -u https://example.com --payloads payloads/custom_payloads.txt")
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
