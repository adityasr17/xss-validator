#!/usr/bin/env python3
"""
Example usage and demonstration of the XSS Scanner
"""

import os
import sys
import time
from pathlib import Path

def print_banner():
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                    XSS Vulnerability Scanner                 ║
    ║                      Example & Demo Script                   ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def run_example_scans():
    """Run example scans with different configurations"""
    
    print("🚀 XSS Scanner Example Usage")
    print("=" * 60)
    
    # Example URLs (using httpbin.org for safe testing)
    test_urls = [
        "https://httpbin.org/forms/post",
        "https://httpbin.org/get",
        "https://httpbin.org/html"
    ]
    
    examples = [
        {
            "name": "Basic Scan",
            "description": "Simple scan with default settings",
            "command": "python simple_xss_scanner.py -u {url}",
            "url": test_urls[0]
        },
        {
            "name": "Enhanced Scan",
            "description": "Enhanced scan with basic payloads",
            "command": "python enhanced_xss_scanner.py -u {url} --output reports/basic_scan --format html",
            "url": test_urls[1]
        },
        {
            "name": "Aggressive Scan",
            "description": "Comprehensive scan with all payloads",
            "command": "python enhanced_xss_scanner.py -u {url} --aggressive --threads 10 --output reports/aggressive_scan --format json",
            "url": test_urls[2]
        },
        {
            "name": "Subdomain Scan",
            "description": "Scan with subdomain enumeration",
            "command": "python enhanced_xss_scanner.py -u {url} --subdomains --depth 3 --output reports/subdomain_scan --format xml",
            "url": "https://example.com"
        },
        {
            "name": "Custom Payload Scan",
            "description": "Scan using custom payload file",
            "command": "python enhanced_xss_scanner.py -u {url} --payloads payloads/custom_payloads.txt --output reports/custom_scan --format csv",
            "url": test_urls[0]
        }
    ]
    
    for i, example in enumerate(examples, 1):
        print(f"\n{i}. {example['name']}")
        print(f"   Description: {example['description']}")
        print(f"   Command: {example['command'].format(url=example['url'])}")
        print(f"   URL: {example['url']}")
    
    print("\n" + "=" * 60)
    print("📝 Command Line Options:")
    print("   -u, --url          Target URL (required)")
    print("   -d, --depth        Crawling depth (default: 2)")
    print("   --subdomains       Enable subdomain enumeration")
    print("   --threads          Number of concurrent threads (default: 5)")
    print("   --timeout          Request timeout in seconds (default: 10)")
    print("   --user-agent       Custom User-Agent string")
    print("   --output           Output file for results")
    print("   --format           Output format (json, html, csv, xml)")
    print("   --payloads         Custom payload file")
    print("   --aggressive       Enable aggressive scanning")
    print("   --verbose          Enable verbose output")

def demonstrate_features():
    """Demonstrate key features of the scanner"""
    
    print("\n🔍 Scanner Features:")
    print("=" * 60)
    
    features = [
        {
            "name": "Multi-Type XSS Detection",
            "description": "Detects Reflected, Stored, and DOM-based XSS vulnerabilities"
        },
        {
            "name": "Comprehensive Crawling",
            "description": "Discovers endpoints through intelligent crawling and common path checking"
        },
        {
            "name": "Subdomain Enumeration",
            "description": "Finds and tests subdomains using DNS brute force and certificate transparency"
        },
        {
            "name": "Advanced Payload Testing",
            "description": "Tests hundreds of XSS payloads including bypass techniques"
        },
        {
            "name": "Form Analysis",
            "description": "Automatically detects and tests forms for XSS vulnerabilities"
        },
        {
            "name": "Multi-Format Reporting",
            "description": "Generates reports in JSON, HTML, CSV, and XML formats"
        },
        {
            "name": "Concurrent Testing",
            "description": "Fast parallel testing with configurable thread pool"
        },
        {
            "name": "Browser Automation",
            "description": "Uses Selenium for DOM-based XSS detection"
        }
    ]
    
    for i, feature in enumerate(features, 1):
        print(f"{i}. {feature['name']}")
        print(f"   {feature['description']}")
    
    print("\n📊 Output Formats:")
    print("   JSON - Structured data for further processing")
    print("   HTML - Rich visual report with styling")
    print("   CSV  - Spreadsheet-compatible format")
    print("   XML  - Standard XML format")

def create_test_environment():
    """Create a test environment with sample files"""
    
    print("\n🧪 Creating Test Environment...")
    
    # Create test directories
    test_dirs = ["test_reports", "test_payloads", "test_logs"]
    for directory in test_dirs:
        Path(directory).mkdir(exist_ok=True)
        print(f"   Created: {directory}/")
    
    # Create sample test payload
    test_payload_file = Path("test_payloads") / "test_payloads.txt"
    test_payloads = [
        "<script>alert('TEST')</script>",
        "<img src=x onerror=alert('TEST')>",
        "<svg onload=alert('TEST')>",
        "javascript:alert('TEST')",
        "'><script>alert('TEST')</script>"
    ]
    
    with open(test_payload_file, 'w') as f:
        for payload in test_payloads:
            f.write(payload + '\n')
    
    print(f"   Created: {test_payload_file}")
    
    # Create sample configuration
    test_config = Path("test_config.json")
    config_data = {
        "target_urls": [
            "https://httpbin.org/forms/post",
            "https://httpbin.org/get"
        ],
        "scan_options": {
            "threads": 5,
            "timeout": 10,
            "depth": 2,
            "aggressive": False
        },
        "output_options": {
            "format": "html",
            "directory": "test_reports"
        }
    }
    
    import json
    with open(test_config, 'w') as f:
        json.dump(config_data, f, indent=2)
    
    print(f"   Created: {test_config}")
    print("   Test environment ready!")

def run_quick_test():
    """Run a quick test to verify installation"""
    
    print("\n⚡ Quick Installation Test...")
    
    try:
        # Test import of main modules
        print("   Testing module imports...")
        
        modules_to_test = [
            ("requests", "HTTP client"),
            ("urllib.parse", "URL parsing"),
            ("concurrent.futures", "Threading"),
            ("json", "JSON handling"),
            ("argparse", "Argument parsing")
        ]
        
        for module_name, description in modules_to_test:
            try:
                __import__(module_name)
                print(f"   ✅ {description}: OK")
            except ImportError:
                print(f"   ❌ {description}: FAILED")
        
        # Test optional modules
        optional_modules = [
            ("bs4", "BeautifulSoup (HTML parsing)"),
            ("selenium", "Browser automation"),
            ("colorama", "Colored output"),
            ("tqdm", "Progress bars")
        ]
        
        print("\n   Testing optional modules...")
        for module_name, description in optional_modules:
            try:
                __import__(module_name)
                print(f"   ✅ {description}: OK")
            except ImportError:
                print(f"   ⚠️  {description}: Not installed (some features may be limited)")
        
        print("\n   ✅ Installation test completed!")
        
    except Exception as e:
        print(f"   ❌ Test failed: {e}")

def show_legal_disclaimer():
    """Show legal disclaimer and responsible use guidelines"""
    
    disclaimer = """
    ⚖️  LEGAL DISCLAIMER AND RESPONSIBLE USE
    ═══════════════════════════════════════════════════════════════
    
    This XSS Vulnerability Scanner is intended for:
    
    ✅ AUTHORIZED security testing and assessment
    ✅ Educational and research purposes
    ✅ Testing your own websites and applications
    ✅ Bug bounty programs with proper authorization
    ✅ Penetration testing with written permission
    
    ❌ DO NOT use this tool for:
    ❌ Unauthorized testing of websites you don't own
    ❌ Malicious activities or illegal purposes
    ❌ Violating terms of service or applicable laws
    ❌ Disrupting services or causing harm
    
    🔒 RESPONSIBLE USE GUIDELINES:
    • Always obtain proper authorization before testing
    • Respect rate limits and don't overwhelm servers
    • Report vulnerabilities responsibly through proper channels
    • Follow applicable laws and regulations in your jurisdiction
    • Use the tool ethically and professionally
    
    By using this tool, you agree to use it responsibly and legally.
    The authors are not responsible for any misuse or illegal activities.
    ═══════════════════════════════════════════════════════════════
    """
    print(disclaimer)

def main():
    """Main function to run the example and demo"""
    
    print_banner()
    show_legal_disclaimer()
    
    print("\n🎯 What would you like to do?")
    print("1. View example commands and usage")
    print("2. See scanner features and capabilities")
    print("3. Create test environment")
    print("4. Run quick installation test")
    print("5. All of the above")
    print("0. Exit")
    
    try:
        choice = input("\nEnter your choice (0-5): ").strip()
        
        if choice == '1':
            run_example_scans()
        elif choice == '2':
            demonstrate_features()
        elif choice == '3':
            create_test_environment()
        elif choice == '4':
            run_quick_test()
        elif choice == '5':
            run_example_scans()
            demonstrate_features()
            create_test_environment()
            run_quick_test()
        elif choice == '0':
            print("Goodbye! 👋")
            return
        else:
            print("Invalid choice. Please select 0-5.")
    
    except KeyboardInterrupt:
        print("\n\nInterrupted by user. Goodbye! 👋")
    except Exception as e:
        print(f"\nError: {e}")

if __name__ == "__main__":
    main()
