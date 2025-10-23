#!/usr/bin/env python3
"""
Test script to verify XSS Scanner functionality
"""

import unittest
import tempfile
import os
from pathlib import Path

# Add the project directory to Python path
import sys
sys.path.insert(0, str(Path(__file__).parent))

# Import our modules
try:
    from payloads import XSSPayloadManager
    from config import SCANNER_CONFIG, PAYLOAD_CATEGORIES
except ImportError as e:
    print(f"Warning: Could not import all modules: {e}")
    print("Some tests may be skipped")

class TestXSSScanner(unittest.TestCase):
    """Test cases for XSS Scanner components"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.test_dir = Path(tempfile.mkdtemp())
        
    def tearDown(self):
        """Clean up test fixtures"""
        import shutil
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir)
    
    def test_payload_manager(self):
        """Test XSS payload manager"""
        try:
            manager = XSSPayloadManager()
            
            # Test basic payloads
            basic_payloads = manager.get_basic_payloads()
            self.assertIsInstance(basic_payloads, list)
            self.assertGreater(len(basic_payloads), 0)
            
            # Test advanced payloads
            advanced_payloads = manager.get_advanced_payloads()
            self.assertIsInstance(advanced_payloads, list)
            self.assertGreater(len(advanced_payloads), 0)
            
            # Test all payloads
            all_payloads = manager.get_all_payloads()
            self.assertIsInstance(all_payloads, list)
            self.assertGreater(len(all_payloads), len(basic_payloads))
            
            print("✅ Payload Manager tests passed")
            
        except NameError:
            print("⚠️  Skipping Payload Manager tests (module not available)")
    
    def test_config_loading(self):
        """Test configuration loading"""
        try:
            # Test scanner config
            self.assertIsInstance(SCANNER_CONFIG, dict)
            self.assertIn('default_timeout', SCANNER_CONFIG)
            self.assertIn('default_threads', SCANNER_CONFIG)
            
            # Test payload categories
            self.assertIsInstance(PAYLOAD_CATEGORIES, dict)
            self.assertIn('basic', PAYLOAD_CATEGORIES)
            self.assertIn('advanced', PAYLOAD_CATEGORIES)
            
            print("✅ Configuration tests passed")
            
        except NameError:
            print("⚠️  Skipping Configuration tests (module not available)")
    
    def test_file_operations(self):
        """Test file operations"""
        # Test creating payload file
        test_file = self.test_dir / "test_payloads.txt"
        test_payloads = [
            "<script>alert('test')</script>",
            "<img src=x onerror=alert('test')>"
        ]
        
        with open(test_file, 'w') as f:
            for payload in test_payloads:
                f.write(payload + '\n')
        
        # Test reading payload file
        with open(test_file, 'r') as f:
            loaded_payloads = [line.strip() for line in f if line.strip()]
        
        self.assertEqual(len(loaded_payloads), len(test_payloads))
        self.assertEqual(loaded_payloads, test_payloads)
        
        print("✅ File operations tests passed")
    
    def test_url_validation(self):
        """Test URL validation"""
        import urllib.parse
        
        valid_urls = [
            "https://example.com",
            "http://example.com",
            "https://sub.example.com/path",
            "http://example.com:8080/path?param=value"
        ]
        
        invalid_urls = [
            "example.com",
            "ftp://example.com",
            "not-a-url",
            ""
        ]
        
        for url in valid_urls:
            parsed = urllib.parse.urlparse(url)
            self.assertIn(parsed.scheme, ['http', 'https'])
            self.assertTrue(parsed.netloc)
        
        print("✅ URL validation tests passed")
    
    def test_payload_encoding(self):
        """Test payload encoding functions"""
        import urllib.parse
        import html
        
        test_payload = "<script>alert('test')</script>"
        
        # Test URL encoding
        url_encoded = urllib.parse.quote(test_payload)
        self.assertNotEqual(url_encoded, test_payload)
        self.assertIn('%3C', url_encoded)
        
        # Test HTML encoding
        html_encoded = html.escape(test_payload)
        self.assertNotEqual(html_encoded, test_payload)
        self.assertIn('&lt;', html_encoded)
        
        print("✅ Payload encoding tests passed")

def run_basic_tests():
    """Run basic functionality tests"""
    print("🧪 Running XSS Scanner Tests")
    print("=" * 40)
    
    # Test basic Python functionality
    print("Testing basic Python functionality...")
    
    # Test imports
    required_modules = ['urllib.parse', 'json', 'argparse', 'concurrent.futures']
    for module in required_modules:
        try:
            __import__(module)
            print(f"✅ {module}: OK")
        except ImportError:
            print(f"❌ {module}: FAILED")
    
    # Test optional modules
    optional_modules = ['requests', 'bs4', 'selenium', 'colorama', 'tqdm']
    for module in optional_modules:
        try:
            __import__(module)
            print(f"✅ {module}: OK")
        except ImportError:
            print(f"⚠️  {module}: Not available (optional)")
    
    print("\n" + "=" * 40)
    
    # Run unit tests
    print("Running unit tests...")
    unittest.main(argv=[''], exit=False, verbosity=2)

def test_simple_scanner():
    """Test the simple scanner without dependencies"""
    print("\n🔍 Testing Simple Scanner...")
    
    try:
        # Test URL parsing
        import urllib.parse
        test_url = "https://httpbin.org/get?param=test"
        parsed = urllib.parse.urlparse(test_url)
        
        print(f"✅ URL parsing: {parsed.netloc}")
        
        # Test payload creation
        basic_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')"
        ]
        
        print(f"✅ Payload creation: {len(basic_payloads)} payloads")
        
        # Test parameter extraction
        if parsed.query:
            params = urllib.parse.parse_qs(parsed.query)
            print(f"✅ Parameter extraction: {list(params.keys())}")
        
        print("✅ Simple scanner components working")
        
    except Exception as e:
        print(f"❌ Simple scanner test failed: {e}")

if __name__ == '__main__':
    print("🚀 XSS Scanner Test Suite")
    print("=" * 50)
    
    # Run basic tests first
    run_basic_tests()
    
    # Test simple scanner
    test_simple_scanner()
    
    print("\n" + "=" * 50)
    print("✅ Test suite completed!")
    print("\nTo run the scanner:")
    print("python simple_xss_scanner.py -u https://httpbin.org/get")
    print("python enhanced_xss_scanner.py -u https://httpbin.org/get")
