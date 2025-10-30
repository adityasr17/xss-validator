#!/usr/bin/env python3
"""
Simple XSS Scanner for quick testing
Detects Reflected and Stored XSS vulnerabilities
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
import uuid

class SimpleXSSScanner:
    """Lightweight XSS scanner for Reflected and Stored XSS detection"""
    
    def __init__(self, target_url, timeout=10, threads=5):
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.threads = threads
        self.session = requests.Session()
        self.session.timeout = timeout
        self.vulnerabilities = []
        self.stored_xss_candidates = []  # Track potential stored XSS locations
        
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
        """Test forms for Reflected XSS"""
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
                                print(f"[VULN] Reflected XSS found in form at {form_url}")
                                return vuln
                        except Exception:
                            continue
        except Exception:
            pass
        
        return None
    
    def test_stored_xss(self, url):
        """Test for Stored XSS vulnerabilities"""
        try:
            response = self.session.get(url)
            
            # Find forms using regex
            form_pattern = r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>'
            input_pattern = r'<input[^>]*name=["\']([^"\']*)["\'][^>]*>'
            textarea_pattern = r'<textarea[^>]*name=["\']([^"\']*)["\'][^>]*>'
            
            forms = re.findall(form_pattern, response.text, re.IGNORECASE | re.DOTALL)
            
            for form_action, form_content in forms:
                form_url = urllib.parse.urljoin(url, form_action)
                
                # Find all input fields
                inputs = re.findall(input_pattern, form_content, re.IGNORECASE)
                textareas = re.findall(textarea_pattern, form_content, re.IGNORECASE)
                all_fields = list(set(inputs + textareas))
                
                if all_fields:
                    # Generate unique identifier for this test
                    unique_id = str(uuid.uuid4())[:8]
                    
                    # Test with a unique payload for stored XSS
                    for payload_template in self.payloads[:2]:  # Use first 2 payloads
                        # Add unique identifier to payload
                        payload = payload_template.replace("XSS", f"XSS-{unique_id}")
                        
                        form_data = {}
                        for field_name in all_fields:
                            # Put payload in fields that might store data
                            if any(keyword in field_name.lower() for keyword in 
                                   ['comment', 'message', 'text', 'content', 'description', 
                                    'review', 'feedback', 'note', 'body', 'post', 'reply']):
                                form_data[field_name] = payload
                            else:
                                form_data[field_name] = f"test_{unique_id}"
                        
                        try:
                            # Submit the form with payload
                            post_response = self.session.post(form_url, data=form_data, allow_redirects=True)
                            
                            # Store candidate for later verification
                            candidate = {
                                'url': url,
                                'form_url': form_url,
                                'payload': payload,
                                'unique_id': unique_id,
                                'fields': form_data,
                                'redirect_url': post_response.url
                            }
                            self.stored_xss_candidates.append(candidate)
                            
                        except Exception as e:
                            continue
                            
        except Exception:
            pass
        
        return None
    
    def verify_stored_xss(self):
        """Verify stored XSS by revisiting pages"""
        print("Verifying stored XSS candidates...")
        
        for candidate in self.stored_xss_candidates:
            try:
                # Wait a moment to ensure data is stored
                time.sleep(1)
                
                # Check multiple locations where the payload might appear
                urls_to_check = [
                    candidate['url'],
                    candidate['form_url'],
                    candidate['redirect_url']
                ]
                
                for check_url in set(urls_to_check):
                    try:
                        response = self.session.get(check_url)
                        
                        # Check if our unique payload appears in the response
                        if candidate['payload'] in response.text:
                            vuln = {
                                'type': 'Stored XSS',
                                'submission_url': candidate['form_url'],
                                'display_url': check_url,
                                'payload': candidate['payload'],
                                'method': 'POST',
                                'fields': list(candidate['fields'].keys())
                            }
                            
                            # Check if not already reported
                            if not any(v.get('payload') == candidate['payload'] and 
                                      v.get('type') == 'Stored XSS' 
                                      for v in self.vulnerabilities):
                                self.vulnerabilities.append(vuln)
                                print(f"[VULN] Stored XSS found! Submitted at {candidate['form_url']}, appears at {check_url}")
                                break
                                
                    except Exception:
                        continue
                        
            except Exception:
                continue
    
    def test_url(self, url):
        """Test a single URL"""
        vulnerabilities = []
        
        # Test reflected XSS
        reflected = self.test_reflected_xss(url)
        if reflected:
            vulnerabilities.append(reflected)
        
        # Test form for reflected XSS
        form_xss = self.test_form_xss(url)
        if form_xss:
            vulnerabilities.append(form_xss)
        
        # Test for stored XSS (candidates will be verified later)
        self.test_stored_xss(url)
        
        return vulnerabilities
    
    def scan(self):
        """Main scan function"""
        print(f"Starting XSS scan for {self.target_url}")
        print("Scanning for Reflected and Stored XSS vulnerabilities...")
        start_time = datetime.now()
        
        # Discover URLs
        print("\n[1/3] Discovering URLs...")
        urls = self.discover_urls(self.target_url)
        print(f"Found {len(urls)} URLs to test")
        
        # Test URLs for reflected XSS and submit payloads for stored XSS
        print("\n[2/3] Testing for Reflected XSS and submitting Stored XSS payloads...")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self.test_url, url) for url in urls]
            
            for future in futures:
                try:
                    result = future.result()
                    if result:
                        self.vulnerabilities.extend(result)
                except Exception as e:
                    print(f"Error testing URL: {e}")
        
        # Verify stored XSS
        print(f"\n[3/3] Verifying Stored XSS ({len(self.stored_xss_candidates)} candidates)...")
        if self.stored_xss_candidates:
            self.verify_stored_xss()
        
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
                'stored_xss_candidates': len(self.stored_xss_candidates),
                'vulnerabilities_found': len(self.vulnerabilities)
            },
            'vulnerabilities': self.vulnerabilities
        }
        
        print(f"\n{'='*50}")
        print(f"Scan completed in {duration:.2f} seconds")
        print(f"Found {len(self.vulnerabilities)} vulnerabilities")
        
        # Count by type
        reflected_count = sum(1 for v in self.vulnerabilities if 'Reflected' in v['type'])
        stored_count = sum(1 for v in self.vulnerabilities if 'Stored' in v['type'])
        
        if reflected_count > 0:
            print(f"  - Reflected XSS: {reflected_count}")
        if stored_count > 0:
            print(f"  - Stored XSS: {stored_count}")
        print(f"{'='*50}")
        
        return report

def main():
    parser = argparse.ArgumentParser(description='XSS Scanner - Detects Reflected and Stored XSS')
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds')
    parser.add_argument('--threads', type=int, default=5, help='Number of concurrent threads')
    parser.add_argument('--output', help='Output file path (JSON format)')
    
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
