#!/usr/bin/env python3
"""
Enhanced XSS Vulnerability Scanner
A comprehensive tool for detecting Reflected, Stored, and DOM-based XSS vulnerabilities
"""

import argparse
import json
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List, Dict, Set, Tuple, Optional

import requests
from bs4 import BeautifulSoup
from colorama import init, Fore, Style
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException
from webdriver_manager.chrome import ChromeDriverManager
import tqdm

# Import custom modules
from payloads import XSSPayloadManager
from discovery import URLDiscovery, FormDiscovery
from subdomain_enum import SubdomainEnumerator
from reporting import ReportGenerator, VulnerabilityAnalyzer

# Initialize colorama for colored output
init(autoreset=True)

class EnhancedXSSScanner:
    """Enhanced XSS vulnerability scanner with comprehensive testing capabilities"""
    
    def __init__(self, target_url: str, depth: int = 2, threads: int = 5, 
                 timeout: int = 10, user_agent: str = None, enable_subdomains: bool = False,
                 custom_payloads: str = None, aggressive: bool = False):
        self.target_url = target_url.rstrip('/')
        self.domain = urllib.parse.urlparse(target_url).netloc
        self.depth = depth
        self.threads = threads
        self.timeout = timeout
        self.enable_subdomains = enable_subdomains
        self.aggressive = aggressive
        
        # Session setup
        self.session = requests.Session()
        self.session.timeout = timeout
        
        # User agent
        self.user_agent = user_agent or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )
        self.session.headers.update({'User-Agent': self.user_agent})
        
        # Data storage
        self.discovered_urls: Set[str] = set()
        self.tested_urls: Set[str] = set()
        self.vulnerabilities: List[Dict] = []
        self.subdomains: Set[str] = set()
        
        # Selenium driver
        self.driver = None
        self._setup_selenium()
        
        # Load XSS payloads
        self.payload_manager = XSSPayloadManager()
        if custom_payloads:
            custom = self.payload_manager.load_custom_payloads(custom_payloads)
            self.payloads = custom if custom else self.payload_manager.get_all_payloads()
        else:
            if aggressive:
                self.payloads = self.payload_manager.get_all_payloads()
            else:
                # Use basic + advanced for normal scanning
                self.payloads = (self.payload_manager.get_basic_payloads() + 
                               self.payload_manager.get_advanced_payloads())
        
        # Initialize discovery tools
        self.url_discovery = URLDiscovery(self.session, self.depth)
        self.subdomain_enum = SubdomainEnumerator(self.domain, timeout=self.timeout)
        
        print(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} Initialized scanner with {len(self.payloads)} payloads")
        
    def _setup_selenium(self):
        """Setup Selenium WebDriver for DOM-based XSS testing"""
        try:
            options = Options()
            options.add_argument('--headless')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument('--disable-gpu')
            options.add_argument('--window-size=1920,1080')
            options.add_argument(f'--user-agent={self.user_agent}')
            options.add_argument('--disable-logging')
            options.add_argument('--log-level=3')
            
            service = Service(ChromeDriverManager().install())
            self.driver = webdriver.Chrome(service=service, options=options)
            print(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} Selenium WebDriver initialized")
        except Exception as e:
            print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} Failed to initialize Selenium: {e}")
            print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} DOM-based XSS testing will be disabled")
    
    def discover_subdomains(self) -> Set[str]:
        """Discover subdomains using comprehensive enumeration"""
        if not self.enable_subdomains:
            return {self.domain}
        
        print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Starting subdomain enumeration for {self.domain}")
        
        # Use the enhanced subdomain enumerator
        subdomains = self.subdomain_enum.comprehensive_enumeration()
        
        self.subdomains = subdomains
        return subdomains
    
    def discover_endpoints(self, subdomains: Set[str]) -> Set[str]:
        """Discover all endpoints across subdomains"""
        all_urls = set()
        
        for subdomain in subdomains:
            subdomain_url = f"{urllib.parse.urlparse(self.target_url).scheme}://{subdomain}"
            print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Discovering endpoints for {subdomain}")
            
            try:
                # Comprehensive URL discovery
                discovered_urls = self.url_discovery.comprehensive_discovery(subdomain_url)
                all_urls.update(discovered_urls)
                print(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} Found {len(discovered_urls)} endpoints for {subdomain}")
                
            except Exception as e:
                print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} Error discovering endpoints for {subdomain}: {e}")
        
        return all_urls
    
    def test_reflected_xss(self, url: str, payload: str) -> Optional[Dict]:
        """Enhanced reflected XSS testing"""
        parsed_url = urllib.parse.urlparse(url)
        vulnerabilities = []
        
        # Test GET parameters
        if parsed_url.query:
            params = urllib.parse.parse_qs(parsed_url.query)
            for param_name in params:
                test_params = params.copy()
                test_params[param_name] = [payload]
                
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                query_string = urllib.parse.urlencode(test_params, doseq=True)
                full_url = f"{test_url}?{query_string}"
                
                try:
                    response = self.session.get(full_url)
                    
                    # Check for payload reflection
                    if self._check_xss_reflection(response, payload):
                        return {
                            'type': 'Reflected XSS',
                            'url': full_url,
                            'parameter': param_name,
                            'payload': payload,
                            'method': 'GET',
                            'evidence': f"Payload reflected in response at parameter '{param_name}'",
                            'response_excerpt': response.text[:500]
                        }
                except Exception:
                    pass
        
        # Test POST forms
        try:
            response = self.session.get(url)
            forms = FormDiscovery.extract_forms(response.text, url)
            
            for form in forms:
                if form['method'] == 'POST':
                    form_data = {}
                    
                    # Fill form fields with payload
                    for input_field in form['inputs']:
                        field_name = input_field['name']
                        field_type = input_field['type']
                        
                        if field_name and field_type not in ['submit', 'button', 'reset', 'file']:
                            if field_type == 'hidden':
                                form_data[field_name] = input_field['value']
                            else:
                                form_data[field_name] = payload
                    
                    # Add textarea and select fields
                    for textarea in form['textareas']:
                        if textarea['name']:
                            form_data[textarea['name']] = payload
                    
                    for select in form['selects']:
                        if select['name'] and select['options']:
                            form_data[select['name']] = select['options'][0]  # Use first option
                    
                    if form_data:
                        try:
                            post_response = self.session.post(form['action'], data=form_data)
                            
                            if self._check_xss_reflection(post_response, payload):
                                return {
                                    'type': 'Reflected XSS',
                                    'url': form['action'],
                                    'parameter': list(form_data.keys()),
                                    'payload': payload,
                                    'method': 'POST',
                                    'evidence': f"Payload reflected in response via POST form",
                                    'form_action': form['action']
                                }
                        except Exception:
                            pass
        except Exception:
            pass
        
        return None
    
    def test_stored_xss(self, url: str, payload: str) -> Optional[Dict]:
        """Enhanced stored XSS testing"""
        try:
            response = self.session.get(url)
            forms = FormDiscovery.extract_forms(response.text, url)
            
            for form in forms:
                if form['method'] == 'POST':
                    # Create unique payload for tracking
                    unique_payload = f"{payload}<!--{int(time.time())}-->"
                    form_data = {}
                    
                    # Fill form with payload
                    for input_field in form['inputs']:
                        field_name = input_field['name']
                        field_type = input_field['type']
                        
                        if field_name and field_type not in ['submit', 'button', 'reset', 'file']:
                            if field_type == 'hidden':
                                form_data[field_name] = input_field['value']
                            elif field_type in ['text', 'textarea', 'search', 'email']:
                                form_data[field_name] = unique_payload
                            else:
                                form_data[field_name] = "test"
                    
                    for textarea in form['textareas']:
                        if textarea['name']:
                            form_data[textarea['name']] = unique_payload
                    
                    if form_data:
                        try:
                            # Submit payload
                            self.session.post(form['action'], data=form_data)
                            
                            # Wait for processing
                            time.sleep(2)
                            
                            # Check multiple pages for stored XSS
                            check_urls = [url, form['action']]
                            
                            # Add common pages where stored content might appear
                            base_url = f"{urllib.parse.urlparse(url).scheme}://{urllib.parse.urlparse(url).netloc}"
                            check_urls.extend([
                                f"{base_url}/",
                                f"{base_url}/index.php",
                                f"{base_url}/home",
                                f"{base_url}/comments",
                                f"{base_url}/posts"
                            ])
                            
                            for check_url in check_urls:
                                try:
                                    check_response = self.session.get(check_url)
                                    if unique_payload in check_response.text:
                                        return {
                                            'type': 'Stored XSS',
                                            'url': check_url,
                                            'form_action': form['action'],
                                            'payload': unique_payload,
                                            'method': 'POST',
                                            'evidence': f"Payload stored and reflected on {check_url}",
                                            'storage_location': check_url
                                        }
                                except Exception:
                                    continue
                        except Exception:
                            pass
        except Exception:
            pass
        
        return None
    
    def test_dom_xss(self, url: str, payload: str) -> Optional[Dict]:
        """Enhanced DOM-based XSS testing"""
        if not self.driver:
            return None
        
        dom_test_vectors = [
            f"{url}#{payload}",
            f"{url}?xss={urllib.parse.quote(payload)}",
            f"{url}#!{payload}",
            f"{url}#!/{payload}"
        ]
        
        for test_url in dom_test_vectors:
            try:
                self.driver.get(test_url)
                
                # Wait for page to load
                WebDriverWait(self.driver, 5).until(
                    EC.presence_of_element_located((By.TAG_NAME, "body"))
                )
                
                # Check for alert dialogs
                try:
                    WebDriverWait(self.driver, 2).until(EC.alert_is_present())
                    alert = self.driver.switch_to.alert
                    alert_text = alert.text
                    alert.accept()
                    
                    if any(keyword in alert_text.lower() for keyword in ['xss', 'alert', 'test']):
                        return {
                            'type': 'DOM-based XSS',
                            'url': test_url,
                            'payload': payload,
                            'method': 'Fragment/Parameter',
                            'evidence': f"JavaScript alert triggered: {alert_text}",
                            'alert_text': alert_text
                        }
                except TimeoutException:
                    pass
                
                # Check for payload execution in DOM
                try:
                    page_source = self.driver.page_source
                    if payload in page_source:
                        # Check if it's in a script context
                        scripts = self.driver.find_elements(By.TAG_NAME, "script")
                        for script in scripts:
                            script_content = script.get_attribute('innerHTML')
                            if script_content and payload in script_content:
                                return {
                                    'type': 'DOM-based XSS',
                                    'url': test_url,
                                    'payload': payload,
                                    'method': 'Fragment/Parameter',
                                    'evidence': f"Payload found in script context",
                                    'script_content': script_content[:200]
                                }
                except Exception:
                    pass
                
            except Exception:
                continue
        
        return None
    
    def _check_xss_reflection(self, response: requests.Response, payload: str) -> bool:
        """Check if XSS payload is reflected in response"""
        if response.status_code != 200:
            return False
        
        content_type = response.headers.get('content-type', '').lower()
        if 'text/html' not in content_type:
            return False
        
        # Check for exact payload match
        if payload in response.text:
            return True
        
        # Check for HTML-encoded payload
        import html
        encoded_payload = html.escape(payload)
        if encoded_payload in response.text:
            return True
        
        # Check for URL-encoded payload
        url_encoded = urllib.parse.quote(payload)
        if url_encoded in response.text:
            return True
        
        return False
    
    def test_url_for_xss(self, url: str) -> List[Dict]:
        """Test a single URL for all types of XSS vulnerabilities"""
        vulnerabilities = []
        
        # Limit payload testing to avoid overwhelming the server
        test_payloads = self.payloads[:10] if not self.aggressive else self.payloads
        
        for payload in test_payloads:
            # Test Reflected XSS
            reflected_vuln = self.test_reflected_xss(url, payload)
            if reflected_vuln:
                vulnerabilities.append(reflected_vuln)
                print(f"{Fore.RED}[VULN]{Style.RESET_ALL} Reflected XSS found at: {url}")
                if not self.aggressive:
                    break  # Found one, move to next type
            
            # Test Stored XSS (more conservative)
            if self.aggressive or len(vulnerabilities) == 0:
                stored_vuln = self.test_stored_xss(url, payload)
                if stored_vuln:
                    vulnerabilities.append(stored_vuln)
                    print(f"{Fore.RED}[VULN]{Style.RESET_ALL} Stored XSS found at: {url}")
                    if not self.aggressive:
                        break
            
            # Test DOM-based XSS
            if self.aggressive or len(vulnerabilities) == 0:
                dom_vuln = self.test_dom_xss(url, payload)
                if dom_vuln:
                    vulnerabilities.append(dom_vuln)
                    print(f"{Fore.RED}[VULN]{Style.RESET_ALL} DOM-based XSS found at: {url}")
                    if not self.aggressive:
                        break
            
            # If we found vulnerabilities and not in aggressive mode, stop testing more payloads
            if vulnerabilities and not self.aggressive:
                break
        
        return vulnerabilities
    
    def scan(self) -> Dict:
        """Main scanning function"""
        print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Starting enhanced XSS scan for {self.target_url}")
        start_time = datetime.now()
        
        # Discover subdomains
        subdomains = self.discover_subdomains()
        print(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} Found {len(subdomains)} subdomains")
        
        # Discover endpoints
        all_urls = self.discover_endpoints(subdomains)
        print(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} Found {len(all_urls)} endpoints to test")
        
        if not all_urls:
            print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} No endpoints found to test")
            return self._generate_empty_report(start_time)
        
        # Test URLs for XSS
        print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Testing for XSS vulnerabilities...")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_url = {executor.submit(self.test_url_for_xss, url): url for url in all_urls}
            
            for future in tqdm.tqdm(as_completed(future_to_url), total=len(all_urls), desc="Testing URLs"):
                url = future_to_url[future]
                try:
                    vulnerabilities = future.result()
                    self.vulnerabilities.extend(vulnerabilities)
                except Exception as e:
                    print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} Error testing {url}: {e}")
        
        end_time = datetime.now()
        scan_duration = (end_time - start_time).total_seconds()
        
        # Generate comprehensive report
        report = {
            'scan_info': {
                'target': self.target_url,
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration_seconds': scan_duration,
                'urls_tested': len(all_urls),
                'subdomains_found': len(subdomains),
                'vulnerabilities_found': len(self.vulnerabilities),
                'scan_type': 'Aggressive' if self.aggressive else 'Standard',
                'payloads_used': len(self.payloads)
            },
            'subdomains': list(subdomains),
            'vulnerabilities': self.vulnerabilities,
            'analysis': VulnerabilityAnalyzer.analyze_impact(self.vulnerabilities)
        }
        
        print(f"\n{Fore.GREEN}[COMPLETE]{Style.RESET_ALL} Scan completed in {scan_duration:.2f} seconds")
        print(f"{Fore.GREEN}[RESULT]{Style.RESET_ALL} Found {len(self.vulnerabilities)} XSS vulnerabilities")
        
        return report
    
    def _generate_empty_report(self, start_time: datetime) -> Dict:
        """Generate empty report when no URLs found"""
        end_time = datetime.now()
        return {
            'scan_info': {
                'target': self.target_url,
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration_seconds': (end_time - start_time).total_seconds(),
                'urls_tested': 0,
                'subdomains_found': len(self.subdomains),
                'vulnerabilities_found': 0,
                'scan_type': 'Aggressive' if self.aggressive else 'Standard',
                'payloads_used': len(self.payloads)
            },
            'subdomains': list(self.subdomains),
            'vulnerabilities': [],
            'analysis': VulnerabilityAnalyzer.analyze_impact([])
        }
    
    def cleanup(self):
        """Clean up resources"""
        if self.driver:
            self.driver.quit()
        self.session.close()


def main():
    parser = argparse.ArgumentParser(description='Enhanced XSS Vulnerability Scanner')
    parser.add_argument('-u', '--url', required=True, help='Target URL to scan')
    parser.add_argument('-d', '--depth', type=int, default=2, help='Crawling depth (default: 2)')
    parser.add_argument('--subdomains', action='store_true', help='Enable subdomain enumeration')
    parser.add_argument('--threads', type=int, default=5, help='Number of concurrent threads (default: 5)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('--user-agent', help='Custom User-Agent string')
    parser.add_argument('--output', help='Output file for results (JSON format)')
    parser.add_argument('--format', choices=['json', 'html', 'csv', 'xml'], default='json', help='Output format')
    parser.add_argument('--payloads', help='Custom payload file')
    parser.add_argument('--aggressive', action='store_true', help='Enable aggressive scanning (more payloads, thorough testing)')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
    
    args = parser.parse_args()
    
    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} URL must start with http:// or https://")
        sys.exit(1)
    
    scanner = None
    try:
        # Initialize enhanced scanner
        scanner = EnhancedXSSScanner(
            target_url=args.url,
            depth=args.depth,
            threads=args.threads,
            timeout=args.timeout,
            user_agent=args.user_agent,
            enable_subdomains=args.subdomains,
            custom_payloads=args.payloads,
            aggressive=args.aggressive
        )
        
        # Run scan
        report = scanner.scan()
        
        # Generate and save report
        report_generator = ReportGenerator(report)
        
        if args.output:
            base_name = args.output.rsplit('.', 1)[0]
            
            if args.format == 'json':
                output_file = f"{base_name}.json"
                report_generator.generate_json_report(output_file)
            elif args.format == 'html':
                output_file = f"{base_name}.html"
                report_generator.generate_html_report(output_file)
            elif args.format == 'csv':
                output_file = f"{base_name}.csv"
                report_generator.generate_csv_report(output_file)
            elif args.format == 'xml':
                output_file = f"{base_name}.xml"
                report_generator.generate_xml_report(output_file)
            
            print(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} Report saved to {output_file}")
        
        # Print summary
        report_generator.print_summary()
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[INFO]{Style.RESET_ALL} Scan interrupted by user")
    except Exception as e:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} An error occurred: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
    finally:
        if scanner:
            scanner.cleanup()


if __name__ == '__main__':
    main()
