#!/usr/bin/env python3
"""
XSS Vulnerability Scanner
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
import dns.resolver
import tqdm

# Initialize colorama for colored output
init(autoreset=True)

class XSSScanner:
    def __init__(self, target_url: str, depth: int = 2, threads: int = 5, 
                 timeout: int = 10, user_agent: str = None, enable_subdomains: bool = False):
        self.target_url = target_url.rstrip('/')
        self.domain = urllib.parse.urlparse(target_url).netloc
        self.depth = depth
        self.threads = threads
        self.timeout = timeout
        self.enable_subdomains = enable_subdomains
        
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
        self.payloads = self._load_payloads()
        
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
            
            service = Service(ChromeDriverManager().install())
            self.driver = webdriver.Chrome(service=service, options=options)
            print(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} Selenium WebDriver initialized")
        except Exception as e:
            print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} Failed to initialize Selenium: {e}")
            print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} DOM-based XSS testing will be disabled")
    
    def _load_payloads(self) -> List[str]:
        """Load XSS payloads for testing"""
        payloads = [
            # Basic payloads
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
            
            # Event handlers
            "<body onload=alert('XSS')>",
            "<div onmouseover=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<marquee onstart=alert('XSS')>",
            "<video><source onerror=alert('XSS')>",
            
            # Encoded payloads
            "%3Cscript%3Ealert('XSS')%3C/script%3E",
            "&lt;script&gt;alert('XSS')&lt;/script&gt;",
            "&#60;script&#62;alert('XSS')&#60;/script&#62;",
            
            # Filter bypasses
            "<ScRiPt>alert('XSS')</ScRiPt>",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<img src=\"x\" onerror=\"alert('XSS')\">",
            "'\"><script>alert('XSS')</script>",
            "\"><script>alert('XSS')</script>",
            "<script>alert(/XSS/)</script>",
            
            # Advanced payloads
            "<svg><script>alert('XSS')</script></svg>",
            "<math><mi//xlink:href=\"data:x,<script>alert('XSS')</script>\">",
            "<embed src=javascript:alert('XSS')>",
            "<object data=javascript:alert('XSS')>",
            "<applet code=javascript:alert('XSS')>",
            
            # Attribute-based
            "\" onmouseover=alert('XSS') \"",
            "' onmouseover=alert('XSS') '",
            "\"> <script>alert('XSS')</script>",
            "'> <script>alert('XSS')</script>",
            
            # Template injection
            "{{alert('XSS')}}",
            "${alert('XSS')}",
            "#{alert('XSS')}",
            
            # Special characters
            "<script>alert('XSS\u0027)</script>",
            "<script>alert('XSS\u0022)</script>",
            "<script>alert`XSS`</script>",
        ]
        
        print(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} Loaded {len(payloads)} XSS payloads")
        return payloads
    
    def discover_subdomains(self) -> Set[str]:
        """Discover subdomains using DNS enumeration"""
        if not self.enable_subdomains:
            return {self.domain}
            
        print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Discovering subdomains for {self.domain}")
        subdomains = {self.domain}
        
        # Common subdomain wordlist
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'api', 
            'app', 'blog', 'shop', 'store', 'portal', 'support', 'help',
            'docs', 'cdn', 'assets', 'static', 'media', 'images', 'uploads',
            'secure', 'login', 'auth', 'sso', 'vpn', 'remote', 'mx', 'ns',
            'mobile', 'm', 'beta', 'alpha', 'pre', 'prod', 'live'
        ]
        
        for subdomain in common_subdomains:
            target = f"{subdomain}.{self.domain}"
            try:
                dns.resolver.resolve(target, 'A')
                subdomains.add(target)
                print(f"{Fore.GREEN}[FOUND]{Style.RESET_ALL} Subdomain: {target}")
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, Exception):
                pass
        
        self.subdomains = subdomains
        print(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} Found {len(subdomains)} subdomains")
        return subdomains
    
    def crawl_endpoints(self, url: str, current_depth: int = 0) -> Set[str]:
        """Crawl website to discover endpoints"""
        if current_depth > self.depth or url in self.discovered_urls:
            return set()
        
        self.discovered_urls.add(url)
        found_urls = {url}
        
        try:
            response = self.session.get(url, allow_redirects=True)
            if response.status_code != 200:
                return found_urls
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Find all links
            for link in soup.find_all(['a', 'form'], href=True):
                href = link.get('href') or link.get('action')
                if href:
                    absolute_url = urllib.parse.urljoin(url, href)
                    parsed = urllib.parse.urlparse(absolute_url)
                    
                    # Only crawl same domain
                    if parsed.netloc == urllib.parse.urlparse(url).netloc:
                        found_urls.add(absolute_url)
                        if current_depth < self.depth:
                            found_urls.update(self.crawl_endpoints(absolute_url, current_depth + 1))
            
            # Find forms for potential input points
            for form in soup.find_all('form'):
                action = form.get('action', '')
                if action:
                    form_url = urllib.parse.urljoin(url, action)
                    found_urls.add(form_url)
        
        except Exception as e:
            print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} Error crawling {url}: {e}")
        
        return found_urls
    
    def test_reflected_xss(self, url: str, payload: str) -> Optional[Dict]:
        """Test for reflected XSS vulnerability"""
        parsed_url = urllib.parse.urlparse(url)
        
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
                    if payload in response.text and 'text/html' in response.headers.get('content-type', ''):
                        return {
                            'type': 'Reflected XSS',
                            'url': full_url,
                            'parameter': param_name,
                            'payload': payload,
                            'method': 'GET',
                            'evidence': f"Payload reflected in response at parameter '{param_name}'"
                        }
                except Exception:
                    pass
        
        # Test POST forms
        try:
            response = self.session.get(url)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            for form in soup.find_all('form'):
                form_action = form.get('action', url)
                form_url = urllib.parse.urljoin(url, form_action)
                method = form.get('method', 'GET').upper()
                
                if method == 'POST':
                    form_data = {}
                    for input_field in form.find_all(['input', 'textarea', 'select']):
                        field_name = input_field.get('name')
                        if field_name:
                            form_data[field_name] = payload
                    
                    if form_data:
                        try:
                            post_response = self.session.post(form_url, data=form_data)
                            if payload in post_response.text and 'text/html' in post_response.headers.get('content-type', ''):
                                return {
                                    'type': 'Reflected XSS',
                                    'url': form_url,
                                    'parameter': list(form_data.keys()),
                                    'payload': payload,
                                    'method': 'POST',
                                    'evidence': f"Payload reflected in response via POST form"
                                }
                        except Exception:
                            pass
        except Exception:
            pass
        
        return None
    
    def test_stored_xss(self, url: str, payload: str) -> Optional[Dict]:
        """Test for stored XSS vulnerability"""
        try:
            # First, submit the payload
            response = self.session.get(url)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            for form in soup.find_all('form'):
                form_action = form.get('action', url)
                form_url = urllib.parse.urljoin(url, form_action)
                method = form.get('method', 'GET').upper()
                
                if method == 'POST':
                    form_data = {}
                    for input_field in form.find_all(['input', 'textarea', 'select']):
                        field_name = input_field.get('name')
                        field_type = input_field.get('type', 'text')
                        
                        if field_name and field_type not in ['submit', 'button', 'reset']:
                            if field_type == 'hidden':
                                form_data[field_name] = input_field.get('value', '')
                            else:
                                form_data[field_name] = payload
                    
                    if form_data:
                        try:
                            # Submit the payload
                            self.session.post(form_url, data=form_data)
                            
                            # Wait a moment for processing
                            time.sleep(1)
                            
                            # Check if payload is stored by visiting the page again
                            check_response = self.session.get(url)
                            if payload in check_response.text and 'text/html' in check_response.headers.get('content-type', ''):
                                return {
                                    'type': 'Stored XSS',
                                    'url': url,
                                    'form_action': form_url,
                                    'payload': payload,
                                    'method': 'POST',
                                    'evidence': f"Payload stored and executed on page reload"
                                }
                        except Exception:
                            pass
        except Exception:
            pass
        
        return None
    
    def test_dom_xss(self, url: str, payload: str) -> Optional[Dict]:
        """Test for DOM-based XSS vulnerability using Selenium"""
        if not self.driver:
            return None
        
        try:
            # Test URL fragments
            test_url = f"{url}#{payload}"
            self.driver.get(test_url)
            
            # Wait for page to load
            WebDriverWait(self.driver, 5).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            
            # Check for alert dialogs (XSS execution)
            try:
                WebDriverWait(self.driver, 2).until(EC.alert_is_present())
                alert = self.driver.switch_to.alert
                alert_text = alert.text
                alert.accept()
                
                if 'XSS' in alert_text:
                    return {
                        'type': 'DOM-based XSS',
                        'url': test_url,
                        'payload': payload,
                        'method': 'Fragment',
                        'evidence': f"JavaScript alert triggered: {alert_text}"
                    }
            except TimeoutException:
                pass
            
            # Check if payload is reflected in DOM
            page_source = self.driver.page_source
            if payload in page_source:
                # Additional check for script execution context
                scripts = self.driver.find_elements(By.TAG_NAME, "script")
                for script in scripts:
                    if payload in script.get_attribute('innerHTML'):
                        return {
                            'type': 'DOM-based XSS',
                            'url': test_url,
                            'payload': payload,
                            'method': 'Fragment',
                            'evidence': f"Payload found in script context"
                        }
            
        except Exception as e:
            pass
        
        return None
    
    def test_url_for_xss(self, url: str) -> List[Dict]:
        """Test a single URL for all types of XSS vulnerabilities"""
        vulnerabilities = []
        
        for payload in self.payloads:
            # Test Reflected XSS
            reflected_vuln = self.test_reflected_xss(url, payload)
            if reflected_vuln:
                vulnerabilities.append(reflected_vuln)
                print(f"{Fore.RED}[VULN]{Style.RESET_ALL} Reflected XSS found at: {url}")
                break  # Don't test more payloads for same type
            
            # Test Stored XSS
            stored_vuln = self.test_stored_xss(url, payload)
            if stored_vuln:
                vulnerabilities.append(stored_vuln)
                print(f"{Fore.RED}[VULN]{Style.RESET_ALL} Stored XSS found at: {url}")
                break
            
            # Test DOM-based XSS
            dom_vuln = self.test_dom_xss(url, payload)
            if dom_vuln:
                vulnerabilities.append(dom_vuln)
                print(f"{Fore.RED}[VULN]{Style.RESET_ALL} DOM-based XSS found at: {url}")
                break
        
        return vulnerabilities
    
    def scan(self) -> Dict:
        """Main scanning function"""
        print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Starting XSS scan for {self.target_url}")
        start_time = datetime.now()
        
        # Discover subdomains
        subdomains = self.discover_subdomains()
        
        # Crawl all subdomains
        all_urls = set()
        for subdomain in subdomains:
            subdomain_url = f"{urllib.parse.urlparse(self.target_url).scheme}://{subdomain}"
            print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Crawling {subdomain_url}")
            urls = self.crawl_endpoints(subdomain_url)
            all_urls.update(urls)
        
        print(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} Found {len(all_urls)} endpoints to test")
        
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
        
        # Generate report
        report = {
            'scan_info': {
                'target': self.target_url,
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration_seconds': scan_duration,
                'urls_tested': len(all_urls),
                'subdomains_found': len(subdomains),
                'vulnerabilities_found': len(self.vulnerabilities)
            },
            'subdomains': list(subdomains),
            'vulnerabilities': self.vulnerabilities
        }
        
        print(f"\n{Fore.GREEN}[COMPLETE]{Style.RESET_ALL} Scan completed in {scan_duration:.2f} seconds")
        print(f"{Fore.GREEN}[RESULT]{Style.RESET_ALL} Found {len(self.vulnerabilities)} XSS vulnerabilities")
        
        return report
    
    def cleanup(self):
        """Clean up resources"""
        if self.driver:
            self.driver.quit()
        self.session.close()


def main():
    parser = argparse.ArgumentParser(description='XSS Vulnerability Scanner')
    parser.add_argument('-u', '--url', required=True, help='Target URL to scan')
    parser.add_argument('-d', '--depth', type=int, default=2, help='Crawling depth (default: 2)')
    parser.add_argument('--subdomains', action='store_true', help='Enable subdomain enumeration')
    parser.add_argument('--threads', type=int, default=5, help='Number of concurrent threads (default: 5)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('--user-agent', help='Custom User-Agent string')
    parser.add_argument('--output', help='Output file for results (JSON format)')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
    
    args = parser.parse_args()
    
    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} URL must start with http:// or https://")
        sys.exit(1)
    
    scanner = None
    try:
        # Initialize scanner
        scanner = XSSScanner(
            target_url=args.url,
            depth=args.depth,
            threads=args.threads,
            timeout=args.timeout,
            user_agent=args.user_agent,
            enable_subdomains=args.subdomains
        )
        
        # Run scan
        report = scanner.scan()
        
        # Save report
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} Report saved to {args.output}")
        
        # Print summary
        vuln_types = {}
        for vuln in report['vulnerabilities']:
            vuln_type = vuln['type']
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
        
        print(f"\n{Fore.CYAN}=== SCAN SUMMARY ==={Style.RESET_ALL}")
        print(f"Target: {report['scan_info']['target']}")
        print(f"URLs tested: {report['scan_info']['urls_tested']}")
        print(f"Subdomains found: {report['scan_info']['subdomains_found']}")
        print(f"Total vulnerabilities: {report['scan_info']['vulnerabilities_found']}")
        
        if vuln_types:
            print(f"\n{Fore.YELLOW}Vulnerability breakdown:{Style.RESET_ALL}")
            for vuln_type, count in vuln_types.items():
                print(f"  {vuln_type}: {count}")
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[INFO]{Style.RESET_ALL} Scan interrupted by user")
    except Exception as e:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} An error occurred: {e}")
        sys.exit(1)
    finally:
        if scanner:
            scanner.cleanup()


if __name__ == '__main__':
    main()
