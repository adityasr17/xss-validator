"""
Subdomain enumeration utilities
"""

import dns.resolver
import requests
import threading
import queue
from typing import Set, List
import time


class SubdomainEnumerator:
    """Comprehensive subdomain enumeration"""
    
    def __init__(self, domain: str, timeout: int = 5, threads: int = 10):
        self.domain = domain
        self.timeout = timeout
        self.threads = threads
        self.found_subdomains: Set[str] = set()
        self.wordlist = self._get_subdomain_wordlist()
    
    def _get_subdomain_wordlist(self) -> List[str]:
        """Get comprehensive subdomain wordlist"""
        return [
            # Common subdomains
            'www', 'mail', 'ftp', 'cpanel', 'webmail', 'email', 'cloud',
            'admin', 'administrator', 'root', 'test', 'testing', 'demo',
            'dev', 'development', 'staging', 'stage', 'prod', 'production',
            'live', 'beta', 'alpha', 'preview', 'pre', 'uat',
            
            # API and services
            'api', 'app', 'service', 'services', 'rest', 'graphql',
            'gateway', 'proxy', 'load-balancer', 'lb',
            
            # Content and media
            'blog', 'news', 'forum', 'chat', 'support', 'help', 'docs',
            'documentation', 'wiki', 'kb', 'knowledgebase',
            'cdn', 'static', 'assets', 'media', 'images', 'img',
            'files', 'uploads', 'download', 'downloads',
            
            # E-commerce
            'shop', 'store', 'cart', 'checkout', 'payment', 'pay',
            'billing', 'invoice', 'order', 'orders',
            
            # Authentication and security
            'login', 'auth', 'authentication', 'sso', 'oauth', 'saml',
            'secure', 'ssl', 'vpn', 'remote', 'rdp',
            
            # Monitoring and analytics
            'monitor', 'monitoring', 'metrics', 'analytics', 'stats',
            'status', 'health', 'ping', 'uptime',
            
            # Database and storage
            'db', 'database', 'mysql', 'postgres', 'mongo', 'redis',
            'cache', 'memcache', 'elasticsearch', 'es',
            
            # Mail services
            'smtp', 'pop', 'pop3', 'imap', 'exchange', 'outlook',
            'mailserver', 'mx', 'mx1', 'mx2', 'mx3',
            
            # Network infrastructure
            'ns', 'ns1', 'ns2', 'ns3', 'dns', 'resolver',
            'router', 'switch', 'firewall', 'gateway',
            
            # Geographic/Regional
            'us', 'eu', 'asia', 'africa', 'au', 'ca', 'uk',
            'east', 'west', 'north', 'south', 'central',
            
            # Environments
            'local', 'localhost', 'internal', 'private', 'public',
            'external', 'dmz', 'edge',
            
            # Version specific
            'v1', 'v2', 'v3', 'v4', 'version1', 'version2',
            'old', 'new', 'legacy', 'current',
            
            # Common numbers
            '1', '2', '3', '4', '5', '01', '02', '03',
            
            # Common hosting patterns
            'host', 'hosting', 'shared', 'dedicated', 'vps',
            'cloud1', 'cloud2', 'server', 'srv', 'srv1', 'srv2',
            
            # Mobile and apps
            'mobile', 'm', 'app', 'android', 'ios', 'tablet',
            
            # Social and community
            'social', 'community', 'forum', 'discussion', 'board'
        ]
    
    def dns_bruteforce(self) -> Set[str]:
        """Brute force subdomain discovery using DNS"""
        found = set()
        
        def check_subdomain(subdomain: str, result_queue: queue.Queue):
            """Check if subdomain exists"""
            target = f"{subdomain}.{self.domain}"
            try:
                dns.resolver.resolve(target, 'A')
                result_queue.put(target)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, Exception):
                pass
        
        result_queue = queue.Queue()
        threads = []
        
        # Create threads for concurrent checking
        for subdomain in self.wordlist:
            thread = threading.Thread(target=check_subdomain, args=(subdomain, result_queue))
            threads.append(thread)
            thread.start()
            
            # Limit concurrent threads
            if len(threads) >= self.threads:
                for t in threads:
                    t.join()
                threads = []
        
        # Wait for remaining threads
        for thread in threads:
            thread.join()
        
        # Collect results
        while not result_queue.empty():
            found.add(result_queue.get())
        
        return found
    
    def certificate_transparency(self) -> Set[str]:
        """Find subdomains using Certificate Transparency logs"""
        found = set()
        
        ct_apis = [
            f"https://crt.sh/?q=%.{self.domain}&output=json",
            f"https://api.certspotter.com/v1/issuances?domain={self.domain}&include_subdomains=true&expand=dns_names"
        ]
        
        for api_url in ct_apis:
            try:
                response = requests.get(api_url, timeout=self.timeout)
                if response.status_code == 200:
                    data = response.json()
                    
                    if 'crt.sh' in api_url:
                        # Parse crt.sh response
                        for cert in data:
                            name_value = cert.get('name_value', '')
                            for name in name_value.split('\n'):
                                name = name.strip()
                                if name.endswith(f".{self.domain}"):
                                    # Remove wildcard
                                    if name.startswith('*.'):
                                        name = name[2:]
                                    found.add(name)
                    
                    elif 'certspotter' in api_url:
                        # Parse certspotter response
                        for cert in data:
                            dns_names = cert.get('dns_names', [])
                            for name in dns_names:
                                if name.endswith(f".{self.domain}"):
                                    # Remove wildcard
                                    if name.startswith('*.'):
                                        name = name[2:]
                                    found.add(name)
            
            except Exception:
                continue
        
        return found
    
    def search_engines(self) -> Set[str]:
        """Find subdomains using search engines"""
        found = set()
        
        # Google search
        try:
            google_query = f"site:{self.domain}"
            # Note: This would require implementing proper Google search API
            # For now, we'll skip this to avoid rate limiting
            pass
        except Exception:
            pass
        
        return found
    
    def wayback_machine(self) -> Set[str]:
        """Find subdomains using Wayback Machine"""
        found = set()
        
        try:
            wayback_url = f"http://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=json&collapse=urlkey"
            response = requests.get(wayback_url, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data[1:]:  # Skip header
                    if len(entry) > 2:
                        url = entry[2]
                        if '://' in url:
                            domain_part = url.split('://')[1].split('/')[0]
                            if domain_part.endswith(f".{self.domain}"):
                                found.add(domain_part)
        
        except Exception:
            pass
        
        return found
    
    def virustotal_api(self) -> Set[str]:
        """Find subdomains using VirusTotal API (requires API key)"""
        found = set()
        
        # Note: This would require a VirusTotal API key
        # Implementation would be similar to other APIs
        
        return found
    
    def comprehensive_enumeration(self) -> Set[str]:
        """Perform comprehensive subdomain enumeration"""
        print(f"[INFO] Starting comprehensive subdomain enumeration for {self.domain}")
        
        all_subdomains = set()
        
        # 1. DNS Brute Force
        print("[INFO] Performing DNS brute force...")
        dns_results = self.dns_bruteforce()
        all_subdomains.update(dns_results)
        print(f"[INFO] DNS brute force found {len(dns_results)} subdomains")
        
        # 2. Certificate Transparency
        print("[INFO] Checking Certificate Transparency logs...")
        ct_results = self.certificate_transparency()
        all_subdomains.update(ct_results)
        print(f"[INFO] Certificate Transparency found {len(ct_results)} subdomains")
        
        # 3. Wayback Machine
        print("[INFO] Checking Wayback Machine...")
        wayback_results = self.wayback_machine()
        all_subdomains.update(wayback_results)
        print(f"[INFO] Wayback Machine found {len(wayback_results)} subdomains")
        
        # Validate discovered subdomains
        validated_subdomains = self._validate_subdomains(all_subdomains)
        
        print(f"[INFO] Total unique subdomains found: {len(validated_subdomains)}")
        return validated_subdomains
    
    def _validate_subdomains(self, subdomains: Set[str]) -> Set[str]:
        """Validate discovered subdomains"""
        validated = set()
        
        def validate_subdomain(subdomain: str, result_queue: queue.Queue):
            """Validate a single subdomain"""
            try:
                # Check DNS resolution
                dns.resolver.resolve(subdomain, 'A')
                
                # Check HTTP/HTTPS accessibility
                for protocol in ['https', 'http']:
                    try:
                        url = f"{protocol}://{subdomain}"
                        response = requests.head(url, timeout=5, allow_redirects=True)
                        if response.status_code < 400:
                            result_queue.put(subdomain)
                            break
                    except Exception:
                        continue
                        
            except Exception:
                pass
        
        result_queue = queue.Queue()
        threads = []
        
        for subdomain in subdomains:
            thread = threading.Thread(target=validate_subdomain, args=(subdomain, result_queue))
            threads.append(thread)
            thread.start()
            
            # Limit concurrent threads
            if len(threads) >= self.threads:
                for t in threads:
                    t.join()
                threads = []
        
        # Wait for remaining threads
        for thread in threads:
            thread.join()
        
        # Collect results
        while not result_queue.empty():
            validated.add(result_queue.get())
        
        return validated
