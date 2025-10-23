"""
URL discovery and crawling utilities
"""

import urllib.parse
import re
import time
from typing import Set, List, Dict
from bs4 import BeautifulSoup
import requests


class URLDiscovery:
    """Advanced URL discovery and crawling"""
    
    def __init__(self, session: requests.Session, max_depth: int = 3):
        self.session = session
        self.max_depth = max_depth
        self.discovered_urls: Set[str] = set()
        self.crawled_urls: Set[str] = set()
        
    def extract_urls_from_html(self, html_content: str, base_url: str) -> Set[str]:
        """Extract URLs from HTML content"""
        urls = set()
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Extract from various HTML elements
        for element in soup.find_all(['a', 'form', 'frame', 'iframe', 'link', 'script', 'img']):
            # Get URL from different attributes
            for attr in ['href', 'src', 'action', 'data-href', 'data-src']:
                url = element.get(attr)
                if url:
                    absolute_url = urllib.parse.urljoin(base_url, url)
                    urls.add(absolute_url)
        
        # Extract from inline JavaScript
        js_urls = self._extract_from_javascript(html_content, base_url)
        urls.update(js_urls)
        
        # Extract from CSS
        css_urls = self._extract_from_css(html_content, base_url)
        urls.update(css_urls)
        
        return urls
    
    def _extract_from_javascript(self, html_content: str, base_url: str) -> Set[str]:
        """Extract URLs from JavaScript code"""
        urls = set()
        
        # Common JavaScript URL patterns
        js_patterns = [
            r'(?:location\.href|window\.location)\s*=\s*["\']([^"\']+)["\']',
            r'(?:fetch|xhr\.open|ajax)\s*\([^,]*["\']([^"\']+)["\']',
            r'["\']([^"\']*\.(?:php|asp|aspx|jsp|json|xml|html|htm)[^"\']*)["\']',
            r'["\']([^"\']*\/[^"\']*)["\']'
        ]
        
        for pattern in js_patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            for match in matches:
                if match.startswith(('http', '/', '.')):
                    absolute_url = urllib.parse.urljoin(base_url, match)
                    urls.add(absolute_url)
        
        return urls
    
    def _extract_from_css(self, html_content: str, base_url: str) -> Set[str]:
        """Extract URLs from CSS"""
        urls = set()
        
        # CSS URL patterns
        css_pattern = r'url\s*\(\s*["\']?([^"\']+)["\']?\s*\)'
        matches = re.findall(css_pattern, html_content, re.IGNORECASE)
        
        for match in matches:
            absolute_url = urllib.parse.urljoin(base_url, match)
            urls.add(absolute_url)
        
        return urls
    
    def discover_sitemap(self, base_url: str) -> Set[str]:
        """Discover URLs from sitemap.xml"""
        urls = set()
        
        sitemap_urls = [
            '/sitemap.xml',
            '/sitemap_index.xml',
            '/sitemaps.xml',
            '/sitemap/',
            '/robots.txt'
        ]
        
        for sitemap_path in sitemap_urls:
            sitemap_url = urllib.parse.urljoin(base_url, sitemap_path)
            try:
                response = self.session.get(sitemap_url, timeout=10)
                if response.status_code == 200:
                    if sitemap_path.endswith('.xml'):
                        # Parse XML sitemap
                        urls.update(self._parse_sitemap_xml(response.text, base_url))
                    elif sitemap_path.endswith('robots.txt'):
                        # Parse robots.txt
                        urls.update(self._parse_robots_txt(response.text, base_url))
            except Exception:
                continue
        
        return urls
    
    def _parse_sitemap_xml(self, xml_content: str, base_url: str) -> Set[str]:
        """Parse XML sitemap"""
        urls = set()
        
        # Extract <loc> tags
        loc_pattern = r'<loc>([^<]+)</loc>'
        matches = re.findall(loc_pattern, xml_content, re.IGNORECASE)
        
        for match in matches:
            absolute_url = urllib.parse.urljoin(base_url, match)
            urls.add(absolute_url)
        
        return urls
    
    def _parse_robots_txt(self, robots_content: str, base_url: str) -> Set[str]:
        """Parse robots.txt for disallowed paths"""
        urls = set()
        
        disallow_pattern = r'Disallow:\s*([^\s]+)'
        matches = re.findall(disallow_pattern, robots_content, re.IGNORECASE)
        
        for match in matches:
            if match != '/':  # Ignore root disallow
                absolute_url = urllib.parse.urljoin(base_url, match)
                urls.add(absolute_url)
        
        return urls
    
    def discover_common_files(self, base_url: str) -> Set[str]:
        """Discover common files and directories"""
        urls = set()
        
        common_paths = [
            # Admin panels
            '/admin', '/admin/', '/admin.php', '/administrator',
            '/wp-admin', '/phpmyadmin', '/cpanel',
            
            # API endpoints
            '/api', '/api/', '/api/v1', '/api/v2', '/rest', '/graphql',
            
            # Configuration files
            '/config', '/config.php', '/configuration.php', '/.env',
            '/web.config', '/app.config',
            
            # Backup files
            '/backup', '/backups', '/backup.sql', '/db.sql',
            
            # Upload directories
            '/upload', '/uploads', '/files', '/media', '/images',
            
            # Development files
            '/test', '/tests', '/dev', '/development', '/staging',
            '/debug', '/.git', '/.svn',
            
            # Common pages
            '/login', '/register', '/contact', '/about', '/search',
            '/profile', '/account', '/dashboard', '/settings'
        ]
        
        for path in common_paths:
            url = urllib.parse.urljoin(base_url, path)
            urls.add(url)
        
        return urls
    
    def discover_parameter_endpoints(self, base_url: str) -> Set[str]:
        """Discover endpoints with common parameters"""
        urls = set()
        
        common_params = [
            'id', 'user', 'name', 'search', 'q', 'query', 'keyword',
            'page', 'p', 'category', 'cat', 'type', 'action', 'cmd',
            'file', 'path', 'url', 'redirect', 'return', 'callback'
        ]
        
        # Add parameters to base URL
        for param in common_params:
            parameterized_url = f"{base_url}?{param}=test"
            urls.add(parameterized_url)
        
        return urls
    
    def crawl_depth_first(self, start_url: str, target_domain: str) -> Set[str]:
        """Perform depth-first crawling"""
        to_crawl = [start_url]
        depth_map = {start_url: 0}
        
        while to_crawl:
            current_url = to_crawl.pop(0)
            current_depth = depth_map[current_url]
            
            if current_depth > self.max_depth or current_url in self.crawled_urls:
                continue
            
            self.crawled_urls.add(current_url)
            
            try:
                response = self.session.get(current_url, timeout=10)
                if response.status_code == 200 and 'text/html' in response.headers.get('content-type', ''):
                    # Extract URLs from this page
                    found_urls = self.extract_urls_from_html(response.text, current_url)
                    
                    for url in found_urls:
                        parsed = urllib.parse.urlparse(url)
                        
                        # Only crawl same domain
                        if parsed.netloc == target_domain and url not in self.discovered_urls:
                            self.discovered_urls.add(url)
                            
                            if current_depth < self.max_depth:
                                to_crawl.append(url)
                                depth_map[url] = current_depth + 1
                
                # Small delay to avoid overwhelming the server
                time.sleep(0.1)
                
            except Exception:
                continue
        
        return self.discovered_urls
    
    def comprehensive_discovery(self, base_url: str) -> Set[str]:
        """Perform comprehensive URL discovery"""
        parsed_url = urllib.parse.urlparse(base_url)
        target_domain = parsed_url.netloc
        
        all_urls = set()
        
        # 1. Basic crawling
        crawled_urls = self.crawl_depth_first(base_url, target_domain)
        all_urls.update(crawled_urls)
        
        # 2. Sitemap discovery
        sitemap_urls = self.discover_sitemap(base_url)
        all_urls.update(sitemap_urls)
        
        # 3. Common files discovery
        common_urls = self.discover_common_files(base_url)
        all_urls.update(common_urls)
        
        # 4. Parameter endpoints
        param_urls = self.discover_parameter_endpoints(base_url)
        all_urls.update(param_urls)
        
        # Filter to only include same domain
        filtered_urls = set()
        for url in all_urls:
            parsed = urllib.parse.urlparse(url)
            if parsed.netloc == target_domain:
                filtered_urls.add(url)
        
        return filtered_urls


class FormDiscovery:
    """Discover and analyze forms for testing"""
    
    @staticmethod
    def extract_forms(html_content: str, base_url: str) -> List[Dict]:
        """Extract form information from HTML"""
        forms = []
        soup = BeautifulSoup(html_content, 'html.parser')
        
        for form in soup.find_all('form'):
            form_info = {
                'action': urllib.parse.urljoin(base_url, form.get('action', '')),
                'method': form.get('method', 'GET').upper(),
                'inputs': [],
                'textareas': [],
                'selects': []
            }
            
            # Extract input fields
            for input_field in form.find_all('input'):
                input_info = {
                    'name': input_field.get('name'),
                    'type': input_field.get('type', 'text'),
                    'value': input_field.get('value', ''),
                    'required': input_field.has_attr('required')
                }
                form_info['inputs'].append(input_info)
            
            # Extract textarea fields
            for textarea in form.find_all('textarea'):
                textarea_info = {
                    'name': textarea.get('name'),
                    'value': textarea.get_text(),
                    'required': textarea.has_attr('required')
                }
                form_info['textareas'].append(textarea_info)
            
            # Extract select fields
            for select in form.find_all('select'):
                select_info = {
                    'name': select.get('name'),
                    'options': [option.get('value') for option in select.find_all('option')],
                    'required': select.has_attr('required')
                }
                form_info['selects'].append(select_info)
            
            forms.append(form_info)
        
        return forms
