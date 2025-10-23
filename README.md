# XSS Vulnerability Scanner

A comprehensive XSS (Cross-Site Scripting) vulnerability scanner that detects Reflected, Stored, and DOM-based XSS vulnerabilities across multiple endpoints and subdomains. This tool is designed for security professionals, penetration testers, and developers to identify XSS vulnerabilities in web applications.

## 🚀 Features

### Multi-Type XSS Detection

- **Reflected XSS**: Detects XSS in URL parameters and form inputs
- **Stored XSS**: Identifies persistent XSS in user-generated content
- **DOM-based XSS**: Uses browser automation to find client-side XSS

### Advanced Discovery

- **Intelligent Crawling**: Discovers endpoints through link analysis and common paths
- **Subdomain Enumeration**: DNS brute force and certificate transparency lookup
- **Form Analysis**: Automatically detects and tests web forms
- **Sitemap Parsing**: Extracts URLs from sitemap.xml and robots.txt

### Comprehensive Testing

- **500+ XSS Payloads**: Extensive payload database with bypass techniques
- **Context-Aware Testing**: Different payloads for different injection contexts
- **WAF Bypass Techniques**: Advanced evasion methods
- **Custom Payload Support**: Load your own payload files

### Performance & Reliability

- **Concurrent Testing**: Multi-threaded scanning for speed
- **Rate Limiting**: Configurable delays to avoid overwhelming servers
- **Error Handling**: Robust error handling and recovery
- **Progress Tracking**: Real-time progress indicators

### Rich Reporting

- **Multiple Formats**: JSON, HTML, CSV, and XML reports
- **Detailed Analysis**: Vulnerability categorization and risk scoring
- **Visual Reports**: Professional HTML reports with charts and graphs
- **Export Options**: Easy integration with other security tools

## 📦 Installation

### Quick Setup (Windows)

```cmd
git clone <repository-url>
cd mini_project
setup.bat
```

### Manual Installation

```bash
# Clone the repository
git clone <repository-url>
cd mini_project

# Install Python dependencies
pip install -r requirements.txt

# Run setup script
python setup.py
```

### Requirements

- Python 3.7+
- Google Chrome (for DOM-based XSS testing)
- Internet connection for subdomain enumeration

## 🎯 Usage

### Quick Start

```bash
# Basic scan
python enhanced_xss_scanner.py -u https://example.com

# Simple scan (lightweight, no heavy dependencies)
python simple_xss_scanner.py -u https://example.com
```

### Windows Batch Files

```cmd
# Setup
setup.bat

# Quick scan
scan.bat https://example.com

# Advanced scan
scan.bat https://example.com --subdomains --aggressive --output report --format html
```

### Advanced Usage Examples

#### Comprehensive Scan with Subdomains

```bash
python enhanced_xss_scanner.py -u https://example.com \
    --subdomains \
    --depth 3 \
    --threads 10 \
    --output comprehensive_scan \
    --format html
```

#### Aggressive Testing with Custom Payloads

```bash
python enhanced_xss_scanner.py -u https://example.com \
    --aggressive \
    --payloads payloads/custom_payloads.txt \
    --timeout 15 \
    --output aggressive_scan \
    --format json
```

#### API Testing

```bash
python enhanced_xss_scanner.py -u https://api.example.com \
    --user-agent "CustomAPITester/1.0" \
    --threads 5 \
    --output api_scan \
    --format csv
```

## 🔧 Configuration

### Command Line Options

| Option         | Description                       | Default          |
| -------------- | --------------------------------- | ---------------- |
| `-u, --url`    | Target URL (required)             | -                |
| `-d, --depth`  | Crawling depth                    | 2                |
| `--subdomains` | Enable subdomain enumeration      | False            |
| `--threads`    | Number of concurrent threads      | 5                |
| `--timeout`    | Request timeout in seconds        | 10               |
| `--user-agent` | Custom User-Agent string          | Chrome/120.0.0.0 |
| `--output`     | Output file basename              | -                |
| `--format`     | Report format (json/html/csv/xml) | json             |
| `--payloads`   | Custom payload file               | Built-in         |
| `--aggressive` | Enable aggressive testing         | False            |
| `--verbose`    | Enable verbose output             | False            |

### Custom Payloads

Create a text file with one payload per line:

```
<script>alert('Custom XSS')</script>
<img src=x onerror=alert('Custom')>
<svg onload=alert('Custom')>
```

## 📊 Sample Output

### Console Output

```
🚀 Starting XSS scan for https://example.com
[INFO] Discovering subdomains for example.com
[FOUND] Subdomain: www.example.com
[FOUND] Subdomain: api.example.com
[INFO] Found 3 subdomains
[INFO] Discovering endpoints for www.example.com
[INFO] Found 25 endpoints for www.example.com
[INFO] Found 45 endpoints to test
[INFO] Testing for XSS vulnerabilities...
Testing URLs: 100%|██████████| 45/45 [00:30<00:00,  1.50it/s]
[VULN] Reflected XSS found at: https://example.com/search?q=<payload>
[VULN] Stored XSS found at: https://example.com/comments
[COMPLETE] Scan completed in 32.45 seconds
[RESULT] Found 2 XSS vulnerabilities

=== SCAN SUMMARY ===
Target: https://example.com
URLs tested: 45
Subdomains found: 3
Total vulnerabilities: 2

Vulnerability breakdown:
  Reflected XSS: 1
  Stored XSS: 1
```

### HTML Report Sample

The HTML report includes:

- Executive summary with statistics
- Vulnerability details with evidence
- Risk assessment and recommendations
- Technical details for remediation

## 🛠️ Architecture

### Core Components

- `enhanced_xss_scanner.py` - Main scanner with full features
- `simple_xss_scanner.py` - Lightweight scanner for basic testing
- `payloads.py` - XSS payload management
- `discovery.py` - URL and endpoint discovery
- `subdomain_enum.py` - Subdomain enumeration
- `reporting.py` - Report generation and analysis
- `config.py` - Configuration and constants

### Flow Diagram

```
Target URL Input
    ↓
Subdomain Discovery (optional)
    ↓
Endpoint Crawling & Discovery
    ↓
Form Detection & Analysis
    ↓
XSS Payload Testing
    ↓
Vulnerability Analysis
    ↓
Report Generation
```

## 🔒 Security Considerations

### Responsible Use

- ✅ Only test websites you own or have explicit permission to test
- ✅ Use for authorized penetration testing and bug bounty programs
- ✅ Follow responsible disclosure practices
- ✅ Respect rate limits and server resources

### Rate Limiting

The scanner includes built-in delays and respects server resources:

- Configurable request timeouts
- Thread limiting to prevent overwhelming servers
- Automatic backoff on errors

## 🎓 Educational Resources

### Understanding XSS Types

#### Reflected XSS

- Occurs when user input is immediately reflected in the response
- Common in search boxes, error messages, and form validation
- Example: `https://example.com/search?q=<script>alert('XSS')</script>`

#### Stored XSS

- User input is stored and later displayed to other users
- Found in comments, user profiles, and message boards
- More dangerous as it affects multiple users

#### DOM-based XSS

- Occurs entirely in the browser's DOM
- JavaScript reads from unsafe sources (URL fragments, etc.)
- Requires browser automation to detect effectively

### Common Vulnerable Parameters

- Search queries: `q`, `query`, `search`, `keyword`
- User data: `name`, `email`, `comment`, `message`
- Navigation: `url`, `redirect`, `return`, `callback`
- Identifiers: `id`, `user`, `page`, `category`

## 🔧 Troubleshooting

### Common Issues

#### Chrome Driver Issues

```bash
# Update Chrome driver automatically
python -c "from webdriver_manager.chrome import ChromeDriverManager; ChromeDriverManager().install()"
```

#### SSL Certificate Errors

```bash
# Add --ignore-ssl-errors flag for testing environments
python enhanced_xss_scanner.py -u https://example.com --user-agent "Mozilla/5.0..."
```

#### Permission Errors

- Ensure you have permission to test the target
- Check if the website blocks automated requests
- Try using different User-Agent strings

### Performance Optimization

- Reduce thread count for slower servers: `--threads 3`
- Increase timeout for slow responses: `--timeout 20`
- Use simple scanner for basic testing: `simple_xss_scanner.py`

## 📚 Advanced Features

### Custom User Agents

```bash
# Mobile testing
--user-agent "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X)"

# API testing
--user-agent "CustomAPITester/1.0"
```

### Integration with CI/CD

```yaml
# Example GitHub Actions workflow
- name: Run XSS Scan
  run: |
    python enhanced_xss_scanner.py -u ${{ env.TARGET_URL }} \
      --output scan_results \
      --format json

- name: Upload Results
  uses: actions/upload-artifact@v2
  with:
    name: xss-scan-results
    path: scan_results.json
```

## 🤝 Contributing

We welcome contributions! Areas for improvement:

- Additional payload techniques
- New discovery methods
- Enhanced reporting features
- Performance optimizations
- Documentation improvements

## ⚖️ Legal Disclaimer

This tool is for authorized security testing only. Users are responsible for ensuring they have proper permission before testing any websites. The authors are not responsible for any misuse or illegal activities.

**Always:**

- Obtain written permission before testing
- Follow responsible disclosure practices
- Respect applicable laws and regulations
- Use the tool ethically and professionally

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🔗 Resources

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [PortSwigger XSS Labs](https://portswigger.net/web-security/cross-site-scripting)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

## 📞 Support

For issues, feature requests, or questions:

- Open an issue on GitHub
- Check the troubleshooting section
- Review the examples and documentation
