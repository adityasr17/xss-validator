# XSS Vulnerability Scanner

A simple XSS (Cross-Site Scripting) vulnerability scanner that detects Reflected and Stored XSS vulnerabilities. This lightweight tool is designed for security professionals, penetration testers, and developers to identify XSS vulnerabilities in web applications.

## 🚀 Features

### XSS Detection

- **Reflected XSS**: Detects XSS in URL parameters and form inputs that are immediately reflected
- **Stored XSS**: Identifies persistent XSS in forms where user input is stored and displayed later
- **Lightweight**: No heavy dependencies like Selenium
- **Fast Scanning**: Multi-threaded testing for speed

### Testing Capabilities

- **XSS Payloads**: Essential payload database with unique identifiers for tracking
- **Form Analysis**: Automatically detects and tests web forms
- **URL Discovery**: Simple link extraction and testing
- **Payload Verification**: Revisits pages to verify if stored payloads persist

### Performance

- **Concurrent Testing**: Multi-threaded scanning for speed
- **Configurable Threads**: Adjust scanning speed
- **Error Handling**: Robust error handling and recovery

### Reporting

- **JSON Reports**: Export results in JSON format
- **Console Output**: Real-time vulnerability detection feedback

## 📦 Installation

### Manual Installation

```bash
# Clone the repository
git clone <repository-url>
cd mini_project

# Install Python dependencies
pip install -r requirements.txt
```

### Requirements

- Python 3.7+
- Internet connection

## 🎯 Usage

### Quick Start

```bash
# Basic scan
python simple_xss_scanner.py -u https://example.com

# Scan with custom threads
python simple_xss_scanner.py -u https://example.com --threads 10

# Save results to file
python simple_xss_scanner.py -u https://example.com --output results.json
```

## 🔧 Configuration

### Command Line Options

| Option      | Description                  | Default |
| ----------- | ---------------------------- | ------- |
| `-u, --url` | Target URL (required)        | -       |
| `--threads` | Number of concurrent threads | 5       |
| `--timeout` | Request timeout in seconds   | 10      |
| `--output`  | Output JSON file             | -       |

## 📊 Sample Output

### Console Output

```
Starting XSS scan for https://example.com
Scanning for Reflected and Stored XSS vulnerabilities...

[1/3] Discovering URLs...
Found 5 URLs to test

[2/3] Testing for Reflected XSS and submitting Stored XSS payloads...
[VULN] Reflected XSS found: q in https://example.com/search

[3/3] Verifying Stored XSS (3 candidates)...
[VULN] Stored XSS found! Submitted at https://example.com/comment, appears at https://example.com/

==================================================
Scan completed in 18.45 seconds
Found 2 vulnerabilities
  - Reflected XSS: 1
  - Stored XSS: 1
==================================================
```

### JSON Report Sample

```json
{
  "scan_info": {
    "target": "https://example.com",
    "urls_tested": 5,
    "stored_xss_candidates": 3,
    "vulnerabilities_found": 2
  },
  "vulnerabilities": [
    {
      "type": "Reflected XSS",
      "url": "https://example.com/search?q=...",
      "parameter": "q",
      "payload": "<script>alert('XSS')</script>",
      "method": "GET"
    },
    {
      "type": "Stored XSS",
      "submission_url": "https://example.com/comment",
      "display_url": "https://example.com/",
      "payload": "<script>alert('XSS-a1b2c3d4')</script>",
      "method": "POST",
      "fields": ["comment", "name"]
    }
  ]
}
```

## 🛠️ Architecture

### Core Components

- `simple_xss_scanner.py` - Lightweight scanner for XSS testing

### Flow Diagram

```
Target URL Input
    ↓
URL Discovery
    ↓
Form Detection & Analysis
    ↓
Reflected XSS Testing (immediate response)
    ↓
Stored XSS Payload Submission
    ↓
Stored XSS Verification (revisit pages)
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
- The scanner tests GET parameters and form inputs for immediate reflection

#### Stored XSS (Persistent XSS)

- User input is stored on the server and later displayed to users
- Found in comments, user profiles, message boards, and review sections
- More dangerous as it can affect multiple users over time
- The scanner submits payloads with unique identifiers and revisits pages to verify persistence

### How Stored XSS Detection Works

1. **Identification**: Scanner identifies forms with fields likely to store data (comment, message, review, etc.)
2. **Submission**: Unique payloads are submitted to these forms
3. **Verification**: Scanner revisits the same page and related pages to check if the payload persists
4. **Detection**: If the unique payload appears on a subsequent visit, Stored XSS is confirmed

### Common Vulnerable Parameters

- Search queries: `q`, `query`, `search`, `keyword`
- User data: `name`, `email`, `comment`, `message`
- Navigation: `url`, `redirect`, `return`, `callback`
- Identifiers: `id`, `user`, `page`, `category`
- Content fields: `description`, `review`, `feedback`, `note`, `body`, `post`

## 🔧 Troubleshooting

### Common Issues

#### Permission Errors

- Ensure you have permission to test the target
- Check if the website blocks automated requests

### Performance Optimization

- Reduce thread count for slower servers: `--threads 3`
- Increase timeout for slow responses: `--timeout 20`

## 🤝 Contributing

We welcome contributions! Areas for improvement:

- Additional payload techniques
- New discovery methods
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
