from flask import Flask, render_template, request, jsonify
import json
import traceback

# Import scanner components directly to avoid shelling out
from xss_scanner import SimpleXSSScanner  # type: ignore

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    error = None
    url_value = ''

    if request.method == 'POST':
        url_value = request.form.get('url', '').strip()
        if not url_value:
            error = 'Please enter a URL.'
        elif not (url_value.startswith('http://') or url_value.startswith('https://')):
            error = 'URL must start with http:// or https://'
        else:
            try:
                # Run the scanner directly and capture the report
                scanner = SimpleXSSScanner(url_value, timeout=10, threads=5)
                report = scanner.scan()
                # Show JSON in page; also provide a compact summary
                result = {
                    'summary': {
                        'target': report['scan_info']['target'],
                        'urls_tested': report['scan_info']['urls_tested'],
                        'vulnerabilities_found': report['scan_info']['vulnerabilities_found'],
                    },
                    'vulnerabilities': report.get('vulnerabilities', [])
                }
            except Exception:
                error = 'Error running scan:\n' + traceback.format_exc()

    return render_template('index.html', result=result, error=error, url_value=url_value)

@app.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.get_json(silent=True) or {}
    url_value = (data.get('url') or '').strip()
    if not url_value:
        return jsonify({'error': 'Missing url'}), 400
    if not (url_value.startswith('http://') or url_value.startswith('https://')):
        return jsonify({'error': 'URL must start with http:// or https://'}), 400
    try:
        scanner = SimpleXSSScanner(url_value, timeout=10, threads=5)
        report = scanner.scan()
        return jsonify(report)
    except Exception:
        return jsonify({'error': 'Scan failed', 'details': traceback.format_exc()}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
