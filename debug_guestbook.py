import requests
import re

url = 'http://testphp.vulnweb.com/guestbook.php'
response = requests.get(url)

forms = re.findall(r'(<form.*?</form>)', response.text, re.DOTALL | re.IGNORECASE)

print(f"Found {len(forms)} forms:")
for i, form in enumerate(forms):
    print(f"--- Form {i+1} ---")
    print(form)
