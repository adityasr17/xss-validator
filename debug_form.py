import requests
import re

url = 'http://testphp.vulnweb.com/guestbook.php'
response = requests.get(url)

# Find the form that contains "guestbook" or "add"
forms = re.findall(r'(<form.*?</form>)', response.text, re.DOTALL | re.IGNORECASE)

for form in forms:
    if 'add' in form or 'guestbook' in form.lower():
        print("--- Guestbook Form ---")
        # Print lines to avoid truncation issues with large blocks
        for line in form.split('\n'):
            print(line)
