"""
Redirect Hell Solver - Easy Edition
Plain text flags in simple locations
"""

import requests
import re
from urllib.parse import urljoin

BASE_URL = "http://34.93.13.209:40389"

def solve():
    print("=" * 50)
    print("🌀 MULTIVERSE SOLVER - EASY EDITION")
    print("=" * 50)
    
    session = requests.Session()
    flag_parts = {}
    dim = 0
    url = f"{BASE_URL}/"
    
    for _ in range(20):
        try:
            resp = session.get(url, allow_redirects=False)
        except:
            print("[!] Server not running")
            return
        
        if resp.status_code in [302, 307]:
            url = urljoin(BASE_URL, resp.headers.get('Location', ''))
            continue
        
        if resp.status_code == 200:
            html = resp.text
            dim += 1
            print(f"[*] Portal {dim}")
            
            # HTML comment: <!-- FLAG_PART: xxx -->
            m = re.search(r'<!-- FLAG_PART: ([^>]+) -->', html)
            if m:
                print(f"    [+] Comment: {m.group(1)}")
                flag_parts[dim] = m.group(1)
            
            # X-Flag header
            if 'X-Flag' in resp.headers:
                print(f"    [+] Header: {resp.headers['X-Flag']}")
                flag_parts[dim] = resp.headers['X-Flag']
            
            # Cookie
            if 'flag_part' in resp.cookies:
                print(f"    [+] Cookie: {resp.cookies['flag_part']}")
                flag_parts[dim] = resp.cookies['flag_part']
            
            # Hidden input: <input type="hidden" name="flag" value="xxx">
            m = re.search(r'<input[^>]*name="flag"[^>]*value="([^"]+)"', html)
            if m:
                print(f"    [+] Hidden: {m.group(1)}")
                flag_parts[dim] = m.group(1)
            
            # JS variable: var flagPart = "xxx";
            m = re.search(r'var flagPart = "([^"]+)"', html)
            if m:
                print(f"    [+] JS var: {m.group(1)}")
                flag_parts[dim] = m.group(1)
            
            # Title
            m = re.search(r'<title>([^<]+)</title>', html)
            if m and m.group(1) != '∞':
                print(f"    [+] Title: {m.group(1)}")
                flag_parts[dim] = m.group(1)
            
            if dim >= 16:
                break
            
            # Next URL
            m = re.search(r'window\.location\.(?:href = |replace\()"([^"]+)"', html)
            if m:
                url = urljoin(BASE_URL, m.group(1))
            else:
                break
    
    print()
    print("=" * 50)
    flag = ''.join(p for _, p in sorted(flag_parts.items()))
    print(f"🚩 FLAG: {flag}")
    print("=" * 50)

if __name__ == "__main__":
    solve()
