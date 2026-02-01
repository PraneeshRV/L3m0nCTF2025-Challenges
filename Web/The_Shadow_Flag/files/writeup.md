
# Arbitrage CTF Challenge – Writeup

## Challenge Overview

**Objective:** Purchase **The Shadow Flag**
**Item Cost:** $1,000
**Starting Balance:** $100 (fixed)

![Shop Page](https://github.com/user-attachments/assets/eea0cc31-80f1-4823-8bd4-b498748001df)

The web application implements a coupon-based discount system that provides **$100 off per coupon**, with the intention that **only one coupon can be applied per cart**.
The goal of this challenge is to identify weaknesses in the application logic and exploit them to reduce the cart total to `$0`, allowing the purchase of the flag.

---

## Reconnaissance & Initial Observations

On the shop page, *The Shadow Flag* is listed for **$1000**, which is far above the available balance.

![Shadow Flag Item](https://github.com/user-attachments/assets/5f5c8f2a-bdc6-498f-a63b-5c53708fecbe)

At checkout, an **Apply Coupon** option is present, but no coupon code is provided to the user.
A hint in the challenge suggests that the coupon exists at the path `/coupon`.

Directly visiting `/coupon` results in an error stating that the file cannot be found.

![Coupon Error](https://github.com/user-attachments/assets/53876626-c04a-4294-afea-7fb4fc32a895)

This indicates that the coupon exists on the server but is not directly accessible.

---

## Vulnerability Analysis

### 1. Path Traversal – Information Disclosure

After authentication, the footer contains a link to a document labeled **Corporate Policy**.

**Endpoint:**

```
/doc_viewer?doc=corporate_policy.txt
```

![Document Viewer](https://github.com/user-attachments/assets/e20349d7-1f52-45a7-85ac-841c6c703bff)

The application attempts to prevent directory traversal using a simple string replacement:

```
filename.replace("../", "")
```

This approach is flawed because it is **not recursive** and does not account for alternative traversal patterns.

#### Exploitation

By using the payload `....//`, the sanitization can be bypassed:

```
/doc_viewer?doc=....//coupon
```

After filesystem normalization, this resolves to `../coupon`, allowing access to the restricted file.

#### Result

The hidden coupon file is successfully disclosed:

```
LEGACY PROMO CODE DETECTED
------------------------
Use this code at checkout for a discount:
Code: SHADOW_DISCOUNT
Value: $100.00 OFF
```

![Coupon File](https://github.com/user-attachments/assets/739e2584-8758-4ee4-bb82-f44198309218)
![Coupon Content](https://github.com/user-attachments/assets/afbcc97f-2e5f-46ff-8019-9944a20c9313)

At this stage, the coupon code is known, but applying it once is insufficient to purchase the flag.

---

### 2. Race Condition – Coupon Stacking

With the coupon code obtained, attention shifts to the coupon application logic.

**Endpoint:**

```
POST /cart/apply_coupon
```

The application stores cart state in a **global in-memory object**.
The coupon application logic follows this sequence:

1. Check if a coupon has already been applied
2. Introduce a **500ms delay**
3. Apply the discount and increment the coupon counter

Because the **check and update are not atomic**, multiple concurrent requests can bypass the single-coupon restriction.

![Burp Intercept](https://github.com/user-attachments/assets/7080aed9-c17a-4d11-a98c-9b710fd21d3e)
![Race Condition Logic](https://github.com/user-attachments/assets/720f4da5-50f6-4a60-a5a2-683a1b3a3f32)

---

## Exploitation Strategy

1. Add **The Shadow Flag** ($1000) to the cart.
2. Navigate to `/checkout`.
3. Intercept the `POST /cart/apply_coupon` request using **Burp Suite**.
4. Send the request to **Repeater**.
5. Use **Send group in parallel (last-byte sync)** to ensure all requests reach the server simultaneously.
6. Send approximately **15 parallel requests** using the coupon code `SHADOW_DISCOUNT`.
7. Due to the race condition, the coupon is applied multiple times before the counter is updated.
8. Refresh the checkout page to observe the cart total reduced to `$0`.
9. Confirm the purchase.

![Successful Purchase](https://github.com/user-attachments/assets/9421a01f-572e-4b4b-b0b3-dffff53c4446)

---

## Root Cause Analysis

* **Improper path sanitization** enabled arbitrary file disclosure.
* **Non-atomic coupon logic** introduced a race condition.
* **Global in-memory cart state** allowed concurrent manipulation.
* The application trusted request timing instead of enforcing transactional integrity.

This vulnerability chain closely resembles real-world promotional abuse and e-commerce logic flaws.

---



