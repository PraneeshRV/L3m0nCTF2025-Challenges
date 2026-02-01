# Challenge Writeup: NeonVault (l3mon_web2)

## Challenge Description
**Title:** NeonVault
**Category:** Web / Cryptography
**Objective:** Gain access to the `/admin` panel to retrieve the flag.
<img width="577" height="563" alt="image" src="https://github.com/user-attachments/assets/da424529-3f7e-41b8-bd89-3b0f7491e04f" />
login in with the given credentials


## Reconnaissance

1.  **Initial Access**: The application provides a login page. We are given credentials `thala:thala@123`. Logging in redirects us to `/account`.
2.  **Token Analysis**: Upon login, a `session` cookie is set. Inspecting this cookie reveals it is a JWT (JSON Web Token).
   <img width="583" height="667" alt="image" src="https://github.com/user-attachments/assets/873bbad6-184c-4757-b39f-8c596f489c7e" />

Upon analyzing it in jwt.io
<img width="1528" height="767" alt="image" src="https://github.com/user-attachments/assets/c5412ea5-1a22-4aa9-a5e3-06e87ef7d2f3" />

    *   Header: `{"alg": "RS256", "kid": "neon_root_key", ...}`
    *   Payload: `{"sub": "thala", ...}`
4.  **Discovery**:
    <img width="950" height="635" alt="image" src="https://github.com/user-attachments/assets/3d1dcb7c-2897-4f27-a9bf-006e4cffd837" />

    *   There is a `/.well-known/jwks.json` endpoint.
    *   Accessing `/.well-known/jwks.json` returns a JSON response containing a `verification_cert` instead of just standard keys.
  
    * Analyzing the certificate using openssl gave us
    * <img width="1632" height="1029" alt="image" src="https://github.com/user-attachments/assets/d68ae7b3-412a-4932-b317-ea1605a68483" />


## Vulnerability Analysis

The application suffers from a **JWT Key Confusion (Algorithm Confusion)** vulnerability.

1.  **The Flaw**: The server supports both `RS256` (RSA Signature) and `HS256` (HMAC) algorithms.
    *   When `RS256` is used, it verifies the signature using the RSA Public Key.
    *   When `HS256` is used, the server *incorrectly* uses the **RSA Public Key string** as the **HMAC secret key**.
2.  **The Constraint**: The server enforces that the `kid` (Key ID) header must match a specific value. i.e is the same value as decoded 


## Exploitation Steps

### Step 1: Obtain the Public Key and KID
The `/.well-known/jwks.json` endpoint gives us a PEM-encoded certificate. We need to:
  **Extract the Public Key**: The server uses the public key from this certificate for verification.
  <img width="983" height="354" alt="image" src="https://github.com/user-attachments/assets/f7f3d956-2dca-4ab6-a9b5-d674feb2464d" />


### Step 2: Forge the Admin Token
We can now forge a valid JWT for the `administrator` user.

1.  **Header**:
    *   `alg`: `HS256` (Force the server to use HMAC)
    *   `kid`: `neon_root_key` 
2.  **Payload**:
    *   `sub`: `administrator`
    *   `iss`: `DecoyKeyCTF`
3.  **Signature**:
    *   Create the signature using `HMAC-SHA256`.
    *   **Secret Key**: The PEM-encoded Public Key string (extracted from the cert).
      I wrote a python code for doing this

<img width="958" height="920" alt="image" src="https://github.com/user-attachments/assets/8f2d0e1c-2683-4c84-90f9-0a50843c0f13" />


### Step 3: Retrieve the Flag
Send the forged token in the `session` cookie to the `/admin` endpoint. The server will verify the HMAC signature using its public key (which it thinks is the secret), accept the token, and grant access to the admin panel.
<img width="845" height="740" alt="image" src="https://github.com/user-attachments/assets/309a0e0e-acf8-4097-bf12-4034edd5185a" />
<img width="806" height="708" alt="image" src="https://github.com/user-attachments/assets/efcf71f3-2f6b-4ec3-a47a-9bc8e2335f5c" />


**Flag:** `L3m0nctf{K3y_C0nfus10n_M4st3r_8821}`

