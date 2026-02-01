import jwt
import json
from flask import (
    Flask,
    request,
    make_response,
    redirect,
    render_template,
    jsonify,
    g,
    url_for,
)
from functools import wraps
import sys
import os

# --- Challenge Setup ---
app = Flask(__name__)
app.config["SECRET_KEY"] = "this_is_not_the_jwt_secret"

def get_flag():
    if "FLAG" in os.environ:
        return os.environ["FLAG"]
    try:
        with open("/flag.txt", "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        pass
    return "L3m0nctf{K3y_C0nfus10n_M4st3r_8821}"

FLAG = get_flag()

# --- NEW: Load Keys From Files ---
# This reads the keys you just generated with openssl
try:
    with open('private.pem', 'r') as f:
        REAL_PRIVATE_KEY = f.read()

    with open('public.pem', 'r') as f:
        REAL_PUBLIC_KEY = f.read()
        
    with open('cert.pem', 'r') as f:
        REAL_CERT = f.read()
except FileNotFoundError as e:
    print("="*50, file=sys.stderr)
    print(f"ERROR: {e.filename} not found.", file=sys.stderr)
    print("Please generate the keys by running:", file=sys.stderr)
    print("  openssl genrsa -out private.pem 2048", file=sys.stderr)
    print("  openssl rsa -in private.pem -pubout -out public.pem", file=sys.stderr)
    print("  openssl req -new -x509 -key private.pem -out cert.pem -days 365 -subj '/C=US/ST=NeonState/L=NeonCity/O=NeonVault/OU=neon_root_key/CN=auth.neonvault.local'", file=sys.stderr)
    print("="*50, file=sys.stderr)
    sys.exit(1)
# --- End of New Key Loading ---


# This is the DECOY key. It's what's shown to the user.
# It's a valid JWK, but it's not the one used for verification.
DECOY_PUBLIC_KEY_JWK = {
    "keys": [
        {
            "kty": "RSA",
            "e": "AQAB",
            "use": "sig",
            "kid": "key-id-98763",
            "alg": "RS256",
            "n": "vFLmRoFBwhB3A5SsrTjD-fTuQy53bTna-CPy2-NVM-pNH-tZ0-wA32-9Wii6S0cRdT-ZShD4PUoAhb2y5vNYP8Gz-BWWW-zLhC1iR-Ets-Jb9aW-Hk5VUy-VxF-JvD-t-t-qY-t-t-qY-t-t-qY-t-t-qY-t-t-qY-t-t-qY-t-t-qY-t-t-qY-t-t-qY-t-t-qY-t-t-qY-t-t-qY-t-t-qY-t-t-qY-t-t-qY-t-t-qY-t-t-qY-t-t-qY-t-t-qY-t-t-qY-t-t-qY",
        },
        {
            "kty": "RSA",
            "e": "AQAB",
            "use": "sig",
            "kid": "key-id-98768",
            "alg": "RS256",
            "n": "vFLmRoFBwhB3A5SsrTjD-fTuQy53bTna-CPy2-NVM-pNH-tZ0-wA32-9Wii6S0cRdT-ZShD4PUoAhb2y5vNYP8Gz-BWWW-zLhC1iR-Ets-Jb9aW-Hk5VUy-VxF-JvD-t-t-qY-t-t-qY-t-t-qY-t-t-qY-t-t-qY-t-t-qY-t-t-qY-t-t-qY-t-t-qY-t-t-qY-t-t-qY-t-t-qY-t-t-qY-t-t-qY-t-t-qY-t-t-qY-t-t-qY-t-t-qY-t-t-qY-t-t-qY-t-t-qY",
        },
        {
            "kty": "RSA",
            "e": "AQAB",
            "use": "sig",
            "kid": "key-id-98760",
            "alg": "RS256",
            "n": "vFLmRoFBwhB3A5SsrTjD-fTuQy53bTna-CPy2-NVM-pNH-tZ0-wA32-9Wii6S0cRdT-ZShD4PUoAhb2y5vNYP8Gz-BWWW-zLhC1iR-Ets-Jb9aW-Hk5VUy-VxF-JvD-t-t-qY-t-t-qY-t-t-qY-t-t-qY-t-t-qY-t-t-qY-t-t-qY-t-t-qY-t-t-qY-t-t-qY-t-t-qY-t-t-qY-t-t-qY-t-t-qY-t-t-qY-t-t-qY-t-t-qY-t-t-qY-t-t-qY-t-t-qY-t-t-qY",
        }
    ]
}

# --- The Vulnerable Token Check ---
# This decorator checks the JWT
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get("session")
        if not token:
            return redirect(url_for("login_page"))
        
        try:
            # 1. Get header to read 'alg' WITHOUT verification
            header = jwt.get_unverified_header(token)
            alg = header.get("alg")
            kid = header.get("kid")
            
            # TWIST 2: Enforce Key ID
            if kid != "neon_root_key":
                return "Invalid Key ID. Access Denied.", 401

            if alg == "RS256":
                # 2. If RS256, verify normally using the REAL public key
                decoded_token = jwt.decode(
                    token, REAL_PUBLIC_KEY, algorithms=["RS256"]
                )
            elif alg == "HS256":
                # 3. VULNERABILITY: If HS256, "verify" using the REAL public key as the secret
                # We must do this manually because modern pyjwt refuses to use PEM as HMAC secret.
                
                # Split token
                parts = token.split('.')
                if len(parts) != 3:
                    raise jwt.InvalidTokenError("Invalid token format")
                
                signing_input = f"{parts[0]}.{parts[1]}"
                signature = parts[2]
                
                # Calculate HMAC using the public key as secret
                import hmac
                import hashlib
                import base64
                
                # Helper for base64url decode
                def base64url_decode(input):
                    rem = len(input) % 4
                    if rem > 0:
                        input += '=' * (4 - rem)
                    return base64.urlsafe_b64decode(input)

                # Verify signature
                expected_sig = hmac.new(
                    REAL_PUBLIC_KEY.encode('utf-8'),
                    signing_input.encode('utf-8'),
                    hashlib.sha256
                ).digest()
                
                # Compare signatures (safe compare)
                # We need to decode the provided signature from base64url to bytes
                try:
                    provided_sig_bytes = base64url_decode(signature)
                except:
                    raise jwt.InvalidTokenError("Invalid signature encoding")

                if not hmac.compare_digest(expected_sig, provided_sig_bytes):
                     raise jwt.InvalidTokenError("Signature verification failed")
                
                # If signature matches, decode payload without verification (we already verified)
                decoded_token = jwt.decode(token, options={"verify_signature": False})
                
            else:
                raise jwt.exceptions.InvalidAlgorithmError("Unsupported algorithm")

            # Store user info for the request
            g.user = decoded_token
        except jwt.ExpiredSignatureError:
            return "Token expired. Please log in again.", 401
        except jwt.InvalidTokenError as e:
            return f"Invalid token: {e}", 401
        except Exception as e:
             print(f"Error: {e}")
             return "Internal Error", 500

        return f(*args, **kwargs)

    return decorated


# --- Web Routes ---
@app.route("/")
def login_page():
    return render_template("index.html")


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    if username == "thala" and password == "thala@123":
        # Sign a standard token with the REAL private key
        # We must include the correct KID now
        token = jwt.encode(
            {"sub": "thala", "iss": "DecoyKeyCTF"},
            REAL_PRIVATE_KEY,
            algorithm="RS256",
            headers={"kid": "neon_root_key"}
        )
        resp = make_response(redirect(url_for("account_page")))
        resp.set_cookie("session", token, httponly=True)
        return resp
    else:
        return "Invalid credentials", 401


@app.route("/account")
@token_required
def account_page():
    # g.user is populated by the @token_required decorator
    username = g.user.get("sub")
    return render_template("account.html", username=username)


# --- API / Key Endpoints ---

@app.route("/.well-known/jwks.json")
def jwks():
    # This is the REAL key discovery point now.
    # We return the certificate so players can extract the public key and the hidden KID.
    return jsonify({
        "keys": [], # Standard field, empty to confuse automated scanners looking for JWKs
        "verification_cert": REAL_CERT, # The critical piece of info
        "note": "Legacy certificate chain provided for verification."
    })

@app.route("/admin")
@token_required
def admin_panel():
    if g.user.get("sub") != "administrator":
        return "Access denied. Admins only.", 403
    return render_template("admin.html", flag=FLAG)


if __name__ == "__main__":
    print("Challenge server running on http://0.0.0.0:5001")
    print("Test account: thala:thala@123")
    app.run(host="0.0.0.0", debug=False, port=int(os.environ.get("PORT", 5001)))