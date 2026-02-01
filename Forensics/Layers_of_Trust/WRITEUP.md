# Challenge Overview: Layers of Trust

**Category:** Forensics / Cryptography  
**Event:** L3m0nCTF 2025  
**Role:** Challenge Author

**Category:** Forensics / Crypto  

> 🛠️ **Author Note**  
> This challenge was authored by me for **L3m0nCTF 2025**.  
> The following explanation describes the **intended multi-layer analysis path**.

---

<img width="651" height="619" alt="image" src="https://github.com/user-attachments/assets/2171bf59-6f5c-4430-b78e-1d4c777d7179" />

## Intended Analysis Path

The challenge was designed to test:
- recognition of email containers as structured forensic artifacts
- inspection of MIME nesting rather than surface content
- correlation of metadata across unrelated formats
- cryptographic key derivation from contextual email data
- separation of decoy encryption from the true trust chain

Attempting to decrypt the PGP content directly without reconstructing
the trust layers was intentionally ineffective.

## Analysis Phase 1 — Establishing the Investigation Scope

The challenge explicitly mentions:

- **Raw email dump**
- **Structure**
- **Attachments**
- **Encrypted content**
- Multiple **layers**

This indicates the challenge is **not solved by reading the email body alone**.  
Instead, the solver must inspect the **email container itself**.

The investigation begins by treating the `.eml` file as a structured MIME container.

## Analysis Phase 2 — Email Container Inspection

`file mysterious_mail.eml`

Expected output confirms it is an RFC 822 email.

On inspecting the file you can conclude there is a

We observe:

- The email is multipart/mixed
- It contains:
  - A plain text body with hints
  - An embedded PNG image (logo.png)
  - A nested email (Content-Type: message/rfc822)
  - A PGP block (decoy)

This confirms that the email structure itself is important.

## Analysis Phase 3 — Nested Email Extraction

Scrolling through the file reveals a ``message/rfc822`` section.

This represents a **nested email**, which we extract into a separate file.

```
nano inner.eml
```

Inspect it:

```
less inner.eml
```

Key headers found:

```
From: "A L1ce" <alice314@example.com>
Subject: Confidential Notes
Date: Thu, 20 Nov 2025 13:00:00 +0530
```

The body of this email explicitly defines the cryptographic logic used to derive the decryption key.

## Analysis Phase 4 — Metadata-Based Key Material Discovery

The outer email embeds an image (``logo.png``) as base64.

We extract and decode it:

```
nano logo.b64
base64 -d logo.b64 > logo.png
```

Now inspect the metadata:

```
exiftool logo.png
```

<img width="821" height="610" alt="image" src="https://github.com/user-attachments/assets/2e7be724-172b-48f9-a702-9636de56f91d" />

Relevant fields:

```
Software          : argon2id
Artist            : time=3;mem=65536
Image Description : parallel=1
Copyright         : salt=7f3c8a21b4d9e012f3a5c9de7e12ab77
```

These values clearly correspond to **Argon2id parameters**.

## Analysis Phase 5 — Base Secret Reconstruction

From the inner email instructions, the base secret is defined as:

<img width="743" height="45" alt="image" src="https://github.com/user-attachments/assets/b1743688-8da9-4217-960c-68baa17996ff" />

Values used:
- **Outer From address** (from outer email):``admin@example.com``
- **Inner Subject** (lowercase, spaces removed):``confidentialnotes``
- **Inner Date** converted to UNIX timestamp (UTC):
```
python3 - << 'EOF'
import email.utils
from datetime import timezone

dt = email.utils.parsedate_to_datetime(
    "Thu, 20 Nov 2025 13:00:00 +0530"
)
print(int(dt.astimezone(timezone.utc).timestamp()))
EOF
```

This gives the UNIX timestamp.

Final base secret format:

```
admin@example.com|confidentialnotes|1763623800
```

## Analysis Phase 6 — Cryptographic Key Derivation

 Using the extracted Argon2 parameters and base secret:

 ```
from argon2.low_level import hash_secret_raw, Type
import hashlib, binascii

base_secret = "admin@example.com|confidentialnotes|<timestamp>"
salt = binascii.unhexlify("7f3c8a21b4d9e012f3a5c9de7e12ab77")

hardened = hash_secret_raw(
    secret=base_secret.encode(),
    salt=salt,
    time_cost=3,
    memory_cost=65536,
    parallelism=1,
    hash_len=32,
    type=Type.ID
)

passphrase = hashlib.sha256(hardened).hexdigest()[:16]
print(passphrase)
```

The result is the **correct PGP passphrase**.

## Final Output

From ``inner.eml``, extract the PGP block and save it.

Decrypt using GPG:

```
gpg --decrypt inner.asc > secret.png
```

When prompted, enter the derived passphrase.

This successfully produces:

``secret.png``

<img width="480" height="480" alt="image" src="https://github.com/user-attachments/assets/b206d527-341b-46c7-b663-dcb707cd4ca7" />

you can see the flag in the image.

**Flag**: ``L3M0NCTF{m41l_ch41n_pgp_4rg0n2_kdf_png_st3g0_m4st3ry}``
