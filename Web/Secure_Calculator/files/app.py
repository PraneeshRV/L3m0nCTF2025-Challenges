from flask import Flask, request, render_template_string
import subprocess
import re

app = Flask(__name__)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Secure Calculator</title>
    <style>
        body {
            background-color: #0d0208;
            color: #00ff41;
            font-family: 'Courier New', Courier, monospace;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            overflow: hidden;
        }
        .container {
            background: rgba(13, 2, 8, 0.9);
            border: 2px solid #00ff41;
            box-shadow: 0 0 20px #00ff41;
            padding: 40px;
            width: 500px;
            text-align: center;
            position: relative;
        }
        .container::before {
            content: "SYSTEM SECURE";
            position: absolute;
            top: -12px;
            left: 20px;
            background: #0d0208;
            padding: 0 10px;
            font-weight: bold;
            color: #00ff41;
        }
        h1 {
            text-transform: uppercase;
            letter-spacing: 4px;
            margin-bottom: 30px;
            text-shadow: 2px 2px #ff00ff;
        }
        input {
            background: transparent;
            border: none;
            border-bottom: 2px solid #00ff41;
            color: #00ff41;
            font-family: inherit;
            font-size: 1.2em;
            width: 100%;
            padding: 10px;
            margin-bottom: 20px;
            outline: none;
        }
        input::placeholder {
            color: #008f11;
        }
        button {
            background: #00ff41;
            color: #0d0208;
            border: none;
            padding: 10px 30px;
            font-weight: bold;
            font-size: 1.1em;
            cursor: pointer;
            transition: all 0.3s;
            text-transform: uppercase;
        }
        button:hover {
            background: #ff00ff;
            color: #fff;
            box-shadow: 0 0 15px #ff00ff;
        }
        .result {
            margin-top: 30px;
            border: 1px dashed #00ff41;
            padding: 15px;
            text-align: left;
            min-height: 50px;
            white-space: pre-wrap;
            word-break: break-all;
        }
        .error {
            color: #ff0055;
            border-color: #ff0055;
        }
        .scan-line {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 5px;
            background: rgba(0, 255, 65, 0.1);
            animation: scan 3s linear infinite;
            pointer-events: none;
        }
        @keyframes scan {
            0% { top: 0%; }
            100% { top: 100%; }
        }
    </style>
</head>
<body>
    <div class="scan-line"></div>
    <div class="container">
        <h1>Calc.exe</h1>
        <form method="GET">
            <input type="text" name="expression" placeholder="ENTER EXPRESSION..." autocomplete="off">
            <button type="submit">EXECUTE</button>
        </form>
        
        {% if output %}
        <div class="result {% if error %}error{% endif %}">
            {{ output }}
        </div>
        {% endif %}
    </div>
</body>
</html>
"""

@app.route('/')
def home():
    expression = request.args.get('expression')
    output = ""
    error = False
    
    if expression:
        # LEVEL 4 SECURITY FILTER (Same blacklist, but stdout is hidden)
        blacklist = [" ", "cat", "flag"]
        
        if any(bad in expression for bad in blacklist):
            output = "🚫 ILLEGAL INPUT DETECTED. INCIDENT REPORTED."
            error = True
        else:
            try:
                # Error-Based execution
                cmd = f"echo {expression} | bc"
                # We run the command, capture stderr, but ignore stdout
                process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr = process.communicate()
                
                if stderr:
                    # We show stderr! This is the key.
                    output = stderr.decode('utf-8')
                else:
                    # If no stderr, we show a generic message because stdout is hidden
                    output = "✅ CALCULATION PROCESSED. RESULT STORED IN SECURE MEMORY."
            except Exception as e:
                output = f"❌ SYSTEM ERROR: {str(e)}"
                error = True

    return render_template_string(HTML_TEMPLATE, output=output, error=error)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)