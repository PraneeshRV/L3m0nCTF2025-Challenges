import os
import base64
import jwt
import datetime
import subprocess
from flask import Flask, render_template, request, redirect, url_for, make_response, jsonify

app = Flask(__name__)

# Configuration
# Weak secret for rockyou.txt cracking. 'maspinakacuteako' is around 40% of rockyou.txt
app.config['SECRET_KEY'] = 'maspinakacuteako' 
ADMIN_USER = 'admin'
# Password: 'agent45_access_granted' -> base64: YWdlbnQ0NV9hY2Nlc3NfZ3JhbnRlZA==
NORMAL_USER_PASS = 'agent45_access_granted' 

def create_token(username, role='user'):
    payload = {
        'username': username,
        'role': role,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def verify_token(token):
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    if username == 'agent45' and password == NORMAL_USER_PASS:
        token = create_token(username, role='user')
        resp = make_response(redirect(url_for('dashboard')))
        resp.set_cookie('auth_token', token)
        return resp
    elif username == ADMIN_USER and password == 'admin_password_super_secure_123': # Unlikely to guess
        token = create_token(username, role='admin')
        resp = make_response(redirect(url_for('admin_panel')))
        resp.set_cookie('auth_token', token)
        return resp
    else:
        return render_template('index.html', error='Invalid credentials')

@app.route('/dashboard')
def dashboard():
    token = request.cookies.get('auth_token')
    if not token:
        return redirect(url_for('index'))
    
    payload = verify_token(token)
    if not payload:
        return redirect(url_for('index'))

    return render_template('dashboard.html', username=payload['username'], role=payload['role'])

@app.route('/admin')
def admin_panel():
    token = request.cookies.get('auth_token')
    if not token:
        return redirect(url_for('index'))
    
    payload = verify_token(token)
    if not payload or payload.get('role') != 'admin':
        return render_template('dashboard.html', username=payload['username'], role=payload['role'], error="Admin access required. Features disabled.")

    return render_template('admin.html', username=payload['username'])

@app.route('/admin/upload', methods=['POST'])
def upload_file():
    token = request.cookies.get('auth_token')
    if not token:
        return jsonify({'error': 'Unauthorized'}), 401
    
    payload = verify_token(token)
    if not payload or payload.get('role') != 'admin':
        return jsonify({'error': 'Forbidden'}), 403

    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if file:
        # Save and execute the file
        filepath = os.path.join('/tmp', file.filename)
        file.save(filepath)
        
        try:
            # Execute the uploaded script
            # If it's a python script, run it. If shell, run it.
            # For this challenge, we assume they upload a python script for the C2 polling
            if filepath.endswith('.py'):
                # We run it in the background or just run it?
                # The user wants "The server keeps polling...". 
                # So we should spawn it.
                subprocess.Popen(['python3', filepath])
                return jsonify({'message': 'Plugin uploaded and executed successfully. Monitoring started.'})
            else:
                 # Fallback execution
                subprocess.Popen(['chmod', '+x', filepath])
                subprocess.Popen([filepath])
                return jsonify({'message': 'File uploaded and executed.'})

        except Exception as e:
            return jsonify({'error': str(e)}), 500

    return jsonify({'error': 'Upload failed'}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
