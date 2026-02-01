from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, jsonify
import os

app = Flask(__name__)
app.secret_key = 'super_secret_key_for_ctf_challenge'

# Mock Database
users = {
    "attacker": {"password": "123", "otp": "1234"},
    "super_admin_2025": {"password": "complex_password_you_wont_guess", "otp": "9999"}
}

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/robots.txt')
def robots():
    return "User-agent: super_admin_2025\notp is 1234"

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username in users:
            return render_template('signup.html', error="User already exists")
        
        # In a real app, we'd hash passwords. For CTF, plain text is fine.
        users[username] = {"password": password, "otp": "1234"} # Default OTP for new users
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username in users and users[username]['password'] == password:
            session['pre_auth_user'] = username
            return redirect(url_for('otp_page'))
        else:
            return render_template('login.html', error="Invalid credentials")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/otp', methods=['GET'])
def otp_page():
    if 'pre_auth_user' not in session:
        return redirect(url_for('login'))
    return render_template('otp.html')

@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    if 'pre_auth_user' not in session:
        return jsonify({"status": "error", "message": "Session expired"}), 401

    data = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "Invalid request"}), 400

    otp_input = data.get('otp')
    # Vulnerability: The server trusts the 'username' from the JSON body 
    # for the final session creation, but validates OTP against the session user.
    target_username = data.get('username') 
    
    current_user = session['pre_auth_user']
    
    # 1. Verify OTP against the currently logged-in (pre-auth) user
    if users[current_user]['otp'] == otp_input:
        # 2. Issue session for the requested target_username (The Switcheroo)
        session['user'] = target_username
        session.pop('pre_auth_user', None)
        return jsonify({"status": "success", "redirect": url_for('dashboard')})
    else:
        return jsonify({"status": "error", "message": "Invalid OTP"}), 403

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    user = session['user']
    # Only super_admin_2025 can see the real dashboard
    if user != 'super_admin_2025':
        return render_template('dashboard.html', user=user, admin=False)
    
    return render_template('dashboard.html', user=user, admin=True)

@app.route('/data/<path:filename>')
def download_data(filename):
    if 'user' not in session or session['user'] != 'super_admin_2025':
        return "Unauthorized", 403
    return send_from_directory('data', filename)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=6002, debug=True)
