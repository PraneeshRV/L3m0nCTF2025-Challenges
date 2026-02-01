from flask import Flask, request, render_template, redirect, url_for, make_response, send_file, session, render_template_string
import os

app = Flask(__name__)
app.secret_key = 'super_secret_key_for_session_management'

app.config['SESSION_COOKIE_HTTPONLY'] = False # Vulnerable configuration for CTF

# Mock database for comments
comments = []

# Admin credentials (hardcoded for this challenge)
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'password123'
ADMIN_TOKEN_VALUE = os.environ.get('ADMIN_TOKEN', 'super_secret_admin_token_l3m0n_42')



# In-memory user storage
USERS = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        # In a real app, we would send an email here.
        # For this demo, we'll just show a success message.
        return render_template('contact.html', success=True)
    return render_template('contact.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username in USERS:
            return render_template('signup.html', error='Username already exists')
        
        USERS[username] = password
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/guestbook', methods=['GET', 'POST'])
def guestbook():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        comment = request.form.get('comment')
        if comment:
            # VULNERABILITY: Stored XSS - No sanitization
            comments.append(comment)
            
            # Trigger the bot to visit
            try:
                with open('/tmp/bot_trigger', 'w') as f:
                    f.write('trigger')
            except Exception as e:
                print(f"Error creating bot trigger: {e}")
                
            return redirect(url_for('guestbook'))
    return render_template('guestbook.html', comments=comments)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Check regular user credentials
        if username in USERS and USERS[username] == password:
            session['username'] = username
            return redirect(url_for('index'))
            
        return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Check admin credentials
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['username'] = ADMIN_USERNAME
            session['is_admin'] = True
            resp = make_response(redirect(url_for('admin')))
            # Set a specific admin token cookie that needs to be stolen
            resp.set_cookie('admin_token', ADMIN_TOKEN_VALUE, httponly=False)
            return resp
            
        return render_template('admin_login.html', error='Invalid admin credentials')
    return render_template('admin_login.html')

@app.route('/admin')
def admin():
    # Check for BOTH the session and the specific admin token
    token = request.cookies.get('admin_token')
    if session.get('username') == ADMIN_USERNAME and session.get('is_admin') and token == ADMIN_TOKEN_VALUE:
        return render_template('admin.html')
    else:
        return redirect(url_for('admin_login'))

@app.route('/admin_area/template_editor.php')
def template_editor():
    # Simulate PHP endpoint behavior in Flask
    # This endpoint specifically requires BOTH the admin_token and the session
    token = request.cookies.get('admin_token')
    if session.get('username') != ADMIN_USERNAME or not session.get('is_admin') or token != ADMIN_TOKEN_VALUE:
        return "Access Denied", 403

    search_query = request.args.get('search')
    
    if search_query:
        # VULNERABILITY: Server-Side Template Injection (SSTI)
        # We are rendering the user input directly into the template string
        # This allows an attacker to execute arbitrary code on the server
        
        # Obfuscation: Blacklist filter
        blacklist = ['__', 'class', 'mro', 'subclasses', 'config', 'self', 'import', 'eval', 'popen', 'system']
        for bad_word in blacklist:
            if bad_word in search_query:
                return "Malicious Input Detected", 403

        template = f"""
        {{% extends "under_construction.html" %}}
        {{% block content %}}
        <div class="container" style="max-width: 800px; margin: 40px auto; text-align: center;">
            <div style="font-size: 4rem; margin-bottom: 20px;">🚧</div>
            <h1 style="margin-bottom: 20px;">Template Editor Under Construction</h1>
            <p class="text-muted" style="margin-bottom: 40px;">
                We are currently upgrading the template editor to provide a better experience.
                In the meantime, you can search for existing templates below.
            </p>

            <div class="search-container" style="max-width: 500px; margin: 0 auto;">
                <form action="/admin_area/template_editor.php" method="GET">
                    <div class="form-group">
                        <input type="text" name="search" placeholder="Search templates..." class="form-control" 
                            style="width: 100%; padding: 12px; border-radius: 8px; border: 1px solid var(--border-color); background: var(--card-bg); color: var(--text-color);">
                    </div>
                    <button type="submit" class="btn btn-primary" style="margin-top: 10px; width: 100%;">Search</button>
                </form>
            </div>

            <div class="search-results" style="margin-top: 40px; text-align: left;">
                <h3>Search Results for: {search_query}</h3>
                <p class="text-muted">No templates found matching your query.</p>
            </div>
        </div>
        {{% endblock %}}
        """
        return render_template_string(template)

    return render_template('under_construction.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5005)), debug=False, threaded=True)
