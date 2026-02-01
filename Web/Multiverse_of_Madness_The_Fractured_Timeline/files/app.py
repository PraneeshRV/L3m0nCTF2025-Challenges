"""
Redirect Hell: Multiverse of Madness - Easy Edition
Plain text flag parts in simple locations
"""

import os
import hashlib
import time
from flask import Flask, redirect, make_response, url_for, render_template_string, session

app = Flask(__name__, static_folder='static')
app.secret_key = 'multiverse_of_madness_sorcerer_supreme_2024_xyz'

# Dynamic flag from environment variable
DEFAULT_FLAG = "L3m0nCTF{d1m3ns10n_h0pp1ng_w1th_th3_s0rc3r3r_supr3m3}"
FLAG = os.environ.get('FLAG', DEFAULT_FLAG)

def split_flag(flag):
    """Split flag into 6 parts for distribution across dimensions"""
    # Ensure flag has proper format
    if not flag.startswith('L3m0nCTF{') or not flag.endswith('}'):
        flag = DEFAULT_FLAG
    
    inner = flag[9:-1]  # Extract content between L3m0nCTF{ and }
    parts_count = 5  # Number of inner parts
    chunk_size = len(inner) // parts_count
    
    result = ["L3m0nCTF{"]
    for i in range(parts_count - 1):
        result.append(inner[i * chunk_size:(i + 1) * chunk_size])
    result.append(inner[(parts_count - 1) * chunk_size:] + "}")
    
    return result

FLAG_PARTS = split_flag(FLAG)

def generate_token(dim, session_id):
    data = f"{session_id}:dim{dim}:multiverse"
    return hashlib.sha256(data.encode()).hexdigest()[:16]

def get_session_id():
    if 'sid' not in session:
        session['sid'] = hashlib.sha256(str(time.time()).encode()).hexdigest()[:12]
    return session['sid']

# Simple flag locations - no encryption
DIMENSIONS = {
    1:  {},
    2:  {"flag_part": 0, "flag_type": "comment"},
    3:  {},
    4:  {},
    5:  {"flag_part": 1, "flag_type": "header"},
    6:  {},
    7:  {},
    8:  {"flag_part": 2, "flag_type": "title"},
    9:  {},
    10: {},
    11: {"flag_part": 3, "flag_type": "hidden_input"},
    12: {},
    13: {"flag_part": 4, "flag_type": "js_var"},
    14: {"flag_part": 5, "flag_type": "cookie"},
    15: {},
    16: {}
}

TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ page_title }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        html, body { width: 100%; height: 100%; overflow: hidden; background: #000; }
        
        .dimension-bg {
            position: fixed;
            inset: 0;
            background-image: url('/static/images/dim_{{ img_num }}.png');
            background-size: contain;
            background-position: center;
            background-repeat: no-repeat;
            background-color: #000;
            animation: fadeIn 0.3s ease-out;
        }
        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
        
        .vignette {
            position: fixed;
            inset: 0;
            background: radial-gradient(ellipse at center, transparent 50%, rgba(0,0,0,0.4) 100%);
            pointer-events: none;
            z-index: 10;
        }
        
        .shatter-overlay {
            position: fixed;
            inset: 0;
            z-index: 1000;
            pointer-events: none;
            animation: overlayFade 1s ease-out forwards;
        }
        @keyframes overlayFade { 0%,50% { opacity: 1; } 100% { opacity: 0; } }
        
        .impact-flash {
            position: fixed;
            inset: 0;
            background: radial-gradient(circle at center, rgba(255,255,255,0.9), transparent 60%);
            animation: flashBurst 0.2s ease-out forwards;
        }
        @keyframes flashBurst { 0% { opacity: 1; } 100% { opacity: 0; } }
        
        .shard {
            position: absolute;
            background: linear-gradient(135deg, rgba(255,255,255,0.3), rgba(200,220,255,0.1));
            border: 1px solid rgba(255,255,255,0.3);
            animation: shardExplode 0.8s ease-out forwards;
        }
        @keyframes shardExplode {
            0% { transform: translate(0, 0) rotate(0deg); opacity: 1; }
            100% { transform: translate(var(--tx), var(--ty)) rotate(var(--rot)); opacity: 0; }
        }
        
        .shockwave {
            position: fixed;
            top: 50%; left: 50%;
            border: 2px solid rgba(255,255,255,0.6);
            border-radius: 50%;
            transform: translate(-50%, -50%);
            animation: waveExpand 0.5s ease-out forwards;
        }
        @keyframes waveExpand { 0% { width: 0; height: 0; opacity: 1; } 100% { width: 150vmax; height: 150vmax; opacity: 0; } }
    </style>
</head>
<body>
    <div class="dimension-bg"></div>
    <div class="vignette"></div>
    
    <div class="shatter-overlay">
        <div class="impact-flash"></div>
        <div class="shockwave"></div>
        <div id="shardContainer"></div>
    </div>
    
    {{ html_comment|safe }}
    {{ hidden_input|safe }}
    
    <script>
    (function() {
        const c = document.getElementById('shardContainer');
        const cx = window.innerWidth / 2, cy = window.innerHeight / 2;
        for (let i = 0; i < 30; i++) {
            const s = document.createElement('div');
            s.className = 'shard';
            const sz = 20 + Math.random() * 50;
            s.style.width = sz + 'px'; s.style.height = sz + 'px';
            s.style.clipPath = 'polygon(50% 0%, 0% 100%, 100% 100%)';
            const ang = (i / 30) * Math.PI * 2;
            s.style.left = (cx + Math.cos(ang) * 40 - sz/2) + 'px';
            s.style.top = (cy + Math.sin(ang) * 40 - sz/2) + 'px';
            s.style.setProperty('--tx', Math.cos(ang) * 200 + 'px');
            s.style.setProperty('--ty', (Math.sin(ang) * 200 + 80) + 'px');
            s.style.setProperty('--rot', Math.random() * 360 + 'deg');
            c.appendChild(s);
        }
    })();
    
    {{ js_var|safe }}
    {{ js_redirect|safe }}
    </script>
</body>
</html>
'''

@app.route('/')
def index():
    sid = get_session_id()
    session['current_dim'] = 1
    token = generate_token(1, sid)
    return redirect(f'/portal/{token}')

@app.route('/portal/<token>')
def portal(token):
    sid = get_session_id()
    current_dim = session.get('current_dim', 1)
    
    if token != generate_token(current_dim, sid):
        session['current_dim'] = 1
        return redirect('/')
    
    config = DIMENSIONS[current_dim]
    next_dim = current_dim + 1 if current_dim < 16 else 16
    next_url = f'/portal/{generate_token(next_dim, sid)}'
    
    if current_dim < 16:
        session['current_dim'] = next_dim
    
    template_vars = {
        'img_num': current_dim,
        'page_title': '∞',
        'html_comment': '',
        'hidden_input': '',
        'js_var': '',
        'js_redirect': f'setTimeout(function(){{ window.location.replace("{next_url}"); }}, 1000);' if current_dim < 16 else ''
    }
    
    # Simple plain text flag locations
    if 'flag_part' in config:
        fval = FLAG_PARTS[config['flag_part']]
        ftype = config['flag_type']
        
        if ftype == 'comment':
            template_vars['html_comment'] = f'<!-- FLAG_PART: {fval} -->'
        elif ftype == 'hidden_input':
            template_vars['hidden_input'] = f'<input type="hidden" name="flag" value="{fval}">'
        elif ftype == 'js_var':
            template_vars['js_var'] = f'var flagPart = "{fval}";'
        elif ftype == 'title':
            template_vars['page_title'] = fval
    
    html = render_template_string(TEMPLATE, **template_vars)
    resp = make_response(html)
    
    if 'flag_part' in config:
        fval = FLAG_PARTS[config['flag_part']]
        ftype = config['flag_type']
        if ftype == 'header':
            resp.headers['X-Flag'] = fval
        elif ftype == 'cookie':
            resp.set_cookie('flag_part', fval)
    
    return resp

if __name__ == '__main__':
    print("=" * 60)
    print("🔮 MULTIVERSE OF MADNESS: THE FRACTURED TIMELINE")
    print("=" * 60)
    print("Fragments shattered across 16 dimensions")
    print("=" * 60)
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
