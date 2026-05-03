from flask import Flask, request, jsonify, session
from flask_cors import CORS
import sqlite3
import hashlib
import secrets
import re
from datetime import datetime, timedelta
import os

app = Flask(__name__, static_folder='static', static_url_path='')
app.secret_key = 'qatar_foundation_secret_key_2024'
CORS(app, supports_credentials=True)

DB_PATH = 'database.db'

# ─── DATABASE SETUP ───────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        full_name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS reset_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        token TEXT NOT NULL,
        expires_at TEXT NOT NULL
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS opportunities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        category TEXT NOT NULL,
        duration TEXT NOT NULL,
        start_date TEXT NOT NULL,
        description TEXT NOT NULL,
        skills TEXT NOT NULL,
        future_opportunities TEXT NOT NULL,
        max_applicants TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (admin_id) REFERENCES admins(id)
    )''')
    conn.commit()
    conn.close()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# ─── AUTH ROUTES ──────────────────────────────────────────────────────────────

@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.get_json()
    full_name = data.get('full_name', '').strip()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    confirm_password = data.get('confirm_password', '')

    if not all([full_name, email, password, confirm_password]):
        return jsonify({'error': 'All fields are required'}), 400
    if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
        return jsonify({'error': 'Invalid email format'}), 400
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400
    if password != confirm_password:
        return jsonify({'error': 'Passwords do not match'}), 400

    conn = get_db()
    try:
        conn.execute('INSERT INTO admins (full_name, email, password) VALUES (?, ?, ?)',
                     (full_name, email, hash_password(password)))
        conn.commit()
        return jsonify({'message': 'Account created successfully'}), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'An account with this email already exists'}), 409
    finally:
        conn.close()

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    remember_me = data.get('remember_me', False)

    if not email or not password:
        return jsonify({'error': 'Invalid email or password'}), 401

    conn = get_db()
    admin = conn.execute('SELECT * FROM admins WHERE email=? AND password=?',
                         (email, hash_password(password))).fetchone()
    conn.close()

    if not admin:
        return jsonify({'error': 'Invalid email or password'}), 401

    session['admin_id'] = admin['id']
    session['admin_name'] = admin['full_name']
    if remember_me:
        app.permanent_session_lifetime = timedelta(days=30)
        session.permanent = True
    else:
        session.permanent = False

    return jsonify({'message': 'Login successful', 'admin_name': admin['full_name']}), 200

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'Logged out'}), 200

@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    # Always return success message to protect privacy
    conn = get_db()
    admin = conn.execute('SELECT * FROM admins WHERE email=?', (email,)).fetchone()
    if admin:
        token = secrets.token_urlsafe(32)
        expires_at = (datetime.now() + timedelta(hours=1)).isoformat()
        conn.execute('INSERT INTO reset_tokens (email, token, expires_at) VALUES (?, ?, ?)',
                     (email, token, expires_at))
        conn.commit()
        print(f"[RESET LINK] http://localhost:5000/reset-password?token={token}")
    conn.close()
    return jsonify({'message': 'If this email is registered, a reset link has been sent.'}), 200

@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    token = data.get('token', '')
    new_password = data.get('password', '')

    if len(new_password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400

    conn = get_db()
    row = conn.execute('SELECT * FROM reset_tokens WHERE token=?', (token,)).fetchone()
    if not row:
        conn.close()
        return jsonify({'error': 'Invalid or expired reset link'}), 400

    if datetime.fromisoformat(row['expires_at']) < datetime.now():
        conn.execute('DELETE FROM reset_tokens WHERE token=?', (token,))
        conn.commit()
        conn.close()
        return jsonify({'error': 'Reset link has expired'}), 400

    conn.execute('UPDATE admins SET password=? WHERE email=?',
                 (hash_password(new_password), row['email']))
    conn.execute('DELETE FROM reset_tokens WHERE token=?', (token,))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Password reset successful'}), 200

@app.route('/api/me', methods=['GET'])
def me():
    if 'admin_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    return jsonify({'admin_id': session['admin_id'], 'admin_name': session['admin_name']}), 200

# ─── OPPORTUNITY ROUTES ───────────────────────────────────────────────────────

def require_login():
    if 'admin_id' not in session:
        return None
    return session['admin_id']

@app.route('/api/opportunities', methods=['GET'])
def get_opportunities():
    admin_id = require_login()
    if not admin_id:
        return jsonify({'error': 'Unauthorized'}), 401
    conn = get_db()
    rows = conn.execute('SELECT * FROM opportunities WHERE admin_id=? ORDER BY created_at DESC',
                        (admin_id,)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows]), 200

@app.route('/api/opportunities', methods=['POST'])
def add_opportunity():
    admin_id = require_login()
    if not admin_id:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json()
    required = ['name', 'category', 'duration', 'start_date', 'description', 'skills', 'future_opportunities']
    for field in required:
        if not data.get(field, '').strip():
            return jsonify({'error': f'{field} is required'}), 400

    conn = get_db()
    cursor = conn.execute(
        '''INSERT INTO opportunities (admin_id, name, category, duration, start_date,
           description, skills, future_opportunities, max_applicants)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
        (admin_id, data['name'], data['category'], data['duration'], data['start_date'],
         data['description'], data['skills'], data['future_opportunities'],
         data.get('max_applicants', ''))
    )
    conn.commit()
    new_id = cursor.lastrowid
    row = conn.execute('SELECT * FROM opportunities WHERE id=?', (new_id,)).fetchone()
    conn.close()
    return jsonify(dict(row)), 201

@app.route('/api/opportunities/<int:opp_id>', methods=['GET'])
def get_opportunity(opp_id):
    admin_id = require_login()
    if not admin_id:
        return jsonify({'error': 'Unauthorized'}), 401
    conn = get_db()
    row = conn.execute('SELECT * FROM opportunities WHERE id=? AND admin_id=?',
                       (opp_id, admin_id)).fetchone()
    conn.close()
    if not row:
        return jsonify({'error': 'Not found'}), 404
    return jsonify(dict(row)), 200

@app.route('/api/opportunities/<int:opp_id>', methods=['PUT'])
def update_opportunity(opp_id):
    admin_id = require_login()
    if not admin_id:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json()
    required = ['name', 'category', 'duration', 'start_date', 'description', 'skills', 'future_opportunities']
    for field in required:
        if not data.get(field, '').strip():
            return jsonify({'error': f'{field} is required'}), 400

    conn = get_db()
    result = conn.execute(
        '''UPDATE opportunities SET name=?, category=?, duration=?, start_date=?,
           description=?, skills=?, future_opportunities=?, max_applicants=?
           WHERE id=? AND admin_id=?''',
        (data['name'], data['category'], data['duration'], data['start_date'],
         data['description'], data['skills'], data['future_opportunities'],
         data.get('max_applicants', ''), opp_id, admin_id)
    )
    conn.commit()
    if result.rowcount == 0:
        conn.close()
        return jsonify({'error': 'Not found or unauthorized'}), 404
    row = conn.execute('SELECT * FROM opportunities WHERE id=?', (opp_id,)).fetchone()
    conn.close()
    return jsonify(dict(row)), 200

@app.route('/api/opportunities/<int:opp_id>', methods=['DELETE'])
def delete_opportunity(opp_id):
    admin_id = require_login()
    if not admin_id:
        return jsonify({'error': 'Unauthorized'}), 401
    conn = get_db()
    result = conn.execute('DELETE FROM opportunities WHERE id=? AND admin_id=?',
                          (opp_id, admin_id))
    conn.commit()
    conn.close()
    if result.rowcount == 0:
        return jsonify({'error': 'Not found or unauthorized'}), 404
    return jsonify({'message': 'Deleted successfully'}), 200

# ─── SERVE FRONTEND ───────────────────────────────────────────────────────────

@app.route('/')
def index():
    return app.send_static_file('index.html')

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
