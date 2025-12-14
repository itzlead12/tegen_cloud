from flask import Flask, render_template, redirect, session, request, flash, url_for
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import uuid
import os
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['DATABASE'] = 'tegen_cloud.db'


def get_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_code TEXT UNIQUE NOT NULL,
            username_hash TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            recovery_phrase_hash TEXT NOT NULL,
            email TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            panic_mode_active INTEGER DEFAULT 0,
            is_active INTEGER DEFAULT 1
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id TEXT UNIQUE NOT NULL,
            user_code TEXT NOT NULL,
            filename_encrypted BLOB,
            file_type TEXT,
            file_size INTEGER,
            original_hash TEXT,
            encrypted_hash TEXT,
            upload_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            description TEXT,
            analysis_result TEXT,
            severity_score INTEGER,
            category TEXT,
            is_verified INTEGER DEFAULT 0
        )
    ''')
    
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return redirect('/home')

@app.route('/home')
def home():
    return render_template('profile/index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        recovery_phrase = request.form.get('recovery_phrase', '').strip()
        
        if not username or not password:
            flash('Username and password are required', 'error')
            return redirect('/login')
        
        import hashlib
        username_hash = hashlib.sha256(username.encode()).hexdigest()
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute(
            'SELECT * FROM users WHERE username_hash = ? AND is_active = 1',
            (username_hash,)
        )
        user = cursor.fetchone()
        
        if user and check_password_hash(user['password_hash'], password):
            cursor.execute(
                'UPDATE users SET last_login = ? WHERE id = ?',
                (datetime.now(), user['id'])
            )
            conn.commit()
            
     
            session['user_id'] = user['id']
            session['user_code'] = user['user_code']
            session['username'] = username  
            
            flash('Login successful!', 'success')
            conn.close()
            return redirect('/dashboard')
        else:
            flash('Invalid username or password', 'error')
            conn.close()
    
    return render_template('main/login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        recovery_phrase = request.form.get('recovery_phrase', '').strip()
        email = request.form.get('email', '').strip()
        
        errors = []
        
        if not username or len(username) < 3:
            errors.append('Username must be at least 3 characters')
        
        if not password or len(password) < 8:
            errors.append('Password must be at least 8 characters')
        
        if password != confirm_password:
            errors.append('Passwords do not match')
        
        if not recovery_phrase:
            errors.append('Recovery phrase is required for account recovery')
        
        if errors:
            for error in errors:
                flash(error, 'error')
            return redirect('/register')
        
        import hashlib
        username_hash = hashlib.sha256(username.encode()).hexdigest()
        recovery_phrase_hash = hashlib.sha256(recovery_phrase.encode()).hexdigest()
        password_hash = generate_password_hash(password)
        
        user_code = f"TC-{uuid.uuid4().hex[:8].upper()}-{uuid.uuid4().hex[:4].upper()}"
        
        conn = get_db()
        cursor = conn.cursor()
        
        try:
            cursor.execute('SELECT id FROM users WHERE username_hash = ?', (username_hash,))
            if cursor.fetchone():
                flash('Username already exists', 'error')
                conn.close()
                return redirect('/register')
            
            cursor.execute('''
                INSERT INTO users 
                (user_code, username_hash, password_hash, recovery_phrase_hash, email, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (user_code, username_hash, password_hash, recovery_phrase_hash, email, datetime.now()))
            
            conn.commit()
            
            session['user_id'] = cursor.lastrowid
            session['user_code'] = user_code
            session['username'] = username
            
            flash('Registration successful! Your user code is: ' + user_code, 'success')
            conn.close()
            return redirect('/dashboard')
            
        except sqlite3.IntegrityError:
            flash('Username already exists', 'error')
            conn.close()
            return redirect('/register')
    
    return render_template('main/register.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please login to access dashboard', 'error')
        return redirect('/login')
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute(
        'SELECT COUNT(*) FROM evidence WHERE user_code = ?',
        (session['user_code'],)
    )
    evidence_count = cursor.fetchone()[0]
    
    cursor.execute('''
        SELECT evidence_id, file_type, upload_timestamp, severity_score, is_verified
        FROM evidence 
        WHERE user_code = ? 
        ORDER BY upload_timestamp DESC 
        LIMIT 5
    ''', (session['user_code'],))
    recent_evidence = cursor.fetchall()
    
    cursor.execute(
        'SELECT panic_mode_active FROM users WHERE user_code = ?',
        (session['user_code'],)
    )
    panic_status = cursor.fetchone()
    panic_active = panic_status['panic_mode_active'] if panic_status else 0
    
    conn.close()
    
    return render_template('main/dashboard.html',
                         username=session.get('username'),
                         user_code=session.get('user_code'),
                         evidence_count=evidence_count,
                         recent_evidence=recent_evidence,
                         panic_active=panic_active)

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect('/')

if not os.path.exists(app.config['DATABASE']):
    init_db()

if __name__ == '__main__':
    app.run(debug=True)