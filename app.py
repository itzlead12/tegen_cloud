from flask import Flask, render_template, redirect, session, request, flash, url_for, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import uuid
import os
from datetime import datetime
import hashlib

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['DATABASE'] = 'tegen_cloud.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB max file size
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}

# Create uploads directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def get_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def get_file_size(file_path):
    """Get file size in bytes"""
    try:
        return os.path.getsize(file_path)
    except:
        return 0

def format_file_size(size_bytes):
    """Format file size in human readable format"""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.2f} KB"
    else:
        return f"{size_bytes / (1024 * 1024):.2f} MB"

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    
    # Users table - remove panic_mode_active column if exists (we'll keep it for backward compatibility but not use it)
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
            is_active INTEGER DEFAULT 1,
            notifications_enabled INTEGER DEFAULT 1
        )
    ''')
    
    # Evidence table - update schema to include new fields
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id TEXT UNIQUE NOT NULL,
            user_code TEXT NOT NULL,
            filename TEXT NOT NULL,
            stored_filename TEXT NOT NULL,
            file_type TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            evidence_name TEXT NOT NULL,
            evidence_type TEXT NOT NULL,
            observation TEXT,
            upload_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            description TEXT,
            is_verified INTEGER DEFAULT 0
        )
    ''')
    
    # Add new columns to existing evidence table if they don't exist
    try:
        cursor.execute('ALTER TABLE evidence ADD COLUMN evidence_name TEXT')
    except sqlite3.OperationalError:
        pass  # Column already exists
    
    try:
        cursor.execute('ALTER TABLE evidence ADD COLUMN evidence_type TEXT')
    except sqlite3.OperationalError:
        pass
    
    try:
        cursor.execute('ALTER TABLE evidence ADD COLUMN observation TEXT')
    except sqlite3.OperationalError:
        pass
    
    try:
        cursor.execute('ALTER TABLE evidence ADD COLUMN stored_filename TEXT')
    except sqlite3.OperationalError:
        pass
    
    try:
        cursor.execute('ALTER TABLE evidence ADD COLUMN filename TEXT')
    except sqlite3.OperationalError:
        pass
    
    try:
        cursor.execute('ALTER TABLE users ADD COLUMN notifications_enabled INTEGER DEFAULT 1')
    except sqlite3.OperationalError:
        pass
    
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
        
        if not username or not password:
            flash('Username and password are required', 'error')
            return redirect('/login')
        
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
    
    # Calculate total storage used
    cursor.execute(
        'SELECT SUM(file_size) FROM evidence WHERE user_code = ?',
        (session['user_code'],)
    )
    total_size = cursor.fetchone()[0] or 0
    
    cursor.execute('''
        SELECT evidence_id, evidence_name, file_type, evidence_type, upload_timestamp, file_size, observation
        FROM evidence 
        WHERE user_code = ? 
        ORDER BY upload_timestamp DESC 
        LIMIT 5
    ''', (session['user_code'],))
    recent_evidence = cursor.fetchall()
    
    conn.close()
    
    return render_template('main/dashboard.html',
                         username=session.get('username'),
                         user_code=session.get('user_code'),
                         evidence_count=evidence_count,
                         recent_evidence=recent_evidence,
                         total_storage=total_size)

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'user_id' not in session:
        flash('Please login to upload evidence', 'error')
        return redirect('/login')
    
    if request.method == 'POST':
        # Check if file is present
        if 'file' not in request.files:
            flash('No file selected', 'error')
            return redirect('/upload')
        
        file = request.files['file']
        evidence_name = request.form.get('evidence_name', '').strip()
        evidence_type = request.form.get('evidence_type', '').strip()
        observation = request.form.get('observation', '').strip()
        
        # Validation
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect('/upload')
        
        if not evidence_name:
            flash('Evidence name is required', 'error')
            return redirect('/upload')
        
        if not evidence_type or evidence_type not in ['screenshot', 'document']:
            flash('Please select a valid evidence type', 'error')
            return redirect('/upload')
        
        if not allowed_file(file.filename):
            flash('File type not allowed. Please upload PNG, JPG, JPEG, GIF, or PDF files only.', 'error')
            return redirect('/upload')
        
        # Check file size
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)
        
        if file_size > app.config['MAX_CONTENT_LENGTH']:
            flash(f'File size exceeds maximum allowed size of {format_file_size(app.config["MAX_CONTENT_LENGTH"])}', 'error')
            return redirect('/upload')
        
        # Generate unique filename
        file_ext = file.filename.rsplit('.', 1)[1].lower()
        unique_filename = f"{uuid.uuid4().hex}.{file_ext}"
        evidence_id = f"EVID-{uuid.uuid4().hex[:12].upper()}"
        
        # Save file
        user_upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], session['user_code'])
        os.makedirs(user_upload_dir, exist_ok=True)
        file_path = os.path.join(user_upload_dir, unique_filename)
        file.save(file_path)
        
        # Determine file type
        if file_ext in ['png', 'jpg', 'jpeg', 'gif']:
            db_file_type = 'image'
        else:
            db_file_type = 'pdf'
        
        # Store in database
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO evidence 
            (evidence_id, user_code, filename, stored_filename, file_type, file_size, 
             evidence_name, evidence_type, observation, upload_timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (evidence_id, session['user_code'], secure_filename(file.filename), 
              unique_filename, db_file_type, file_size, evidence_name, 
              evidence_type, observation, datetime.now()))
        
        conn.commit()
        conn.close()
        
        flash('Evidence uploaded successfully!', 'success')
        return redirect('/observations')
    
    return render_template('main/upload.html',
                         username=session.get('username'),
                         user_code=session.get('user_code'))

@app.route('/observations')
def observations():
    if 'user_id' not in session:
        flash('Please login to view observations', 'error')
        return redirect('/login')
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Get filter parameters
    filter_type = request.args.get('type', 'all')
    filter_date = request.args.get('date', '')
    filter_name = request.args.get('name', '').strip()
    
    # Build query
    query = 'SELECT evidence_id, evidence_name, evidence_type, file_type, upload_timestamp, file_size, observation FROM evidence WHERE user_code = ?'
    params = [session['user_code']]
    
    if filter_type != 'all':
        query += ' AND evidence_type = ?'
        params.append(filter_type)
    
    if filter_name:
        query += ' AND evidence_name LIKE ?'
        params.append(f'%{filter_name}%')
    
    if filter_date:
        query += ' AND DATE(upload_timestamp) = ?'
        params.append(filter_date)
    
    query += ' ORDER BY upload_timestamp DESC'
    
    cursor.execute(query, params)
    observations = cursor.fetchall()
    
    conn.close()
    
    return render_template('main/observations.html',
                         username=session.get('username'),
                         user_code=session.get('user_code'),
                         observations=observations,
                         filter_type=filter_type,
                         filter_date=filter_date,
                         filter_name=filter_name)

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        flash('Please login to access profile', 'error')
        return redirect('/login')
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute(
        'SELECT email, created_at, last_login, notifications_enabled FROM users WHERE user_code = ?',
        (session['user_code'],)
    )
    user = cursor.fetchone()
    
    # Calculate storage statistics
    cursor.execute(
        'SELECT COUNT(*) FROM evidence WHERE user_code = ?',
        (session['user_code'],)
    )
    evidence_count = cursor.fetchone()[0]
    
    cursor.execute(
        'SELECT SUM(file_size) FROM evidence WHERE user_code = ?',
        (session['user_code'],)
    )
    total_size = cursor.fetchone()[0] or 0
    
    conn.close()
    
    return render_template('main/profile.html',
                         username=session.get('username'),
                         user_code=session.get('user_code'),
                         user=user,
                         evidence_count=evidence_count,
                         total_storage=total_size)

@app.route('/profile/change-password', methods=['POST'])
def change_password():
    if 'user_id' not in session:
        flash('Please login to change password', 'error')
        return redirect('/login')
    
    current_password = request.form.get('current_password', '').strip()
    new_password = request.form.get('new_password', '').strip()
    confirm_password = request.form.get('confirm_password', '').strip()
    
    if not current_password or not new_password or not confirm_password:
        flash('All password fields are required', 'error')
        return redirect('/profile')
    
    if new_password != confirm_password:
        flash('New passwords do not match', 'error')
        return redirect('/profile')
    
    if len(new_password) < 8:
        flash('New password must be at least 8 characters', 'error')
        return redirect('/profile')
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute(
        'SELECT password_hash FROM users WHERE user_code = ?',
        (session['user_code'],)
    )
    user = cursor.fetchone()
    
    if not user or not check_password_hash(user['password_hash'], current_password):
        flash('Current password is incorrect', 'error')
        conn.close()
        return redirect('/profile')
    
    new_password_hash = generate_password_hash(new_password)
    cursor.execute(
        'UPDATE users SET password_hash = ? WHERE user_code = ?',
        (new_password_hash, session['user_code'])
    )
    conn.commit()
    conn.close()
    
    flash('Password changed successfully!', 'success')
    return redirect('/profile')

@app.route('/profile/update-notifications', methods=['POST'])
def update_notifications():
    if 'user_id' not in session:
        flash('Please login to update settings', 'error')
        return redirect('/login')
    
    notifications_enabled = request.form.get('notifications_enabled', 'off')
    enabled = 1 if notifications_enabled == 'on' else 0
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute(
        'UPDATE users SET notifications_enabled = ? WHERE user_code = ?',
        (enabled, session['user_code'])
    )
    conn.commit()
    conn.close()
    
    flash('Notification preferences updated!', 'success')
    return redirect('/profile')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect('/')

# Ensure database schema is up to date (safe to call on each startup)
init_db()

if __name__ == '__main__':
    app.run(debug=True)
