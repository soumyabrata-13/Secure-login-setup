import sqlite3
import re
import pyotp
import bcrypt
from flask import Flask, request, session, redirect, url_for, render_template_string, flash

app = Flask(__name__)
# Secret key encrypts the session cookies. Never share this in a real app!
app.secret_key = "super_secure_random_secret_key"

# ==========================================
# 1. DATABASE SETUP & SECURITY (SQL INJECTION PREVENTION)
# ==========================================
def init_db():
    """Creates the users table if it doesn't exist."""
    conn = sqlite3.connect('secure_app.db')
    cursor = conn.cursor()
    # Storing plain passwords is a major vulnerability. We store hashed_password.
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            totp_secret TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# ==========================================
# 2. HTML TEMPLATES (Inline for simplicity)
# ==========================================
HTML_BASE = """
<!DOCTYPE html>
<html>
<head><title>Secure App</title><style>body { font-family: Arial; padding: 50px; max-width: 500px; margin: auto; }</style></head>
<body>
    <h2>Secure Login System</h2>
    {% with messages = get_flashed_messages() %}
      {% if messages %} <div style="color: red; margin-bottom:15px;">{{ messages[0] }}</div> {% endif %}
    {% endwith %}
    {{ content|safe }}
</body>
</html>
"""

# ==========================================
# 3. ROUTES & LOGIC
# ==========================================
@app.route('/')
def home():
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # INPUT VALIDATION: Ensure alphanumeric username, at least 3 chars
        if not re.match(r"^[a-zA-Z0-9_]{3,20}$", username):
            flash("Invalid username. Use 3-20 letters/numbers.")
            return redirect(url_for('register'))
        if len(password) < 6:
            flash("Password must be at least 6 characters.")
            return redirect(url_for('register'))

        # PASSWORD HASHING: bcrypt
        salt = bcrypt.gensalt()
        password_hash = bcrypt.hashpw(password.encode('utf-8'), salt)

        # 2FA SETUP: Generate a unique secret for this user
        totp_secret = pyotp.random_base32()

        try:
            conn = sqlite3.connect('secure_app.db')
            cursor = conn.cursor()
            # PARAMETERIZED QUERY: The '?' prevents SQL Injection attacks
            cursor.execute("INSERT INTO users (username, password_hash, totp_secret) VALUES (?, ?, ?)", 
                           (username, password_hash.decode('utf-8'), totp_secret))
            conn.commit()
            conn.close()
            
            flash(f"Account created! Your 2FA Secret Key is: {totp_secret} (Save this!)")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Username already exists.")
            return redirect(url_for('register'))

    content = """
    <form method="POST">
        <input type="text" name="username" placeholder="Username" required><br><br>
        <input type="password" name="password" placeholder="Password" required><br><br>
        <button type="submit">Register</button>
    </form>
    <br><a href="/login">Already have an account? Login</a>
    """
    return render_template_string(HTML_BASE, content=content)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('secure_app.db')
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash, totp_secret FROM users WHERE username = ?", (username,))
        user_record = cursor.fetchone()
        conn.close()

        if user_record:
            stored_hash = user_record[0].encode('utf-8')
            totp_secret = user_record[1]

            # Compare provided password with stored bcrypt hash
            if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
                # Temporary session holding ground until 2FA is passed
                session['pending_user'] = username
                session['totp_secret'] = totp_secret
                return redirect(url_for('verify_2fa'))
        
        flash("Invalid username or password.")
        return redirect(url_for('login'))

    content = """
    <form method="POST">
        <input type="text" name="username" placeholder="Username" required><br><br>
        <input type="password" name="password" placeholder="Password" required><br><br>
        <button type="submit">Login</button>
    </form>
    <br><a href="/register">Create an account</a>
    """
    return render_template_string(HTML_BASE, content=content)

@app.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():
    if 'pending_user' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        otp = request.form['otp']
        totp = pyotp.TOTP(session['totp_secret'])

        # Validate the 6-digit code
        if totp.verify(otp):
            session['user'] = session['pending_user']
            session.pop('pending_user', None)
            session.pop('totp_secret', None)
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid 2FA Code.")

    content = """
    <p>Enter the 6-digit code from your Authenticator App.</p>
    <form method="POST">
        <input type="text" name="otp" placeholder="6-digit code" required autocomplete="off"><br><br>
        <button type="submit">Verify</button>
    </form>
    """
    return render_template_string(HTML_BASE, content=content)

@app.route('/dashboard')
def dashboard():
    # SESSION MANAGEMENT: Protect this route from unauthenticated access
    if 'user' not in session:
        flash("Please log in to access the dashboard.")
        return redirect(url_for('login'))
        
    content = f"""
    <h3>Welcome, {session['user']}!</h3>
    <p>You have successfully passed password verification and Two-Factor Authentication.</p>
    <a href="/logout"><button>Logout</button></a>
    """
    return render_template_string(HTML_BASE, content=content)

@app.route('/logout')
def logout():
    # Clear the session cookie
    session.clear()
    flash("You have been logged out securely.")
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    # Runs the web app locally on port 5000
    app.run(debug=True, port=5000)