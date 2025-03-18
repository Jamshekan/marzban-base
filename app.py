from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
import sqlite3
import subprocess
import os

app = Flask(__name__)
app.secret_key = 'admin'  # یه کلید مخفی دلخواه وارد کنید
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# تعریف کلاس کاربر
class User(UserMixin):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password

# لود کردن کاربر
@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('vpn_panel.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = c.fetchone()
    conn.close()
    if user:
        return User(user[0], user[1], user[2])
    return None

# ایجاد پایگاه داده
def init_db():
    conn = sqlite3.connect('vpn_panel.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE,
                    password TEXT,
                    email TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS configs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    config TEXT,
                    FOREIGN KEY(user_id) REFERENCES users(id))''')
    conn.commit()
    conn.close()

# تولید کلیدهای WireGuard
def generate_wireguard_keys():
    private_key = subprocess.check_output("wg genkey", shell=True).decode().strip()
    public_key = subprocess.check_output(f"echo '{private_key}' | wg pubkey", shell=True).decode().strip()
    return private_key, public_key

# صفحه ثبت‌نام
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        email = request.form['email']
        conn = sqlite3.connect('vpn_panel.db')
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)", (username, password, email))
            conn.commit()
            flash('ثبت‌نام موفقیت‌آمیز بود!', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('نام کاربری قبلاً ثبت شده است.', 'danger')
        finally:
            conn.close()
    return render_template('register.html')

# صفحه ورود
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('vpn_panel.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()
        if user and bcrypt.check_password_hash(user[2], password):
            user_obj = User(user[0], user[1], user[2])
            login_user(user_obj)
            flash('ورود موفقیت‌آمیز بود!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('نام کاربری یا رمز عبور اشتباه است.', 'danger')
    return render_template('login.html')

# خروج از حساب
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('شما خارج شدید.', 'info')
    return redirect(url_for('login'))

# داشبورد کاربر
@app.route('/dashboard')
@login_required
def dashboard():
    conn = sqlite3.connect('vpn_panel.db')
    c = conn.cursor()
    c.execute("SELECT id, config FROM configs WHERE user_id = ?", (current_user.id,))
    configs = c.fetchall()
    conn.close()
    return render_template('dashboard.html', configs=configs)

# ایجاد کانفیگ جدید
@app.route('/create_config', methods=['GET', 'POST'])
@login_required
def create_config():
    if request.method == 'POST':
        user_id = current_user.id
        private_key, public_key = generate_wireguard_keys()
        server_public_key = "YOUR_SERVER_PUBLIC_KEY"  # کلید عمومی سرور رو اینجا بذارید
        server_address = "YOUR_SERVER_IP:PORT"  # آدرس و پورت سرور رو وارد کنید
        config = f"""
[Interface]
PrivateKey = {private_key}
Address = 10.0.0.{user_id}/32
DNS = 8.8.8.8

[Peer]
PublicKey = {server_public_key}
Endpoint = {server_address}
AllowedIPs = 0.0.0.0/0
"""
        conn = sqlite3.connect('vpn_panel.db')
        c = conn.cursor()
        c.execute("INSERT INTO configs (user_id, config) VALUES (?, ?)", (user_id, config))
        conn.commit()
        conn.close()
        flash('کانفیگ با موفقیت ایجاد شد!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('create_config.html')

# دانلود کانفیگ
@app.route('/download_config/<int:config_id>')
@login_required
def download_config(config_id):
    conn = sqlite3.connect('vpn_panel.db')
    c = conn.cursor()
    c.execute("SELECT config FROM configs WHERE id = ? AND user_id = ?", (config_id, current_user.id))
    config = c.fetchone()
    conn.close()
    if config:
        return config[0], 200, {'Content-Type': 'text/plain; charset=utf-8'}
    else:
        flash('کانفیگ یافت نشد.', 'danger')
        return redirect(url_for('dashboard'))

# صفحه اصلی
@app.route('/')
def home():
    return "خوش اومدی به پنل VPN!"

if __name__ == '__main__':
    init_db()  # ساخت پایگاه داده
    app.run(debug=True)