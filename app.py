import os
import sys
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import joblib
import re
from datetime import datetime
from sqlalchemy import func
import pathlib
from typing import Optional
from flask_bcrypt import Bcrypt

try:
    import psycopg2
except ImportError:
    pass

app = Flask(__name__)
bcrypt = Bcrypt(app)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'vcghvuegfjhvgfbvahgfbfhgrfgbgunh')

database_url = os.environ.get('DATABASE_URL', 'sqlite:///site.db')

if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://")

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(60), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    history = db.relationship('History', backref='owner', lazy=True)

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"User('{self.email}', Admin: {self.is_admin})"

class History(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.Text, nullable=False)
    result = db.Column(db.String(20), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    def __repr__(self):
        return f"History('{self.url}', '{self.result}')"

def extract_features(url):
    length = len(url)
    keywords = ['login', 'verify', 'update', 'security']
    keyword_count = sum(1 for k in keywords if k in url.lower())
    vectorized_features = url_vectorizer.transform([url])
    return vectorized_features

@app.route("/")
def index():
    return render_template('index.html', title='Home')

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('That email is already registered. Please log in.', 'danger')
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        new_user = User(name=name, email=email, password_hash=hashed_password, is_admin=False)
        db.session.add(new_user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', title='Register')

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = request.form.get('remember') == 'on'

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            login_user(user, remember=remember)
            next_page = request.args.get('next')
            flash('Login successful.', 'success')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Login Unsuccessful. Please check email and password.', 'danger')

    return render_template('login.html', title='Login')

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

@app.route("/analyze", methods=['POST'])
def analyze():
    if request.method == 'POST':
        url_to_check = request.form.get('url_input', '').strip()

        if not url_to_check:
            flash('Please enter a URL to check.', 'danger')
            return redirect(url_for('index'))

        try:
            features = extract_features(url_to_check)
            prediction = url_model.predict(features)[0]
            probability = url_model.predict_proba(features)[0]

            result = 'Phishing' if prediction == 1 else 'Legitimate'
            confidence = max(probability) * 100

            user_id = current_user.id if current_user.is_authenticated else None
            history_entry = History(url=url_to_check, result=result, user_id=user_id)
            db.session.add(history_entry)
            db.session.commit()

            return render_template('result.html',
                                   title='Analysis Result',
                                   url=url_to_check,
                                   result=result,
                                   confidence=f"{confidence:.2f}%")

        except Exception as e:
            flash(f"An error occurred during analysis: {e}", 'danger')
            return redirect(url_for('index'))

    return redirect(url_for('index'))

@app.route("/dashboard")
@login_required
def dashboard():
    history = History.query.filter_by(user_id=current_user.id).order_by(History.timestamp.desc()).all()

    phishing_count = History.query.filter_by(user_id=current_user.id, result='Phishing').count()
    legitimate_count = History.query.filter_by(user_id=current_user.id, result='Legitimate').count()

    return render_template('dashboard.html',
                           title='Dashboard',
                           history=history,
                           phishing_count=phishing_count,
                           legitimate_count=legitimate_count)

@app.route("/admin")
@login_required
def admin_page():
    if not current_user.is_admin:
        flash('Access denied: You must be an administrator.', 'danger')
        return redirect(url_for('index'))

    history = History.query.order_by(History.timestamp.desc()).all()
    total_checks = History.query.count()
    total_users = User.query.count()

    return render_template('admin.html',
                           title='Admin Panel',
                           history=history,
                           total_checks=total_checks,
                           total_users=total_users)

@app.cli.command("init-db-admin")
def init_db_admin():
    with app.app_context():
        try:
            db.create_all()
            print("Database tables created successfully.")

            admin_email = os.environ.get('ADMIN_EMAIL', 'Adp9550@gmail.com')
            admin_password = os.environ.get('ADMIN_PASSWORD', 'ADp95220')

            if not User.query.filter_by(email=admin_email).first():
                hashed_password = bcrypt.generate_password_hash(admin_password).decode('utf-8')

                admin_user = User(name="Admin User", email=admin_email, password_hash=hashed_password, is_admin=True)
                db.session.add(admin_user)
                db.session.commit()
                print(f"Default admin user '{admin_email}' created (Password: '{admin_password}').")
                print("!!! WARNING: Ensure ADMIN_EMAIL and ADMIN_PASSWORD environment variables are set securely in production !!!")
            else:
                print(f"Admin user '{admin_email}' already exists. Skipping creation.")

        except Exception as e:
            print(f"ERROR: Database initialization failed. Ensure your database is accessible. Details: {e}", file=sys.stderr)
            sys.exit(1)

if __name__ == '__main__':
    print("Running Flask app in local development mode.")
    app.run(debug=True)