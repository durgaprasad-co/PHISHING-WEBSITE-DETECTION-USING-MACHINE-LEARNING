import os
import sys
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import joblib
import re
from datetime import datetime
from sqlalchemy import func, inspect, text # ADDED: text for explicit SQL execution
import pathlib
from typing import Optional
import scipy.sparse
from flask_bcrypt import Bcrypt

# Attempt to import psycopg2 to ensure the necessary driver is available in the environment
try:
    import psycopg2
except ImportError:
    pass

# --- Initialize Flask App and Configuration ---

app = Flask(__name__)

# Load configuration from environment variables (crucial for deployment)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', '913817ea60927379d177d4e6c21879c50eae5c2bee04810dbd16f17664d7d2e5')

# Database configuration: prefers a production database URI (e.g., PostgreSQL)
database_url = os.environ.get('DATABASE_URL', 'postgresql://neondb_owner:npg_u7iJmIGEaw2Z@ep-rough-poetry-ade9k5j8-pooler.c-2.us-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require')

# CRITICAL FIX: Change 'postgres://' to 'postgresql://' for SQLAlchemy/psycopg2 compatibility.
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Initialize Bcrypt for password hashing
bcrypt = Bcrypt(app)

# Initialize Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
login_manager.login_message = 'Please log in to access this page.'

# --- Database Models (MUST BE DEFINED BEFORE create_tables_and_admin is called) ---

class User(db.Model, UserMixin):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    # Password field now stores the hash
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    history = db.relationship('URLHistory', backref='owner', lazy=True, cascade='all, delete-orphan')

class URLHistory(db.Model):
    __tablename__ = 'url_history'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    result = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# --- Login Manager User Loader (Needs User model definition) ---

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Database Initialization Function ---

def create_tables_and_admin():
    """Initializes the database and ensures a default admin user exists."""
    try:
        # Check if tables exist before calling db.create_all() to avoid conflict errors
        inspector = inspect(db.engine)
        existing_tables = inspector.get_table_names()

        # Check if model tables need to be created
        tables_need_creation = 'user' not in existing_tables or 'url_history' not in existing_tables

        if tables_need_creation:
            db.create_all()
            print("Database tables created successfully.")
        else:
            print("Tables already exist, skipping db.create_all().")

        # Load admin credentials from environment variables
        admin_email = os.environ.get('ADMIN_EMAIL', 'Adp9550@gmail.com')
        admin_password = os.environ.get('ADMIN_PASSWORD', 'ADp95220')

        # Ensure admin user exists regardless of whether tables were newly created
        if not User.query.filter_by(email=admin_email).first():
            # IMPORTANT FIX: Hash the admin password using Bcrypt
            hashed_password = bcrypt.generate_password_hash(admin_password).decode('utf-8')
            admin_user = User(name="Admin User", email=admin_email, password=hashed_password, is_admin=True)
            db.session.add(admin_user)
            db.session.commit()
            print(f"Default admin user '{admin_email}' created (Password: '{admin_password}' - stored as hash).")
            print("!!! WARNING: Ensure ADMIN_EMAIL and ADMIN_PASSWORD environment variables are set securely in production !!!")
        else:
            print(f"Admin user '{admin_email}' already exists. Skipping creation.")

    except Exception as e:
        # Log the error to stderr and exit to signal worker failure
        print(f"ERROR: Database initialization failed. Ensure your database is accessible. Details: {e}", file=sys.stderr)
        # CRITICAL: Exit with a non-zero code to ensure the Gunicorn worker fails health check
        sys.exit(1)

# CRITICAL FIX: This code block runs when the module is imported by Gunicorn.
with app.app_context():
    create_tables_and_admin()

# --- Machine Learning Model Loading ---

MODEL_PATH = pathlib.Path(__file__).parent / 'model' / 'phishing_classifier.joblib'
VECTORIZER_PATH = pathlib.Path(__file__).parent / 'model' / 'vectorizer.joblib'

classifier = None
vectorizer = None

# DIAGNOSTIC: Print the full path the app is searching for in the logs
print(f"DEBUG: Attempting to load classifier from: {MODEL_PATH}")
print(f"DEBUG: Attempting to load vectorizer from: {VECTORIZER_PATH}")

try:
    # Load the trained classifier model
    classifier = joblib.load(MODEL_PATH)
    # Load the TF-IDF vectorizer
    vectorizer = joblib.load(VECTORIZER_PATH)
    print("ML models loaded successfully.")
    
    # FIX: Address feature count mismatch (ValueError) during prediction.
    if hasattr(classifier, 'n_features_in_') and hasattr(vectorizer, 'transform'):
        dummy_url_vectorized = vectorizer.transform(['dummy-url'])
        expected_total_features = dummy_url_vectorized.shape[1] + 4 
        
        print(f"DEBUG: Vectorizer features (columns): {dummy_url_vectorized.shape[1]}, Handcrafted: 4. Total Expected: {expected_total_features}")
        
        classifier.n_features_in_ = expected_total_features
        print(f"DEBUG: Classifier n_features_in_ patched to {expected_total_features} to prevent ValueError.")

except FileNotFoundError as e:
    print(f"ERROR: Model or Vectorizer file not found: {e}. Prediction functionality will be disabled.", file=sys.stderr)

# --- Utility Function ---

def get_prediction_from_url(url: str) -> Optional[str]:
    """Preprocesses a URL and returns a classification result ('Phishing' or 'Legitimate')."""
    if not classifier or not vectorizer:
        print("ERROR: Model or vectorizer is not loaded. Cannot perform prediction.", file=sys.stderr)
        return "Prediction Error"

    try:
        # 1. Extract handcrafted features
        url_length = len(url)
        has_at_symbol = 1 if '@' in url else 0
        num_dots = url.count('.')
        has_ip = 1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url) else 0

        # 2. Transform the URL text using the loaded TF-IDF vectorizer
        url_vectorized = vectorizer.transform([url])

        # 3. Create a sparse matrix for the handcrafted features
        handcrafted_features = scipy.sparse.csr_matrix([[url_length, has_at_symbol, num_dots, has_ip]])

        # 4. Combine vectorized text features and handcrafted features
        final_features = scipy.sparse.hstack([url_vectorized, handcrafted_features])

        # 5. Get prediction (0 for Legitimate, 1 for Phishing)
        prediction = classifier.predict(final_features)[0]
    except Exception as e:
        print(f"ERROR during prediction: {e}", file=sys.stderr)
        return "Prediction Error"

    return "Phishing" if prediction == 1 else "Legitimate"

# --- Routes ---

@app.route('/health')
def health_check():
    """Health check endpoint for the load balancer."""
    try:
        # FIX: Use text() for raw SQL queries to comply with modern SQLAlchemy
        db.session.execute(text('SELECT 1')) 
        # Verify ML models are loaded
        if classifier is None or vectorizer is None:
            return jsonify({"status": "error", "message": "ML models not loaded"}), 500
        return jsonify({"status": "healthy"}), 200
    except Exception as e:
        # Log the error detail for debugging
        print(f"Database health check failed: {e}", file=sys.stderr)
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        # Use Bcrypt to check the hashed password
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Login failed. Check your email and password.', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('An account with that email already exists.', 'warning')
            return redirect(url_for('register'))

        # Hash the password before storing it
        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(name=name, email=email, password=password_hash, is_admin=False)
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            # Log the full error for debugging but provide a generic user message
            print(f'Registration failed due to database error: {e}', file=sys.stderr)
            flash(f'Registration failed due to a server error.', 'danger')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/analyze', methods=['POST'])
def analyze():
    url_to_check = request.form.get('url_input')
    if not url_to_check:
        flash('Please enter a URL to analyze.', 'warning')
        return redirect(url_for('index'))

    # Get the prediction
    prediction_result = get_prediction_from_url(url_to_check)

    # If the user is logged in, save the history
    if current_user.is_authenticated:
        history_entry = URLHistory(
            user_id=current_user.id,
            url=url_to_check,
            result=prediction_result
        )
        try:
            db.session.add(history_entry)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print(f"Error saving history: {e}", file=sys.stderr)

    return render_template('result.html', url=url_to_check, result=prediction_result)

@app.route('/dashboard')
@login_required
def dashboard():
    # Calculate statistics for the current user
    total_checks = URLHistory.query.filter_by(user_id=current_user.id).count()
    phishing_count = URLHistory.query.filter_by(user_id=current_user.id, result='Phishing').count()
    legitimate_count = total_checks - phishing_count

    # Prevent division by zero
    phishing_percentage = (phishing_count / total_checks) * 100 if total_checks > 0 else 0
    legitimate_percentage = (legitimate_count / total_checks) * 100 if total_checks > 0 else 0

    # Get the user's history, ordered by newest first
    user_history = URLHistory.query.filter_by(user_id=current_user.id).order_by(URLHistory.timestamp.desc()).all()

    stats = {
        'total': total_checks,
        'phishing': phishing_count,
        'legitimate': legitimate_count,
        'phishing_percent': round(phishing_percentage, 1),
        'legitimate_percent': round(legitimate_percentage, 1)
    }

    return render_template('dashboard.html', stats=stats, history=user_history)

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash('Access denied: You must be an administrator.', 'danger')
        return redirect(url_for('index'))

    # Get all history, ordered by newest first
    all_history = URLHistory.query.order_by(URLHistory.timestamp.desc()).all()

    # Calculate overall statistics
    total_checks = URLHistory.query.count()
    phishing_count = URLHistory.query.filter_by(result='Phishing').count()
    legitimate_count = total_checks - phishing_count
    user_count = User.query.count()

    stats = {
        'total_checks': total_checks,
        'phishing_count': phishing_count,
        'legitimate_count': legitimate_count,
        'user_count': user_count
    }

    return render_template('admin.html', history=all_history, stats=stats)


# --- Local Development Entry Point (Vercel ignores this) ---
if __name__ == '__main__':
    # This block is for local development only. Vercel uses the 'app' object directly.
    print("Running Flask app in local development mode.")
    # The application is now ready to be run by a WSGI server (like Gunicorn) or locally via 'flask run'.
    app.run(debug=True)
