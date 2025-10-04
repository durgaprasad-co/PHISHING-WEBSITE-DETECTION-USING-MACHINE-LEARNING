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

# Attempt to import psycopg2 to ensure the necessary driver is available in the environment
try:
    import psycopg2 
except ImportError:
    pass

# --- Initialize Flask App and Configuration ---

app = Flask(__name__)

# Load configuration from environment variables (crucial for deployment)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'vcghvuegfjhvgfbvahgfbfhgrfgbgunh')

# Database configuration: prefers a production database URI (e.g., PostgreSQL) 
database_url = os.environ.get('DATABASE_URL', 'sqlite:///site.db') 

# CRITICAL FIX: Change 'postgres://' to 'postgresql://' for SQLAlchemy/psycopg2 compatibility.
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# --- Database Initialization Function (New) ---

def create_tables_and_admin():
    """Initializes the database tables and creates the default admin user."""
    try:
        # Create database tables
        db.create_all()
        print("Database tables created successfully.")

        # Load admin credentials from environment variables
        admin_email = os.environ.get('ADMIN_EMAIL', 'Adp9550@gmail.com')
        admin_password = os.environ.get('ADMIN_PASSWORD', 'ADp95220')
        
        # Check if admin user already exists
        if not User.query.filter_by(email=admin_email).first():
            # NOTE: In a real-world app, the password MUST be hashed before storage.
            admin_user = User(name="Admin User", email=admin_email, password=admin_password, is_admin=True)
            db.session.add(admin_user)
            db.session.commit()
            print(f"Default admin user '{admin_email}' created (Password: '{admin_password}').")
            print("!!! WARNING: Ensure ADMIN_EMAIL and ADMIN_PASSWORD environment variables are set securely in production !!!")
        else:
            print(f"Admin user '{admin_email}' already exists. Skipping creation.")
            
    except Exception as e:
        print(f"ERROR: Database initialization or admin creation failed: {e}", file=sys.stderr)
        # Re-raise the exception to indicate a critical failure
        # In a production environment, you may want a gentler exit or log-only behavior
        # But for this problem, we want to ensure it crashes if the DB is unreachable.
        sys.exit(1)


# *** CORE FIX: CALL THE INITIALIZATION FUNCTION ON APP STARTUP ***
with app.app_context():
    create_tables_and_admin()


# Initialize Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
login_manager.login_message = 'Please log in to access this page.'

# --- Database Models ---

class User(db.Model, UserMixin):
    # CRITICAL: Table name is explicitly defined to avoid issues with reserved SQL keywords
    __tablename__ = 'user'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False) 
    is_admin = db.Column(db.Boolean, default=False)

    history = db.relationship('URLHistory', backref='owner', lazy=True, cascade='all, delete-orphan')

class URLHistory(db.Model):
    __tablename__ = 'url_history'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    result = db.Column(db.String(50), nullable=False) # 'Legitimate' or 'Phishing'
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# --- Login Manager Callbacks ---

@login_manager.user_loader
def load_user(user_id: str) -> Optional[User]:
    """Callback to reload the user object from the user ID stored in the session."""
    return db.session.get(User, int(user_id))

# --- ML Model Loading ---

# Resolve the path relative to the current file location
base_dir = pathlib.Path(__file__).parent
model_path = base_dir / 'url_model.joblib'
vectorizer_path = base_dir / 'url_vectorizer.joblib'

url_model = None
url_vectorizer = None

try:
    # Attempt to load the pre-trained model and vectorizer
    url_model = joblib.load(model_path)
    url_vectorizer = joblib.load(vectorizer_path)
    print("ML Model and Vectorizer loaded successfully.")
except FileNotFoundError:
    print("CRITICAL ERROR: ML model files (url_model.joblib or url_vectorizer.joblib) not found.", file=sys.stderr)
    # Allows the app to start, but prediction will fail
except Exception as e:
    print(f"CRITICAL ERROR loading ML files: {e}", file=sys.stderr)

# --- Feature Extraction Function ---

def extract_features(url: str) -> str:
    """
    Returns the raw URL string for the loaded vectorizer to process.
    """
    return url

# --- CLI Command (Kept for consistency, but logic is now automatic) ---

@app.cli.command('init-db-admin')
def init_db_admin():
    """Initializes the database and creates the default admin user."""
    with app.app_context():
        create_tables_and_admin()
        
# --- Routes ---

@app.route('/')
def index():
    """Renders the main URL submission page."""
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
@login_required
def predict():
    """Handles URL submission, prediction, and history logging."""
    if url_model is None or url_vectorizer is None:
        flash('Prediction service is unavailable: ML models failed to load.', 'danger')
        return redirect(url_for('index'))

    url = request.form.get('url', '').strip()
    if not url:
        flash('Please enter a URL for analysis.', 'warning')
        return redirect(url_for('index'))

    # 1. Feature Extraction
    features = extract_features(url)
    
    # 2. Vectorization
    X = url_vectorizer.transform([features])
    
    # 3. Prediction
    prediction = url_model.predict(X)[0]
    result = 'Phishing' if prediction == 1 else 'Legitimate'

    # 4. Save to History
    history_entry = URLHistory(user_id=current_user.id, url=url, result=result)
    db.session.add(history_entry)
    db.session.commit()

    return render_template('result.html', url=url, result=result)

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handles user registration."""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Account already exists for that email.', 'danger')
            return redirect(url_for('register'))

        # NOTE: Passwords should be hashed using generate_password_hash(password) in a real app
        new_user = User(name=name, email=email, password=password) 
        db.session.add(new_user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login."""
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        
        # NOTE: Password check should use check_password_hash(user.password_hash, password) in a real app
        if user and user.password == password: 
            login_user(user)
            next_page = request.args.get('next')
            flash(f'Logged in successfully as {user.name}.', 'success')
            return redirect(next_page or url_for('index'))
        else:
            flash('Login Unsuccessful. Please check email and password.', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """Logs out the current user."""
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    """Shows the user's history and statistics."""
    # Retrieve user's history
    user_history = URLHistory.query.filter_by(user_id=current_user.id).order_by(URLHistory.timestamp.desc()).all()
    
    # Calculate statistics for the chart
    stats = db.session.query(
        URLHistory.result,
        func.count(URLHistory.result)
    ).filter(URLHistory.user_id == current_user.id).group_by(URLHistory.result).all()
    
    # Format data for Chart.js
    chart_data = {
        'labels': [s[0] for s in stats],
        'counts': [s[1] for s in stats]
    }
    
    return render_template('dashboard.html', history=user_history, chart_data=chart_data)

@app.route('/admin')
@login_required
def admin():
    """Shows the full history for admin users only."""
    if not current_user.is_admin:
        flash('Access Denied: You must be an administrator.', 'danger')
        return redirect(url_for('index'))
    
    # Fetch all history entries
    all_history = URLHistory.query.order_by(URLHistory.timestamp.desc()).all()
    
    return render_template('admin.html', history=all_history)


# --- Local Development Entry Point ---
if __name__ == '__main__':
    # This block is for local development only. 
    # The application is run by Gunicorn/Defang's WSGI server in deployment.
    print("Running Flask app in local development mode.")
    app.run(debug=True)