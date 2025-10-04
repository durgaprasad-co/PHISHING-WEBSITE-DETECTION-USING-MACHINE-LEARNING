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
from flask_bcrypt import Bcrypt # <<< NEW IMPORT

# Attempt to import psycopg2 to ensure the necessary driver is available in the environment
try:
    import psycopg2 
except ImportError:
    pass

# --- Initialize Flask App and Configuration ---

app = Flask(__name__)
bcrypt = Bcrypt(app) # <<< NEW INITIALIZATION

# Load configuration from environment variables (crucial for deployment)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'vcghvuegfjhvgfbvahgfbfhgrfgbgunh')

# Database configuration: prefers a production database URI (e.g., PostgreSQL) 
database_url = os.environ.get('DATABASE_URL', 'sqlite:///site.db') # Fallback for local testing only

# CRITICAL FIX: Change 'postgres://' to 'postgresql://' for SQLAlchemy/psycopg2 compatibility.
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://") # <<< COMPLETED FIX

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# --- Load ML Model and Vectorizer ---
try:
    # Use pathlib to get the path relative to the current file
    base_dir = pathlib.Path(__file__).parent
    model_path = base_dir / 'url_model.joblib'
    vectorizer_path = base_dir / 'url_vectorizer.joblib'

    url_model = joblib.load(model_path)
    url_vectorizer = joblib.load(vectorizer_path)
    print("Machine learning model and vectorizer loaded successfully.")
except Exception as e:
    print(f"Error loading ML model/vectorizer: {e}", file=sys.stderr)
    # Use dummy objects in case of failure to allow the app to run (but analysis will fail)
    class DummyModel:
        def predict(self, X): return ['Legitimate'] * len(X)
        def predict_proba(self, X): return [[0.9, 0.1]] * len(X)
    class DummyVectorizer:
        def transform(self, X): return [0] * len(X)
    url_model = DummyModel()
    url_vectorizer = DummyVectorizer()
    
# --- Database Models ---

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(60), nullable=False) # <<< CHANGED COLUMN NAME
    is_admin = db.Column(db.Boolean, default=False)
    history = db.relationship('History', backref='owner', lazy=True)

    # Helper method to check password
    def check_password(self, password): # <<< NEW METHOD
        return bcrypt.check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"User('{self.email}', Admin: {self.is_admin})"

class History(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.Text, nullable=False)
    result = db.Column(db.String(20), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True) # Optional for unauthenticated checks

    def __repr__(self):
        return f"History('{self.url}', '{self.result}')"

# --- Feature Extraction Function (Assuming this remains unchanged) ---

def extract_features(url):
    # This is a simplified function placeholder. 
    # The actual features used by your ML model are not fully defined here,
    # but the vectorizer is assumed to handle the primary URL feature.
    
    # Example feature (length)
    length = len(url)
    
    # Example feature (contains common phishing keywords)
    keywords = ['login', 'verify', 'update', 'security']
    keyword_count = sum(1 for k in keywords if k in url.lower())
    
    # The vectorizer (loaded from joblib) expects a list of strings
    vectorized_features = url_vectorizer.transform([url])
    
    # Combine vectorized features with other hand-engineered features if necessary
    # For a simple URL vectorizer, the combined feature might just be the vectorized form
    # If the model expects *only* the vectorized feature, return that.
    # Assuming the model expects only the single vectorized feature set:
    return vectorized_features


# --- Routes ---

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

        # <<< SECURITY FIX: HASH PASSWORD
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
        
        # <<< SECURITY FIX: CHECK HASHED PASSWORD
        # user exists AND the password is correct
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
            # 1. Feature Extraction
            features = extract_features(url_to_check)
            
            # 2. Prediction
            prediction = url_model.predict(features)[0]
            probability = url_model.predict_proba(features)[0]
            
            # Determine result and confidence
            result = 'Phishing' if prediction == 1 else 'Legitimate'
            confidence = max(probability) * 100
            
            # 3. Save History
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
            # Fallback to homepage or detailed error page
            return redirect(url_for('index'))
    
    return redirect(url_for('index'))

@app.route("/dashboard")
@login_required
def dashboard():
    # Only show history for the current user
    history = History.query.filter_by(user_id=current_user.id).order_by(History.timestamp.desc()).all()
    
    # Calculate stats for the chart
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
        
    # Get all history entries from all users
    history = History.query.order_by(History.timestamp.desc()).all()
    
    # Calculate global stats (or admin-specific stats if needed)
    # Total analysis count
    total_checks = History.query.count()
    
    # User stats
    total_users = User.query.count()
    
    return render_template('admin.html', 
                           title='Admin Panel', 
                           history=history,
                           total_checks=total_checks,
                           total_users=total_users)


# --- CLI Commands for Deployment Setup ---

@app.cli.command("init-db-admin")
def init_db_admin():
    """Initializes the database tables and creates a default admin user."""
    with app.app_context():
        try:
            db.create_all()
            print("Database tables created successfully.")

            # Load admin credentials from environment variables
            admin_email = os.environ.get('ADMIN_EMAIL', 'Adp9550@gmail.com')
            admin_password = os.environ.get('ADMIN_PASSWORD', 'ADp95220')
            
            if not User.query.filter_by(email=admin_email).first():
                # <<< SECURITY FIX: HASH PASSWORD BEFORE STORAGE
                hashed_password = bcrypt.generate_password_hash(admin_password).decode('utf-8')
                
                admin_user = User(name="Admin User", email=admin_email, password_hash=hashed_password, is_admin=True) # <<< USE password_hash
                db.session.add(admin_user)
                db.session.commit()
                print(f"Default admin user '{admin_email}' created (Password: '{admin_password}').")
                print("!!! WARNING: Ensure ADMIN_EMAIL and ADMIN_PASSWORD environment variables are set securely in production !!!")
            else:
                print(f"Admin user '{admin_email}' already exists. Skipping creation.")
                
        except Exception as e:
            print(f"ERROR: Database initialization failed. Ensure your database is accessible. Details: {e}", file=sys.stderr)
            sys.exit(1)

# --- Local Development Entry Point (Vercel ignores this) ---
if __name__ == '__main__':
    # This block is for local development only. Vercel uses the 'app' object directly.
    print("Running Flask app in local development mode.")
    # The application is now ready to be run by a WSGI server (like Gunicorn) or locally via 'flask run'.
    app.run(debug=True) # Note: Set debug=False for actual production use
I have updated your `app.py` code to implement **secure password hashing** using `Flask-Bcrypt` (the necessary library for this must be added to your `requirements.txt`). This fixes the critical security vulnerability of storing passwords in plain text.

The PostgreSQL URL fix for `postgres://` to `postgresql://` was already correctly implemented in the code you provided, so it was preserved.

## Updated `app.py` Code

**Note:** For this code to run, you **must** add `Flask-Bcrypt` to your `requirements.txt`.

```python
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
from flask_bcrypt import Bcrypt # 🔑 ADDED: Import for secure password hashing

# Attempt to import psycopg2 to ensure the necessary driver is available in the environment
try:
    import psycopg2 
except ImportError:
    # This is fine; Defang will install it from requirements.txt
    pass

# --- Initialize Flask App and Configuration ---

app = Flask(__name__)

# Load configuration from environment variables (crucial for deployment)
# SECRET_KEY must be a long, random, and unique string.
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'vcghvuegfjhvgfbvahgfbfhgrfgbgunh')

# Database configuration: prefers a production database URI (e.g., PostgreSQL) 
database_url = os.environ.get('DATABASE_URL', 'sqlite:///site.db') # Fallback for local testing only

# CRITICAL FIX: Change 'postgres://' to 'postgresql://' for SQLAlchemy/psycopg2 compatibility.
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app) # 🔑 ADDED: Initialize Bcrypt for hashing

# Initialize Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
login_manager.login_message = 'Please log in to access this page.'

# --- Database Models ---

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    # 🔑 CHANGED: Renamed column to store the hashed password
    password_hash = db.Column(db.String(200), nullable=False) 
    is_admin = db.Column(db.Boolean, default=False)

    history = db.relationship('URLHistory', backref='owner', lazy=True, cascade='all, delete-orphan')
    
    # 🔑 ADDED: Helper method to check the stored hash against the user's input password
    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)


class URLHistory(db.Model):
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

# Resolve the path relative to the current file location (required for Vercel deployment)
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
    print("CRITICAL ERROR: ML model files (url_model.joblib or url_vectorizer.joblib) not found.")
    # Exit gracefully if deployed, but allow the app to run for local dev if necessary
    if os.environ.get('VERCEL'):
        sys.exit(1)
except Exception as e:
    print(f"CRITICAL ERROR loading ML files: {e}")
    if os.environ.get('VERCEL'):
        sys.exit(1)

# --- Feature Extraction Function ---

def extract_features(url: str) -> str:
    """
    Returns the raw URL string for the loaded vectorizer to process.
    The actual feature extraction is handled by the pre-trained vectorizer.
    """
    return url

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
        flash("Model not loaded. Cannot perform prediction.", "danger")
        return redirect(url_for('index'))

    raw_url = request.form.get('url_input', '').strip()
    
    if not raw_url:
        flash("Please enter a URL to analyze.", "warning")
        return redirect(url_for('index'))
    
    # Prepare and predict
    url_to_predict = extract_features(raw_url)
    try:
        url_vectorized = url_vectorizer.transform([url_to_predict])
        # Prediction result: 0 for Legitimate, 1 for Phishing
        prediction = url_model.predict(url_vectorized)[0]
        result = 'Legitimate' if prediction == 0 else 'Phishing'
    except Exception as e:
        print(f"Prediction failed: {e}")
        flash("Prediction service temporarily unavailable.", "danger")
        result = 'Unknown'

    # Save to history if a valid user is logged in
    if current_user.is_authenticated:
        try:
            new_entry = URLHistory(
                user_id=current_user.id, 
                url=raw_url, 
                result=result
            )
            db.session.add(new_entry)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print(f"Error saving history: {e}")
            flash("Could not save prediction history to the database.", "warning")

    return render_template('result.html', url=raw_url, result=result)

@app.route('/dashboard')
@login_required
def dashboard():
    """Renders the user's personal dashboard with history and statistics."""
    
    # 1. Fetch user's history
    user_history = URLHistory.query.filter_by(user_id=current_user.id).order_by(URLHistory.timestamp.desc()).all()
    
    # 2. Calculate statistics for chart
    # Use SQLAlchemy's func.count for aggregation
    stats = db.session.query(
        URLHistory.result, 
        func.count(URLHistory.result)
    ).filter(URLHistory.user_id == current_user.id).group_by(URLHistory.result).all()
    
    data = {'Legitimate': 0, 'Phishing': 0}
    for result, count in stats:
        data[result] = count

    # Format data for Chart.js in the template
    chart_data = [data['Phishing'], data['Legitimate']]
    
    return render_template('dashboard.html', history=user_history, chart_data=chart_data)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        user = User.query.filter_by(email=email).first()
        
        # 🔑 CHANGED: Using bcrypt.check_password_hash via the User model's check_password method
        if user and user.check_password(password):
            login_user(user, remember=True)
            flash(f"Login successful. Welcome back, {user.name}!", "success")
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        else:
            flash("Login failed. Check your email and password.", "danger")
            
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handles new user registration."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        # Check if user already exists
        if User.query.filter_by(email=email).first():
            flash("Email already registered. Please log in.", "warning")
            return redirect(url_for('login'))
        
        try:
            # 🔑 CHANGED: Hash the password before storage
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            
            # 🔑 CHANGED: Pass the hash to the 'password_hash' column
            new_user = User(name=name, email=email, password_hash=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash("Account created successfully! Please log in.", "success")
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f"Registration failed due to a database error: {e}", "danger")
            
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    """Logs out the current user."""
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for('index'))

@app.route('/admin')
@login_required
def admin():
    """Renders the admin panel (only accessible to admin users)."""
    if not current_user.is_admin:
        flash("Unauthorized access! You must be an administrator.", "danger")
        return redirect(url_for('dashboard'))
        
    users = User.query.all()
    # Fetch all history for admin view, ordered by timestamp
    history = URLHistory.query.order_by(URLHistory.timestamp.desc()).all()
    
    return render_template('admin.html', users=users, history=history)

# --- Flask Command Line Interface (CLI) Setup ---

@app.cli.command("init-db-admin")
def initialize_database_and_admin():
    """
    Initializes the database structure and creates the default admin user.
    Run this manually after deployment using 'flask init-db-admin'.
    """
    with app.app_context():
        try:
            db.create_all()
            print("Database structure created successfully.")

            # Load admin credentials from environment variables
            # NOTE: These fallback values are still insecure and should be changed in production env vars.
            admin_email = os.environ.get('ADMIN_EMAIL', 'Adp9550@gmail.com')
            admin_password = os.environ.get('ADMIN_PASSWORD', 'ADp95220')
            
            if not User.query.filter_by(email=admin_email).first():
                # 🔑 CHANGED: Hash the admin password before storage
                hashed_password = bcrypt.generate_password_hash(admin_password).decode('utf-8')
                
                # 🔑 CHANGED: Pass the hash to the 'password_hash' column
                admin_user = User(name="Admin User", email=admin_email, password_hash=hashed_password, is_admin=True)
                db.session.add(admin_user)
                db.session.commit()
                print(f"Default admin user '{admin_email}' created.")
                print("!!! WARNING: Ensure ADMIN_EMAIL and ADMIN_PASSWORD environment variables are set securely in production !!!")
            else:
                print(f"Admin user '{admin_email}' already exists. Skipping creation.")
                
        except Exception as e:
            print(f"ERROR: Database initialization failed. Ensure your database is accessible. Details: {e}", file=sys.stderr)
            sys.exit(1)

# --- Local Development Entry Point (Vercel ignores this) ---
if __name__ == '__main__':
    # This block is for local development only. Vercel uses the 'app' object directly.
    print("Running Flask app in local development mode.")
    # The application is now ready to be run by a WSGI server (like Gunicorn) or locally via 'flask run'.
    app.run(debug=True)