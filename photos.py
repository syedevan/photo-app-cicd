# =============================================================================
# photos.py - Cloud-Native Photo Sharing Web App with Secure RBAC
# =============================================================================

from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt 
import pymysql.cursors
import os, json
from werkzeug.utils import secure_filename
from azure.storage.blob import BlobServiceClient
import uuid 

# =============================================================================
# 1. CONFIGURATION AND INITIALIZATION
# =============================================================================

app = Flask(__name__)
# !! Reads SECRET_KEY from Azure App Service Environment Variable !!
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY') 

# --- Azure Blob Storage Config ---
# NOTE: Connection string is loaded from environment variables for security.
AZURE_STORAGE_CONNECTION_STRING = os.environ.get('AZURE_STORAGE_CONNECTION_STRING', 'DefaultEndpointsProtocol=https;AccountName=photosappproject;AccountKey=tmDIqOhS1AlN37pprKbZ1bkTvdOeEnO3VqSOoWDxCvUvntYqzkAW0H9ekDGYC8YQF0mJrQRarnF/+AStzK0xVQ==;EndpointSuffix=core.windows.net')
AZURE_CONTAINER_NAME = os.environ.get('AZURE_CONTAINER_NAME', 'photos') 
blob_service_client = BlobServiceClient.from_connection_string(AZURE_STORAGE_CONNECTION_STRING)
container_client = blob_service_client.get_container_client(AZURE_CONTAINER_NAME)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# --- MySQL Database Config (Reads from Environment Variables) ---
DB_CONFIG = {
    'host': os.environ.get('DB_HOST', 'localhost'),
    'user': os.environ.get('DB_USER', 'root'),
    'password': os.environ.get('DB_PASS', ''),
    'db': os.environ.get('DB_NAME', 'flexibleserverdb'), # Using 'flexibleserverdb' as per last successful connection
    'cursorclass': pymysql.cursors.DictCursor
}

def get_db_cursor():
    """Establishes secure DB connection and returns cursor and connection object."""
    db_conn = pymysql.connect(**DB_CONFIG)
    cursor = db_conn.cursor()
    return cursor, db_conn

# --- Flask Extensions Initialization ---
bcrypt = Bcrypt(app) 
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' 
login_manager.login_message = 'Please log in to access this page.' 


# =============================================================================
# 2. USER AUTHENTICATION MODEL AND LOADER
# =============================================================================

class User(UserMixin):
    """Custom User class for Flask-Login, mirroring the 'users' table."""
    def __init__(self, user_id, email, user_role, password_hash=None):
        self.id = user_id
        self.email = email
        self.user_role = user_role
        self.password_hash = password_hash 

    def is_creator(self):
        """Used for Role-Based Access Control (RBAC)."""
        return self.user_role == 'creator'
    
# --- User Loader function for Flask-Login ---
@login_manager.user_loader
def load_user(user_id):
    """Reloads user object from the database using the session ID."""
    cursor, db_conn = get_db_cursor()
    try:
        cursor.execute("SELECT id, email, user_role FROM users WHERE id = %s", (user_id,))
        user_data = cursor.fetchone()
        if user_data:
            return User(user_data['id'], user_data['email'], user_data['user_role'])
    except Exception:
        pass
    finally:
        db_conn.close()
    return None


# =============================================================================
# 3. AUTHENTICATION ROUTES (LOGIN, REGISTER, LOGOUT)
# =============================================================================

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Allows new users to register as a Consumer or Creator (with secret code)."""
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        # Simple role assignment: Use a secret code for Creator access
        secret_code = request.form.get('secret_code') 
        user_role = 'creator' if secret_code == 'SECURECREATORCODE' else 'consumer'
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        cursor, db_conn = get_db_cursor()
        try:
            cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
            if cursor.fetchone():
                flash('Email already registered!', 'danger')
                return render_template('register.html')
                
            cursor.execute(
                "INSERT INTO users (email, password_hash, user_role) VALUES (%s, %s, %s)",
                (email, hashed_password, user_role)
            )
            db_conn.commit()
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f'An error occurred during registration. {e}', 'danger')
        finally:
            db_conn.close()
            
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login and session creation."""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        cursor, db_conn = get_db_cursor()
        try:
            # Select password_hash along with other user details for verification
            cursor.execute(
                "SELECT id, email, user_role, password_hash FROM users WHERE email = %s", 
                (email,)
            )
            user_data = cursor.fetchone()
            
            if user_data:
                # Create a User object with the hash for bcrypt check
                user = User(
                    user_id=user_data['id'], 
                    email=user_data['email'], 
                    user_role=user_data['user_role'], 
                    password_hash=user_data['password_hash']
                )
                
                if bcrypt.check_password_hash(user.password_hash, password):
                    login_user(user) 
                    flash('Logged in successfully.', 'success')
                    return redirect(url_for('index'))
                else:
                    flash('Invalid email or password.', 'danger')
            else:
                flash('Invalid email or password.', 'danger')
        except Exception as e:
            flash(f'An error occurred during login. {e}', 'danger')
        finally:
            db_conn.close()
            
    return render_template('login.html')

@app.route('/logout')
@login_required 
def logout():
    """Handles user session termination."""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


# =============================================================================
# 4. CORE APPLICATION ROUTES (RBAC & METADATA)
# =============================================================================

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- Index/Gallery Route (Consumer View) ---
@app.route('/')
@app.route('/index')
def index():
    """Displays the photo gallery with all metadata (accessible to everyone)."""
    cursor, db_conn = get_db_cursor()
    
    # FIX: Use COALESCE to ensure likes/dislikes are always a number (0)
    metadata_query = """
        SELECT 
            id, blob_name, blob_url, title, caption, location, people_present, creator_id, upload_date,
            COALESCE(likes, 0) AS likes,          
            COALESCE(dislikes, 0) AS dislikes     
        FROM photos_metadata 
        ORDER BY upload_date DESC
    """
    cursor.execute(metadata_query)
    photos_list_metadata = cursor.fetchall()
    
    db_conn.close()
    
    return render_template('index.html', photos=photos_list_metadata)


# --- Upload Route (Creator View - RBAC Enforced) ---
@app.route('/upload_photo', methods=['GET', 'POST'])
@login_required 
def upload_photo():
    """Handles Creator-only uploads with full metadata capture."""
    
    # RBAC Check: Only Creators can proceed
    if not current_user.is_creator():
        flash('Access Denied: Only Creators can upload photos.', 'warning')
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        if 'file' not in request.files or request.files['file'].filename == '':
            flash('No file selected.', 'danger')
            return redirect(request.url)
            
        file = request.files['file']
        
        if file and allowed_file(file.filename):
            # 1. Upload to Azure Blob Storage
            original_filename = secure_filename(file.filename)
            file_extension = original_filename.rsplit('.', 1)[1]
            blob_name = f"{uuid.uuid4().hex}.{file_extension}"
            blob_client = container_client.get_blob_client(blob_name)
            
            file.seek(0)
            blob_client.upload_blob(file, overwrite=True)
            blob_url = blob_client.url

            # 2. Get Metadata from Form (New Requirement)
            title = request.form.get('title', 'Untitled')
            caption = request.form.get('caption', '')
            location = request.form.get('location', '')
            people_present = request.form.get('people_present', '')
            creator_id = current_user.id # Capture the creator's ID

            # 3. Save metadata to MySQL
            cursor, db_conn = get_db_cursor()
            try:
                metadata_query = """
                    INSERT INTO photos_metadata 
                    (blob_name, blob_url, title, caption, location, people_present, creator_id)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """
                cursor.execute(metadata_query, (
                    blob_name, blob_url, title, caption, location, people_present, creator_id
                ))
                db_conn.commit()
                flash('Photo uploaded successfully with metadata!', 'success')
            except Exception as e:
                flash('Error saving photo metadata.', 'danger')
            finally:
                db_conn.close()

            return redirect(url_for('index'))
            
    return render_template('upload.html')


# --- Delete Route (RBAC Enforced) ---
@app.route('/delete_photo/<string:blob_name>', methods=['POST'])
@login_required
def delete_photo(blob_name):
    """Deletes a photo and its metadata. Restricted to Creators."""
    
    if not current_user.is_creator():
        flash('Access Denied: Only Creators can delete photos.', 'warning')
        return redirect(url_for('index'))

    # Delete from Azure Blob Storage
    try:
        blob_client = container_client.get_blob_client(blob_name)
        blob_client.delete_blob()
    except Exception as e:
        flash(f"Error deleting blob.", 'danger')
        
    # Delete from MySQL
    cursor, db_conn = get_db_cursor()
    try:
        cursor.execute("DELETE FROM photos_metadata WHERE blob_name = %s", (blob_name,))
        db_conn.commit()
        flash("Photo successfully deleted.", 'success')
    except Exception as e:
        flash("Error deleting metadata.", 'danger')
    finally:
        db_conn.close()

    return redirect(url_for('index'))


# --- Like/Dislike Routes (Consumer Functionality, requires Login) ---
@app.route('/like_photo/<string:blob_name>', methods=['POST'])
@login_required 
def like_photo(blob_name):
    """Increments the like count for a photo."""
    cursor, db_conn = get_db_cursor()
    try:
        # Simple increment query
        cursor.execute("UPDATE photos_metadata SET likes = COALESCE(likes, 0) + 1 WHERE blob_name = %s", (blob_name,))
        db_conn.commit()
        flash('Photo liked!', 'success')
    except Exception as e:
        flash(f'Error recording like. {e}', 'danger')
    finally:
        db_conn.close()
    return redirect(url_for('index'))

@app.route('/dislike_photo/<string:blob_name>', methods=['POST'])
@login_required 
def dislike_photo(blob_name):
    """Increments the dislike count for a photo."""
    cursor, db_conn = get_db_cursor()
    try:
        # Simple increment query
        cursor.execute("UPDATE photos_metadata SET dislikes = COALESCE(dislikes, 0) + 1 WHERE blob_name = %s", (blob_name,))
        db_conn.commit()
        flash('Photo disliked!', 'success')
    except Exception as e:
        flash(f'Error recording dislike. {e}', 'danger')
    finally:
        db_conn.close()
    return redirect(url_for('index'))

# --- Final app run statement ---
if __name__ == '__main__':
    # For Azure deployment, App Service handles the process
    # app.run(debug=True)
    pass
