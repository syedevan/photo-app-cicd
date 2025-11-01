import os
from flask import Flask, redirect, url_for, request, render_template
from azure.storage.blob import BlobServiceClient
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func

# --- 1. AZURE CONFIGURATION ---
# App Name
app = Flask(__name__)

# Blob Storage Connection
connect_str = os.getenv("AZURE_STORAGE_CONNECTION_STRING")
CONTAINER_NAME = os.getenv("CONTAINER_NAME", "photos")
blob_service_client = BlobServiceClient.from_connection_string(connect_str)
container_client = blob_service_client.get_container_client(CONTAINER_NAME)

try:
    container_client.create_container()
except Exception:
    # Container likely already exists
    pass

# --- 2. DATABASE CONFIGURATION ---
# Database URI is set as an Application Setting in Azure
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- 3. DATABASE MODEL ---
class PhotoMetadata(db.Model):
    # Table to store photo metadata and vote counts
    id = db.Column(db.Integer, primary_key=True)
    blob_name = db.Column(db.String(255), unique=True, nullable=False)
    likes = db.Column(db.Integer, default=0)
    dislikes = db.Column(db.Integer, default=0)

    def __repr__(self):
        return f'<Photo {self.blob_name}>'

# --- 4. APP ROUTES ---

@app.route('/')
def index():
    # List all blobs and get their metadata from the DB
    
    # 1. Get list of blobs from storage
    blob_list = container_client.list_blobs()
    
    # 2. Get all photo metadata from the database
    metadata_list = PhotoMetadata.query.all()
    metadata_dict = {m.blob_name: m for m in metadata_list}

    photos_with_metadata = []
    
    for blob in blob_list:
        if blob.name.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp')):
            # Get public URL for the blob
            blob_client = container_client.get_blob_client(blob)
            photo_url = blob_client.url

            # Get metadata or use defaults if not in DB yet
            metadata = metadata_dict.get(blob.name, PhotoMetadata(blob_name=blob.name))
            
            photos_with_metadata.append({
                'name': blob.name,
                'url': photo_url,
                'likes': metadata.likes,
                'dislikes': metadata.dislikes
            })

    return render_template('index.html', photo_url='/photos/', blob_list=photos_with_metadata)


@app.route('/upload_photo', methods=['POST'])
def upload_photo():
    file = request.files.get('file_upload')

    if not file or file.filename == '':
        return redirect(url_for('index'))

    # 1. Upload file to Blob Storage
    blob_client = container_client.get_blob_client(file.filename)
    blob_client.upload_blob(file, overwrite=True)

    # 2. Create entry in the database if it doesn't exist (initializes likes/dislikes to 0)
    metadata = PhotoMetadata.query.filter_by(blob_name=file.filename).first()
    if not metadata:
        metadata = PhotoMetadata(blob_name=file.filename)
        db.session.add(metadata)
        db.session.commit()

    return redirect(url_for('index'))

@app.route('/delete/<blob_name>', methods=['POST'])
def delete_photo(blob_name):
    # 1. Delete from Blob Storage
    blob_client = container_client.get_blob_client(blob_name)
    try:
        blob_client.delete_blob()
    except Exception as e:
        print(f"Error deleting blob: {e}")

    # 2. Delete from Database
    metadata = PhotoMetadata.query.filter_by(blob_name=blob_name).first()
    if metadata:
        db.session.delete(metadata)
        db.session.commit()

    return redirect(url_for('index'))

@app.route('/vote/<blob_name>/<action>', methods=['POST'])
def vote(blob_name, action):
    # Retrieve or create metadata for the photo
    metadata = PhotoMetadata.query.filter_by(blob_name=blob_name).first()
    if not metadata:
        # Should not happen often if upload works, but handles missing metadata
        metadata = PhotoMetadata(blob_name=blob_name)
        db.session.add(metadata)
        
    if action == 'like':
        metadata.likes += 1
    elif action == 'dislike':
        metadata.dislikes += 1
    
    db.session.commit()
    return redirect(url_for('index'))