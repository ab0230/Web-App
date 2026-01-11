from flask import Flask, request, jsonify, send_from_directory, session
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import pyodbc
import os
import uuid
from functools import wraps
import jwt
import base64
from io import BytesIO
from PIL import Image, ImageDraw, ImageFont
from azure.storage.blob import BlobServiceClient, PublicAccess

app = Flask(__name__, static_folder='static', static_url_path='')
app.config['SECRET_KEY'] = 'a1b2c3d4e5f6789abcdef1234567890abcdef1234567890abcdef1234567890'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # Increased to 100MB for videos
CORS(app)

AZURE_SQL_SERVER = 'abdur123.database.windows.net'
AZURE_SQL_DATABASE = 'Db1'
AZURE_SQL_USERNAME = 'abdurrehman123'
AZURE_SQL_PASSWORD = 'Abdur123'

AZURE_STORAGE_CONNECTION_STRING = (
    'DefaultEndpointsProtocol=https;'
    'AccountName=rehman;'
    'AccountKey=0JA/hD+D5CcMceIff+18fWsw3llnd4L4fprunGnNoVQuTOrdmMgvJgWrGHDyMQIHOsQRMmqF8pWJ+AStdkay8Q==;'
    'EndpointSuffix=core.windows.net'
)
AZURE_STORAGE_CONTAINER = 'photos'

CONNECTION_STRING = (
    f"Driver={{ODBC Driver 18 for SQL Server}};"
    f"Server=tcp:{AZURE_SQL_SERVER},1433;"
    f"Database={AZURE_SQL_DATABASE};"
    f"Uid={AZURE_SQL_USERNAME};"
    f"Pwd={AZURE_SQL_PASSWORD};"
    f"Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;"
)

# Allowed file extensions
ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
ALLOWED_VIDEO_EXTENSIONS = {'mp4', 'mov', 'avi', 'wmv', 'flv', 'webm', 'mkv'}

# Blob Initialization
try:
    blob_service_client = BlobServiceClient.from_connection_string(AZURE_STORAGE_CONNECTION_STRING)
    container_client = blob_service_client.get_container_client(AZURE_STORAGE_CONTAINER)

    if not container_client.exists():
        container_client.create_container(public_access=PublicAccess.Blob)
    else:
        container_client.set_container_access_policy(
            signed_identifiers={},
            public_access=PublicAccess.Blob
        )

    print("[OK] Blob container ready and public")

except Exception as e:
    print(f"[ERROR] Blob initialization failed: {e}")
    blob_service_client = None


def get_db_connection():
    try:
        return pyodbc.connect(CONNECTION_STRING)
    except Exception as e:
        print(f"[ERROR] Database connection failed: {e}")
        return None


def allowed_file(filename, file_type='image'):
    if '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    if file_type == 'image':
        return ext in ALLOWED_IMAGE_EXTENSIONS
    elif file_type == 'video':
        return ext in ALLOWED_VIDEO_EXTENSIONS
    return False


def init_database():
    """Initialize database tables"""
    conn = get_db_connection()
    if not conn:
        return False
    
    cursor = conn.cursor()
    
    try:
        # Users table
        cursor.execute("""
        IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='users' AND xtype='U')
        CREATE TABLE users (
            id INT IDENTITY(1,1) PRIMARY KEY,
            username NVARCHAR(50) UNIQUE NOT NULL,
            email NVARCHAR(100) UNIQUE NOT NULL,
            password_hash NVARCHAR(255) NOT NULL,
            role NVARCHAR(20) NOT NULL CHECK (role IN ('creator', 'consumer')),
            created_at DATETIME DEFAULT GETDATE(),
            profile_image NVARCHAR(500)
        )
        """)
        
        # Media table
        cursor.execute("""
        IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='media' AND xtype='U')
        CREATE TABLE media (
            id INT IDENTITY(1,1) PRIMARY KEY,
            user_id INT NOT NULL,
            title NVARCHAR(200) NOT NULL,
            caption NVARCHAR(1000),
            location NVARCHAR(200),
            people_present NVARCHAR(500),
            blob_url NVARCHAR(500) NOT NULL,
            thumbnail_url NVARCHAR(500),
            media_type NVARCHAR(20) NOT NULL CHECK (media_type IN ('image', 'video')),
            upload_date DATETIME DEFAULT GETDATE(),
            views INT DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """)
        
        # Comments table
        cursor.execute("""
        IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='comments' AND xtype='U')
        CREATE TABLE comments (
            id INT IDENTITY(1,1) PRIMARY KEY,
            media_id INT NOT NULL,
            user_id INT NOT NULL,
            comment_text NVARCHAR(1000) NOT NULL,
            created_at DATETIME DEFAULT GETDATE(),
            FOREIGN KEY (media_id) REFERENCES media(id) ON DELETE NO ACTION,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE NO ACTION
        )
        """)
        
        # Ratings table
        cursor.execute("""
        IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='ratings' AND xtype='U')
        CREATE TABLE ratings (
            id INT IDENTITY(1,1) PRIMARY KEY,
            media_id INT NOT NULL,
            user_id INT NOT NULL,
            rating INT NOT NULL CHECK (rating >= 1 AND rating <= 5),
            created_at DATETIME DEFAULT GETDATE(),
            UNIQUE (media_id, user_id),
            FOREIGN KEY (media_id) REFERENCES media(id) ON DELETE NO ACTION,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE NO ACTION
        )
        """)
        
        conn.commit()
        print("Database initialized successfully")
        return True
    except Exception as e:
        print(f"Database initialization error: {e}")
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()

# JWT token handling
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            if token.startswith('Bearer '):
                token = token[7:]
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = data
        except Exception as e:
            return jsonify({'error': 'Token is invalid'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated

# Helper function to upload to blob storage
def upload_to_blob(file, filename):
    """Upload file to Azure Blob Storage"""
    try:
        blob_client = blob_service_client.get_blob_client(container=AZURE_STORAGE_CONTAINER, blob=filename)
        blob_client.upload_blob(file, overwrite=True)
        return blob_client.url
    except Exception as e:
        print(f"Blob upload error: {e}")
        return None

def create_thumbnail(file):
    """Create a thumbnail from uploaded image"""
    try:
        img = Image.open(file)
        img.thumbnail((400, 400))
        thumb_io = BytesIO()
        img.save(thumb_io, format=img.format or 'JPEG')
        thumb_io.seek(0)
        return thumb_io
    except Exception as e:
        print(f"Thumbnail creation error: {e}")
        return None

def create_video_thumbnail(filename):
    """Create a placeholder thumbnail for videos"""
    try:
        # Create a 400x400 image with a play button
        img = Image.new('RGB', (400, 400), color='#1a1a2e')
        draw = ImageDraw.Draw(img)
        
        # Draw a play button icon
        # Triangle coordinates for play button
        play_button = [(150, 120), (280, 200), (150, 280)]
        draw.polygon(play_button, fill='#ff6b6b')
        
        # Draw a circle around the play button
        draw.ellipse([100, 100, 300, 300], outline='#4ecdc4', width=5)
        
        # Add "VIDEO" text
        try:
            # Try to use a font, fallback to default if not available
            font = ImageFont.truetype("arial.ttf", 30)
        except:
            font = ImageFont.load_default()
        
        text = "VIDEO"
        # Get text bounding box for centering
        bbox = draw.textbbox((0, 0), text, font=font)
        text_width = bbox[2] - bbox[0]
        text_height = bbox[3] - bbox[1]
        
        # Draw text centered at bottom
        text_position = ((400 - text_width) // 2, 320)
        draw.text(text_position, text, fill='#f7f7f7', font=font)
        
        # Save to BytesIO
        thumb_io = BytesIO()
        img.save(thumb_io, format='JPEG')
        thumb_io.seek(0)
        return thumb_io
    except Exception as e:
        print(f"Video thumbnail creation error: {e}")
        return None

# Routes
@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/creator')
def creator_page():
    return send_from_directory('static', 'creator.html')

@app.route('/consumer')
def consumer_page():
    return send_from_directory('static', 'consumer.html')

# Authentication Routes
@app.route('/api/register', methods=['POST'])
def register():
    """Register a new user"""
    data = request.get_json()
    
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    role = data.get('role', 'consumer')
    
    if not all([username, email, password]):
        return jsonify({'error': 'Missing required fields'}), 400
    
    if role not in ['creator', 'consumer']:
        return jsonify({'error': 'Invalid role'}), 400
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    
    cursor = conn.cursor()
    
    try:
        # Check if user exists
        cursor.execute("SELECT id FROM users WHERE username = ? OR email = ?", (username, email))
        if cursor.fetchone():
            return jsonify({'error': 'Username or email already exists'}), 400
        
        # Hash password and insert user
        password_hash = generate_password_hash(password)
        cursor.execute(
            "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
            (username, email, password_hash, role)
        )
        conn.commit()
        
        return jsonify({'message': 'User registered successfully'}), 201
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/login', methods=['POST'])
def login():
    """Login user"""
    data = request.get_json()
    
    username = data.get('username')
    password = data.get('password')
    
    if not all([username, password]):
        return jsonify({'error': 'Missing credentials'}), 400
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "SELECT id, username, email, password_hash, role FROM users WHERE username = ?",
            (username,)
        )
        user = cursor.fetchone()
        
        if not user or not check_password_hash(user[3], password):
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Generate JWT token
        token = jwt.encode({
            'user_id': user[0],
            'username': user[1],
            'role': user[4],
            'exp': datetime.utcnow() + timedelta(days=7)
        }, app.config['SECRET_KEY'], algorithm='HS256')
        
        return jsonify({
            'token': token,
            'user': {
                'id': user[0],
                'username': user[1],
                'email': user[2],
                'role': user[4]
            }
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/media/<int:media_id>', methods=['DELETE'])
@token_required
def delete_media(current_user, media_id):
    """Delete a media item (creator only, own media only)"""
    if current_user['role'] != 'creator':
        return jsonify({'error': 'Only creators can delete media'}), 403
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    
    cursor = conn.cursor()
    
    try:
        # Check if media belongs to user
        cursor.execute("SELECT user_id, blob_url, thumbnail_url FROM media WHERE id = ?", (media_id,))
        media = cursor.fetchone()
        
        if not media:
            return jsonify({'error': 'Media not found'}), 404
        
        if media[0] != current_user['user_id']:
            return jsonify({'error': 'Unauthorized'}), 403
        
        # Delete from database (comments and ratings first to avoid foreign key issues)
        cursor.execute("DELETE FROM comments WHERE media_id = ?", (media_id,))
        cursor.execute("DELETE FROM ratings WHERE media_id = ?", (media_id,))
        cursor.execute("DELETE FROM media WHERE id = ?", (media_id,))
        conn.commit()
        
        # Try to delete blobs (optional, don't fail if it errors)
        try:
            if media[1]:  # blob_url
                blob_name = media[1].split('/')[-1]
                blob_client = blob_service_client.get_blob_client(container=AZURE_STORAGE_CONTAINER, blob=blob_name)
                blob_client.delete_blob()
            
            if media[2]:  # thumbnail_url
                thumb_name = media[2].split('/')[-1]
                thumb_client = blob_service_client.get_blob_client(container=AZURE_STORAGE_CONTAINER, blob=thumb_name)
                thumb_client.delete_blob()
        except Exception as e:
            print(f"Blob deletion error: {e}")
        
        return jsonify({'message': 'Media deleted successfully'}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/api/media', methods=['GET'])
def get_media():
    """Get all media (photos and videos) with pagination, search, and user filter"""
    page = int(request.args.get('page', 1))
    limit = int(request.args.get('limit', 12))
    search = request.args.get('search', '')
    media_type = request.args.get('type', '')
    user_id = request.args.get('user_id', '')
    
    offset = (page - 1) * limit
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    
    cursor = conn.cursor()
    
    try:
        # Build query with search, type filter, and user filter
        base_query = """
            SELECT m.id, m.title, m.caption, m.location, m.people_present, 
                   m.blob_url, m.thumbnail_url, m.media_type, m.upload_date, m.views,
                   u.username, u.id as user_id,
                   (SELECT AVG(CAST(rating AS FLOAT)) FROM ratings WHERE media_id = m.id) as avg_rating,
                   (SELECT COUNT(*) FROM comments WHERE media_id = m.id) as comment_count
            FROM media m
            JOIN users u ON m.user_id = u.id
            WHERE 1=1
        """
        
        params = []
        
        if search:
            base_query += " AND (m.title LIKE ? OR m.caption LIKE ? OR m.location LIKE ? OR m.people_present LIKE ?)"
            search_term = f'%{search}%'
            params.extend([search_term, search_term, search_term, search_term])
        
        if media_type:
            base_query += " AND m.media_type = ?"
            params.append(media_type)
        
        if user_id:
            base_query += " AND m.user_id = ?"
            params.append(int(user_id))
        
        base_query += " ORDER BY m.upload_date DESC OFFSET ? ROWS FETCH NEXT ? ROWS ONLY"
        params.extend([offset, limit])
        
        cursor.execute(base_query, params)
        
        media_items = []
        for row in cursor.fetchall():
            media_items.append({
                'id': row[0],
                'title': row[1],
                'caption': row[2],
                'location': row[3],
                'people_present': row[4],
                'url': row[5],
                'thumbnail_url': row[6] or row[5],
                'media_type': row[7],
                'upload_date': row[8].isoformat() if row[8] else None,
                'views': row[9],
                'username': row[10],
                'user_id': row[11],
                'avg_rating': round(row[12], 1) if row[12] else 0,
                'comment_count': row[13]
            })
        
        # Get total count
        count_query = "SELECT COUNT(*) FROM media m WHERE 1=1"
        count_params = []
        
        if search:
            count_query += " AND (m.title LIKE ? OR m.caption LIKE ? OR m.location LIKE ? OR m.people_present LIKE ?)"
            search_term = f'%{search}%'
            count_params.extend([search_term, search_term, search_term, search_term])
        
        if media_type:
            count_query += " AND m.media_type = ?"
            count_params.append(media_type)
        
        if user_id:
            count_query += " AND m.user_id = ?"
            count_params.append(int(user_id))
        
        cursor.execute(count_query, count_params)
        total = cursor.fetchone()[0]
        
        return jsonify({
            'media': media_items,
            'total': total,
            'page': page,
            'pages': (total + limit - 1) // limit
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/media/<int:media_id>', methods=['GET'])
def get_media_item(media_id):
    """Get single media item details"""
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    
    cursor = conn.cursor()
    
    try:
        # Increment view count
        cursor.execute("UPDATE media SET views = views + 1 WHERE id = ?", (media_id,))
        
        # Get media details
        cursor.execute("""
            SELECT m.id, m.title, m.caption, m.location, m.people_present, 
                   m.blob_url, m.thumbnail_url, m.media_type, m.upload_date, m.views,
                   u.username, u.id as user_id,
                   (SELECT AVG(CAST(rating AS FLOAT)) FROM ratings WHERE media_id = m.id) as avg_rating
            FROM media m
            JOIN users u ON m.user_id = u.id
            WHERE m.id = ?
        """, (media_id,))
        
        row = cursor.fetchone()
        if not row:
            return jsonify({'error': 'Media not found'}), 404
        
        media_item = {
            'id': row[0],
            'title': row[1],
            'caption': row[2],
            'location': row[3],
            'people_present': row[4],
            'url': row[5],
            'thumbnail_url': row[6] or row[5],
            'media_type': row[7],
            'upload_date': row[8].isoformat() if row[8] else None,
            'views': row[9],
            'username': row[10],
            'user_id': row[11],
            'avg_rating': round(row[12], 1) if row[12] else 0
        }
        
        conn.commit()
        return jsonify(media_item), 200
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/media', methods=['POST'])
@token_required
def upload_media(current_user):
    """Upload a new photo or video (creators only)"""
    if current_user['role'] != 'creator':
        return jsonify({'error': 'Only creators can upload media'}), 403
    
    if 'media' not in request.files:
        return jsonify({'error': 'No media file provided'}), 400
    
    file = request.files['media']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # Determine media type
    file_ext = os.path.splitext(file.filename)[1].lower()
    is_video = file_ext.replace('.', '') in ALLOWED_VIDEO_EXTENSIONS
    is_image = file_ext.replace('.', '') in ALLOWED_IMAGE_EXTENSIONS
    
    if not is_video and not is_image:
        return jsonify({'error': 'Invalid file type. Supported: images (jpg, png, gif) and videos (mp4, mov, avi, webm)'}), 400
    
    media_type = 'video' if is_video else 'image'
    
    title = request.form.get('title', '')
    caption = request.form.get('caption', '')
    location = request.form.get('location', '')
    people_present = request.form.get('people_present', '')
    
    if not title:
        return jsonify({'error': 'Title is required'}), 400
    
    # Generate unique filename
    unique_filename = f"{uuid.uuid4()}{file_ext}"
    
    # Upload to blob storage
    file.seek(0)
    blob_url = upload_to_blob(file.read(), unique_filename)
    
    if not blob_url:
        return jsonify({'error': 'Failed to upload media'}), 500
    
    # Create thumbnail
    thumbnail_url = None
    if is_image:
        file.seek(0)
        thumbnail = create_thumbnail(file)
        if thumbnail:
            thumb_filename = f"thumb_{unique_filename}"
            thumbnail_url = upload_to_blob(thumbnail.read(), thumb_filename)
    else:
        # For videos, create a placeholder thumbnail
        video_thumbnail = create_video_thumbnail(unique_filename)
        if video_thumbnail:
            thumb_filename = f"thumb_{unique_filename}.jpg"
            thumbnail_url = upload_to_blob(video_thumbnail.read(), thumb_filename)
    
    # Save to database
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            INSERT INTO media (user_id, title, caption, location, people_present, blob_url, thumbnail_url, media_type)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (current_user['user_id'], title, caption, location, people_present, blob_url, thumbnail_url, media_type))
        
        conn.commit()
        media_id = cursor.execute("SELECT @@IDENTITY").fetchone()[0]
        
        return jsonify({
            'message': f'{media_type.capitalize()} uploaded successfully',
            'media_id': media_id,
            'media_type': media_type
        }), 201
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# Comments Routes
@app.route('/api/media/<int:media_id>/comments', methods=['GET'])
def get_comments(media_id):
    """Get comments for a media item"""
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            SELECT c.id, c.comment_text, c.created_at, u.username, u.id as user_id
            FROM comments c
            JOIN users u ON c.user_id = u.id
            WHERE c.media_id = ?
            ORDER BY c.created_at DESC
        """, (media_id,))
        
        comments = []
        for row in cursor.fetchall():
            comments.append({
                'id': row[0],
                'text': row[1],
                'created_at': row[2].isoformat() if row[2] else None,
                'username': row[3],
                'user_id': row[4]
            })
        
        return jsonify(comments), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/media/<int:media_id>/comments', methods=['POST'])
@token_required
def add_comment(current_user, media_id):
    """Add a comment to a media item"""
    data = request.get_json()
    comment_text = data.get('comment')
    
    if not comment_text:
        return jsonify({'error': 'Comment text is required'}), 400
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            INSERT INTO comments (media_id, user_id, comment_text)
            VALUES (?, ?, ?)
        """, (media_id, current_user['user_id'], comment_text))
        
        conn.commit()
        
        return jsonify({'message': 'Comment added successfully'}), 201
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# Ratings Routes
@app.route('/api/media/<int:media_id>/rating', methods=['POST'])
@token_required
def rate_media(current_user, media_id):
    """Rate a media item"""
    data = request.get_json()
    rating = data.get('rating')
    
    if not rating or rating < 1 or rating > 5:
        return jsonify({'error': 'Rating must be between 1 and 5'}), 400
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    
    cursor = conn.cursor()
    
    try:
        # Check if user already rated
        cursor.execute(
            "SELECT id FROM ratings WHERE media_id = ? AND user_id = ?",
            (media_id, current_user['user_id'])
        )
        existing = cursor.fetchone()
        
        if existing:
            # Update existing rating
            cursor.execute(
                "UPDATE ratings SET rating = ? WHERE id = ?",
                (rating, existing[0])
            )
        else:
            # Insert new rating
            cursor.execute(
                "INSERT INTO ratings (media_id, user_id, rating) VALUES (?, ?, ?)",
                (media_id, current_user['user_id'], rating)
            )
        
        conn.commit()
        
        # Get new average
        cursor.execute(
            "SELECT AVG(CAST(rating AS FLOAT)) FROM ratings WHERE media_id = ?",
            (media_id,)
        )
        avg_rating = cursor.fetchone()[0]
        
        return jsonify({
            'message': 'Rating saved successfully',
            'avg_rating': round(avg_rating, 1) if avg_rating else 0
        }), 200
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/media/<int:media_id>/rating', methods=['GET'])
@token_required
def get_user_rating(current_user, media_id):
    """Get user's rating for a media item"""
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "SELECT rating FROM ratings WHERE media_id = ? AND user_id = ?",
            (media_id, current_user['user_id'])
        )
        rating = cursor.fetchone()
        
        return jsonify({
            'rating': rating[0] if rating else None
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# Health check route
@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    db_status = "connected" if get_db_connection() else "disconnected"
    blob_status = "connected" if blob_service_client else "disconnected"
    
    return jsonify({
        'status': 'healthy',
        'database': db_status,
        'blob_storage': blob_status
    }), 200

if __name__ == '__main__':
    init_database()
    app.run(host='0.0.0.0', port=5000, debug=True)
