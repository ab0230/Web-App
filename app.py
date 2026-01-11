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
from PIL import Image
from azure.storage.blob import BlobServiceClient, PublicAccess

app = Flask(__name__, static_folder='static', static_url_path='')
app.config['SECRET_KEY'] = 'a1b2c3d4e5f6789abcdef1234567890abcdef1234567890abcdef1234567890'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
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
        
        # Photos table
        cursor.execute("""
        IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='photos' AND xtype='U')
        CREATE TABLE photos (
            id INT IDENTITY(1,1) PRIMARY KEY,
            user_id INT NOT NULL,
            title NVARCHAR(200) NOT NULL,
            caption NVARCHAR(1000),
            location NVARCHAR(200),
            people_present NVARCHAR(500),
            blob_url NVARCHAR(500) NOT NULL,
            thumbnail_url NVARCHAR(500),
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
            photo_id INT NOT NULL,
            user_id INT NOT NULL,
            comment_text NVARCHAR(1000) NOT NULL,
            created_at DATETIME DEFAULT GETDATE(),
            FOREIGN KEY (photo_id) REFERENCES photos(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE NO ACTION
        )
        """)
        
        # Ratings table
        cursor.execute("""
        IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='ratings' AND xtype='U')
        CREATE TABLE ratings (
            id INT IDENTITY(1,1) PRIMARY KEY,
            photo_id INT NOT NULL,
            user_id INT NOT NULL,
            rating INT NOT NULL CHECK (rating >= 1 AND rating <= 5),
            created_at DATETIME DEFAULT GETDATE(),
            UNIQUE (photo_id, user_id),
            FOREIGN KEY (photo_id) REFERENCES photos(id) ON DELETE CASCADE,
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

# Photo Routes
@app.route('/api/photos', methods=['GET'])
def get_photos():
    """Get all photos with pagination and search"""
    page = int(request.args.get('page', 1))
    limit = int(request.args.get('limit', 12))
    search = request.args.get('search', '')
    
    offset = (page - 1) * limit
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    
    cursor = conn.cursor()
    
    try:
        # Build query with search
        if search:
            query = """
                SELECT p.id, p.title, p.caption, p.location, p.people_present, 
                       p.blob_url, p.thumbnail_url, p.upload_date, p.views,
                       u.username, u.id as user_id,
                       (SELECT AVG(CAST(rating AS FLOAT)) FROM ratings WHERE photo_id = p.id) as avg_rating,
                       (SELECT COUNT(*) FROM comments WHERE photo_id = p.id) as comment_count
                FROM photos p
                JOIN users u ON p.user_id = u.id
                WHERE p.title LIKE ? OR p.caption LIKE ? OR p.location LIKE ? OR p.people_present LIKE ?
                ORDER BY p.upload_date DESC
                OFFSET ? ROWS FETCH NEXT ? ROWS ONLY
            """
            search_term = f'%{search}%'
            cursor.execute(query, (search_term, search_term, search_term, search_term, offset, limit))
        else:
            query = """
                SELECT p.id, p.title, p.caption, p.location, p.people_present, 
                       p.blob_url, p.thumbnail_url, p.upload_date, p.views,
                       u.username, u.id as user_id,
                       (SELECT AVG(CAST(rating AS FLOAT)) FROM ratings WHERE photo_id = p.id) as avg_rating,
                       (SELECT COUNT(*) FROM comments WHERE photo_id = p.id) as comment_count
                FROM photos p
                JOIN users u ON p.user_id = u.id
                ORDER BY p.upload_date DESC
                OFFSET ? ROWS FETCH NEXT ? ROWS ONLY
            """
            cursor.execute(query, (offset, limit))
        
        photos = []
        for row in cursor.fetchall():
            photos.append({
                'id': row[0],
                'title': row[1],
                'caption': row[2],
                'location': row[3],
                'people_present': row[4],
                'url': row[5],
                'thumbnail_url': row[6] or row[5],
                'upload_date': row[7].isoformat() if row[7] else None,
                'views': row[8],
                'username': row[9],
                'user_id': row[10],
                'avg_rating': round(row[11], 1) if row[11] else 0,
                'comment_count': row[12]
            })
        
        # Get total count
        if search:
            cursor.execute("SELECT COUNT(*) FROM photos WHERE title LIKE ? OR caption LIKE ? OR location LIKE ?", 
                          (search_term, search_term, search_term))
        else:
            cursor.execute("SELECT COUNT(*) FROM photos")
        
        total = cursor.fetchone()[0]
        
        return jsonify({
            'photos': photos,
            'total': total,
            'page': page,
            'pages': (total + limit - 1) // limit
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/photos/<int:photo_id>', methods=['GET'])
def get_photo(photo_id):
    """Get single photo details"""
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    
    cursor = conn.cursor()
    
    try:
        # Increment view count
        cursor.execute("UPDATE photos SET views = views + 1 WHERE id = ?", (photo_id,))
        
        # Get photo details
        cursor.execute("""
            SELECT p.id, p.title, p.caption, p.location, p.people_present, 
                   p.blob_url, p.thumbnail_url, p.upload_date, p.views,
                   u.username, u.id as user_id,
                   (SELECT AVG(CAST(rating AS FLOAT)) FROM ratings WHERE photo_id = p.id) as avg_rating
            FROM photos p
            JOIN users u ON p.user_id = u.id
            WHERE p.id = ?
        """, (photo_id,))
        
        row = cursor.fetchone()
        if not row:
            return jsonify({'error': 'Photo not found'}), 404
        
        photo = {
            'id': row[0],
            'title': row[1],
            'caption': row[2],
            'location': row[3],
            'people_present': row[4],
            'url': row[5],
            'thumbnail_url': row[6] or row[5],
            'upload_date': row[7].isoformat() if row[7] else None,
            'views': row[8],
            'username': row[9],
            'user_id': row[10],
            'avg_rating': round(row[11], 1) if row[11] else 0
        }
        
        conn.commit()
        return jsonify(photo), 200
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/photos', methods=['POST'])
@token_required
def upload_photo(current_user):
    """Upload a new photo (creators only)"""
    if current_user['role'] != 'creator':
        return jsonify({'error': 'Only creators can upload photos'}), 403
    
    if 'photo' not in request.files:
        return jsonify({'error': 'No photo file provided'}), 400
    
    file = request.files['photo']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    title = request.form.get('title', '')
    caption = request.form.get('caption', '')
    location = request.form.get('location', '')
    people_present = request.form.get('people_present', '')
    
    if not title:
        return jsonify({'error': 'Title is required'}), 400
    
    # Generate unique filename
    file_ext = os.path.splitext(file.filename)[1]
    unique_filename = f"{uuid.uuid4()}{file_ext}"
    
    # Upload to blob storage
    file.seek(0)
    blob_url = upload_to_blob(file.read(), unique_filename)
    
    if not blob_url:
        return jsonify({'error': 'Failed to upload photo'}), 500
    
    # Create thumbnail
    file.seek(0)
    thumbnail = create_thumbnail(file)
    thumbnail_url = None
    if thumbnail:
        thumb_filename = f"thumb_{unique_filename}"
        thumbnail_url = upload_to_blob(thumbnail.read(), thumb_filename)
    
    # Save to database
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            INSERT INTO photos (user_id, title, caption, location, people_present, blob_url, thumbnail_url)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (current_user['user_id'], title, caption, location, people_present, blob_url, thumbnail_url))
        
        conn.commit()
        photo_id = cursor.execute("SELECT @@IDENTITY").fetchone()[0]
        
        return jsonify({
            'message': 'Photo uploaded successfully',
            'photo_id': photo_id
        }), 201
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# Comments Routes
@app.route('/api/photos/<int:photo_id>/comments', methods=['GET'])
def get_comments(photo_id):
    """Get comments for a photo"""
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            SELECT c.id, c.comment_text, c.created_at, u.username, u.id as user_id
            FROM comments c
            JOIN users u ON c.user_id = u.id
            WHERE c.photo_id = ?
            ORDER BY c.created_at DESC
        """, (photo_id,))
        
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

@app.route('/api/photos/<int:photo_id>/comments', methods=['POST'])
@token_required
def add_comment(current_user, photo_id):
    """Add a comment to a photo"""
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
            INSERT INTO comments (photo_id, user_id, comment_text)
            VALUES (?, ?, ?)
        """, (photo_id, current_user['user_id'], comment_text))
        
        conn.commit()
        
        return jsonify({'message': 'Comment added successfully'}), 201
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# Ratings Routes
@app.route('/api/photos/<int:photo_id>/rating', methods=['POST'])
@token_required
def rate_photo(current_user, photo_id):
    """Rate a photo"""
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
            "SELECT id FROM ratings WHERE photo_id = ? AND user_id = ?",
            (photo_id, current_user['user_id'])
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
                "INSERT INTO ratings (photo_id, user_id, rating) VALUES (?, ?, ?)",
                (photo_id, current_user['user_id'], rating)
            )
        
        conn.commit()
        
        # Get new average
        cursor.execute(
            "SELECT AVG(CAST(rating AS FLOAT)) FROM ratings WHERE photo_id = ?",
            (photo_id,)
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

@app.route('/api/photos/<int:photo_id>/rating', methods=['GET'])
@token_required
def get_user_rating(current_user, photo_id):
    """Get user's rating for a photo"""
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "SELECT rating FROM ratings WHERE photo_id = ? AND user_id = ?",
            (photo_id, current_user['user_id'])
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