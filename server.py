import os
import ssl
import json
import hashlib
import time
from flask import Flask, jsonify, send_from_directory, request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import JSON

# --- Configuration ---
app = Flask(__name__)

# Database Configuration
# Use SQLite locally if DATABASE_URL is not set, otherwise use the provided URL (Render provides this)
database_url = os.environ.get('DATABASE_URL', 'sqlite:///local.db')
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

MUSIC_FOLDER = 'music_files'

# --- Database Models ---

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    salt = db.Column(db.String(32), nullable=False)
    public_key = db.Column(db.Text, nullable=True)

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(JSON, nullable=False) # Stores the encrypted note object

class Image(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner = db.Column(db.String(80), nullable=True)
    encrypted_html = db.Column(db.Text, nullable=False)

class Message(db.Model):
    """Permanent History Log"""
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(80), nullable=True)
    recipient = db.Column(db.String(80), nullable=False)
    content = db.Column(JSON, nullable=False)
    timestamp = db.Column(db.Float, default=time.time)

class MessageQueue(db.Model):
    """Temporary Queue for Undelivered Messages"""
    id = db.Column(db.Integer, primary_key=True)
    recipient = db.Column(db.String(80), nullable=False)
    content = db.Column(JSON, nullable=False)

# Create tables
with app.app_context():
    db.create_all()

# --- CRYPTO HELPERS ---
def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16).hex()
    combined = password + salt
    hasher = hashlib.sha256()
    hasher.update(combined.encode('utf-8'))
    return hasher.hexdigest(), salt

def get_ip_address():
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        IP = s.getsockname()[0]
    except Exception:
        IP = "127.0.0.1"
    finally:
        s.close()
    return IP

# --- NEW: DES IMAGE ENDPOINTS ---

@app.route('/save_image_des', methods=['POST'])
def save_image_des():
    """Receives HTML string encrypted with DES and saves to DB."""
    data = request.json
    # data contains: { "owner": "user", "encrypted_html": "..." }
    
    new_image = Image(
        owner=data.get('owner'),
        encrypted_html=data.get('encrypted_html')
    )
    db.session.add(new_image)
    db.session.commit()
    
    print("Stored DES Encrypted Image Blob")
    return jsonify({"status": "success"})

@app.route('/get_images_des', methods=['GET'])
def get_images_des():
    images = Image.query.all()
    # Convert back to list of dicts to match original API
    result = []
    for img in images:
        result.append({
            "owner": img.owner,
            "encrypted_html": img.encrypted_html
        })
    return jsonify(result)

# --- SECURE TUNNEL ENDPOINTS ---

@app.route('/upload_public_key', methods=['POST'])
def upload_key():
    data = request.json
    username = data.get('username')
    pub_key = data.get('public_key')
    
    if username and pub_key:
        user = User.query.filter_by(username=username).first()
        if user:
            user.public_key = pub_key
            db.session.commit()
            print(f"Public Key registered for: {username}")
            return jsonify({"status": "success"})
        else:
             # If user doesn't exist but tries to upload key, we could create them or error.
             # Original logic just stored it. Let's assume user must exist or we just store it if we want to mimic strict key-value.
             # But better to attach to User. If User not found, error.
             return jsonify({"status": "error", "message": "User not found"}), 404

    return jsonify({"status": "error"}), 400

@app.route('/get_public_key', methods=['GET'])
def get_key():
    target_user = request.args.get('username')
    user = User.query.filter_by(username=target_user).first()
    
    if user and user.public_key:
        return jsonify({"status": "success", "public_key": user.public_key})
    return jsonify({"status": "error", "message": "User not found or no key uploaded"}), 404

@app.route('/send_message', methods=['POST'])
def send_msg():
    """Relays an encrypted message. Saves to Queue AND History."""
    data = request.json
    recipient = data.get('recipient')
    sender = data.get('sender') # Assuming sender might be in data, if not it's None
    
    if recipient:
        # 1. Add to Delivery Queue (Temporary)
        queue_msg = MessageQueue(recipient=recipient, content=data)
        db.session.add(queue_msg)

        # 2. Add to Permanent History Log
        log_entry = data.copy()
        log_entry['server_timestamp'] = time.time()
        
        history_msg = Message(
            sender=sender,
            recipient=recipient,
            content=log_entry,
            timestamp=log_entry['server_timestamp']
        )
        db.session.add(history_msg)
        
        db.session.commit()
        
        print(f"Relaying message to {recipient} (Saved to History)")
        return jsonify({"status": "success"})
    return jsonify({"status": "error"}), 400

@app.route('/get_messages', methods=['GET'])
def get_msg():
    """User polls this endpoint to get messages waiting for them."""
    username = request.args.get('username')
    
    # Check if there are messages in the Queue
    queued_msgs = MessageQueue.query.filter_by(recipient=username).all()
    
    if queued_msgs:
        # 1. Get messages content
        msgs = [m.content for m in queued_msgs]
        
        # 2. Remove from Queue table (but they stay in History table)
        for m in queued_msgs:
            db.session.delete(m)
        db.session.commit()
        
        return jsonify({"status": "success", "messages": msgs})
    return jsonify({"status": "success", "messages": []})

# --- EXISTING ENDPOINTS ---

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    if not username or not password: return jsonify({"status": "error"}), 400
    
    if User.query.filter_by(username=username).first():
        return jsonify({"status": "error", "message": "User already exists"}), 400
        
    hashed_pw, salt = hash_password(password)
    new_user = User(username=username, password_hash=hashed_pw, salt=salt)
    db.session.add(new_user)
    db.session.commit()
    
    print(f"New User Registered: {username}")
    return jsonify({"status": "success"})

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    user = User.query.filter_by(username=username).first()
    if not user: return jsonify({"status": "error"}), 401
    
    h, _ = hash_password(password, user.salt)
    if h == user.password_hash: 
        print(f"User Logged In: {username}")
        return jsonify({"status": "success"})
    return jsonify({"status": "error"}), 401

@app.route('/songs', methods=['GET'])
def get_songs():
    songs = []
    host = request.host # Use the host from the request (works for Render url)
    # Scheme (http/https)
    scheme = request.scheme
    
    if os.path.exists(MUSIC_FOLDER):
        for f in os.listdir(MUSIC_FOLDER):
            if f.endswith('.mp3'):
                try:
                    p = f.replace('.mp3','').split(' - ')
                    # Construct URL dynamically based on request
                    url = f"{scheme}://{host}/music/{f}"
                    songs.append({'title':p[1].strip(), 'artist':p[0].strip(), 'url':url})
                except: pass
    return jsonify(songs)

@app.route('/music/<path:filename>', methods=['GET'])
def serve_music(filename):
    print(f"Serving: {filename}")
    return send_from_directory(MUSIC_FOLDER, filename)

@app.route('/save_note', methods=['POST'])
def save_note():
    data = request.json
    new_note = Note(content=data)
    db.session.add(new_note)
    db.session.commit()
    print("Stored Encrypted Note")
    return jsonify({"status": "success"})

@app.route('/get_notes', methods=['GET'])
def get_notes():
    notes = Note.query.all()
    # Return list of note contents
    return jsonify([n.content for n in notes])

if __name__ == '__main__':
    # Render sets the PORT environment variable
    port = int(os.environ.get("PORT", 5000))
    
    # In production (Render), we don't need the custom SSL context because Render handles SSL termination.
    # We just run the app on the assigned port.
    # We can keep debug=True for now if desired, or switch to False.
    
    print(f"\n--- SERVER RUNNING on Port {port} ---")
    app.run(host='0.0.0.0', port=port)