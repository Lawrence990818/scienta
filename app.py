from flask import Flask, render_template, request, jsonify, make_response, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import uuid
import jwt
import os
from functools import wraps
from datetime import datetime, timedelta
from flask_cors import CORS
from PIL import Image
import io
import threading
import time
import requests

app = Flask(__name__)
CORS(app)

# Configuration
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///edplatform.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['AVATARS_FOLDER'] = 'static/uploads/avatars'
app.config['POSTS_FOLDER'] = 'static/uploads/posts'
app.config['THUMBNAILS_FOLDER'] = 'static/uploads/thumbnails'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov'}
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload size

# Ensure upload directories exist
os.makedirs(app.config['AVATARS_FOLDER'], exist_ok=True)
os.makedirs(app.config['POSTS_FOLDER'], exist_ok=True)
os.makedirs(app.config['THUMBNAILS_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    username = db.Column(db.String(50), unique=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(200))
    is_admin = db.Column(db.Boolean, default=False)
    is_teacher = db.Column(db.Boolean, default=False)
    full_name = db.Column(db.String(100))
    bio = db.Column(db.Text)
    comments = db.relationship('Comment', backref='author', lazy=True)
    likes = db.relationship('UserLike', backref='user', lazy=True)
    posts = db.relationship('Post', backref='author', lazy=True)
    avatar = db.Column(db.String, default='/static/images/default-avatar.png')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    likes = db.Column(db.Integer, default=0)
    views = db.Column(db.Integer, default=0)
    comments = db.relationship('Comment', backref='post', lazy=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    media = db.relationship('PostMedia', backref='post', lazy=True)
    tags = db.Column(db.String(200))  # Comma-separated tags
    is_published = db.Column(db.Boolean, default=True)

class PostMedia(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    media_type = db.Column(db.String(20))  # 'image' or 'video'
    media_url = db.Column(db.String(200), nullable=False)
    thumbnail_url = db.Column(db.String(200))  # For video thumbnails
    order = db.Column(db.Integer)  # For ordering multiple media

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    likes = db.Column(db.Integer, default=0)
    parent_id = db.Column(db.Integer, db.ForeignKey('comment.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    replies = db.relationship('Comment', backref=db.backref('parent', remote_side=[id]), lazy=True)
    user_likes = db.relationship('UserLike', backref='comment', lazy=True)

class UserLike(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comment_id = db.Column(db.Integer, db.ForeignKey('comment.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    link = db.Column(db.String(200))  # URL to the relevant content

# Helper functions
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(" ")[1]
            
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
            
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except Exception as e:
            return jsonify({'message': 'Token is invalid!', 'error': str(e)}), 401
            
        return f(current_user, *args, **kwargs)
        
    return decorated

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def generate_thumbnail(image_path, output_path, size=(300, 300)):
    try:
        img = Image.open(image_path)
        img.thumbnail(size)
        img.save(output_path)
        return True
    except Exception as e:
        print(f"Error generating thumbnail: {e}")
        return False

def create_media_record(file, post_id, media_type, order):
    public_id = str(uuid.uuid4())
    filename = f"{public_id}.{file.filename.rsplit('.', 1)[1].lower()}"
    
    if media_type == 'image':
        filepath = os.path.join(app.config['POSTS_FOLDER'], filename)
        file.save(filepath)
        
        # Generate thumbnail for image
        thumbnail_filename = f"thumb_{filename}"
        thumbnail_path = os.path.join(app.config['THUMBNAILS_FOLDER'], thumbnail_filename)
        generate_thumbnail(filepath, thumbnail_path)
        
        media_url = f"/static/uploads/posts/{filename}"
        thumbnail_url = f"/static/uploads/thumbnails/{thumbnail_filename}"
    else:
        # For videos, just save the file (thumbnail would be generated separately)
        filepath = os.path.join(app.config['POSTS_FOLDER'], filename)
        file.save(filepath)
        media_url = f"/static/uploads/posts/{filename}"
        thumbnail_url = '/static/images/video-thumbnail.png'  # Placeholder
    
    new_media = PostMedia(
        public_id=public_id,
        post_id=post_id,
        media_type=media_type,
        media_url=media_url,
        thumbnail_url=thumbnail_url,
        order=order
    )
    
    db.session.add(new_media)
    return new_media

# Routes
@app.route("/")
def index():
    return render_template("index.html")

@app.route('/static/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Auth Routes
@app.route('/api/auth/register', methods=['POST'])
def register_user():
    data = request.form
    
    if not data or not data.get('username') or not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Missing required fields'}), 400
    
    # Check if user already exists
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'message': 'Username already exists'}), 400
        
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'message': 'Email already exists'}), 400
    
    hashed_password = generate_password_hash(data['password'])
    
    new_user = User(
        public_id=str(uuid.uuid4()),
        username=data['username'],
        email=data['email'],
        password=hashed_password,
        is_admin=False,
        full_name=data.get('full_name', ''),
        bio=data.get('bio', ''),
        is_teacher=data.get('is_teacher', 'false').lower() == 'true'
    )
    
    # Handle avatar upload
    if 'avatar' in request.files:
        file = request.files['avatar']
        if file and allowed_file(file.filename):
            filename = secure_filename(f"{new_user.public_id}.{file.filename.rsplit('.', 1)[1].lower()}")
            filepath = os.path.join(app.config['AVATARS_FOLDER'], filename)
            file.save(filepath)
            new_user.avatar = f"/static/uploads/avatars/{filename}"
    
    try:
        db.session.add(new_user)
        db.session.commit()
        
        # Create welcome notification
        welcome_notification = Notification(
            public_id=str(uuid.uuid4()),
            user_id=new_user.id,
            content="Welcome to EduSocial! Get started by creating your first post.",
            link="/"
        )
        db.session.add(welcome_notification)
        db.session.commit()
        
        return jsonify({'message': 'Registered successfully'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Registration failed', 'error': str(e)}), 500

@app.route('/api/auth/login', methods=['POST'])
def login_user():
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Missing username or password'}), 400
    
    user = User.query.filter_by(username=data['username']).first()
    if not user:
        return jsonify({'message': 'Invalid credentials'}), 401
    
    if check_password_hash(user.password, data['password']):
        token = jwt.encode({
            'public_id': user.public_id,
            'exp': datetime.utcnow() + timedelta(days=30)
        }, app.config['SECRET_KEY'])
        
        return jsonify({
            'token': token,
            'user': {
                'id': user.public_id,
                'username': user.username,
                'email': user.email,
                'is_admin': user.is_admin,
                'is_teacher': user.is_teacher,
                'full_name': user.full_name,
                'bio': user.bio,
                'avatar': user.avatar
            }
        }), 200
    
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/api/auth/status', methods=['GET'])
@token_required
def auth_status(current_user):
    return jsonify({
        'user': {
            'id': current_user.public_id,
            'username': current_user.username,
            'email': current_user.email,
            'is_admin': current_user.is_admin,
            'is_teacher': current_user.is_teacher,
            'full_name': current_user.full_name,
            'bio': current_user.bio,
            'avatar': current_user.avatar
        }
    }), 200

# Post Routes
@app.route("/api/posts", methods=["GET"])
def get_posts():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    search = request.args.get('search', '')
    tag = request.args.get('tag', '')
    user_id = request.args.get('user_id', '')
    
    query = Post.query.filter_by(is_published=True)
    
    if search:
        query = query.filter(Post.title.ilike(f'%{search}%') | Post.content.ilike(f'%{search}%'))
    
    if tag:
        query = query.filter(Post.tags.ilike(f'%{tag}%'))
    
    if user_id:
        user = User.query.filter_by(public_id=user_id).first()
        if user:
            query = query.filter_by(user_id=user.id)
    
    posts = query.order_by(Post.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    
    posts_data = []
    for post in posts.items:
        author = User.query.get(post.user_id)
        
        # Check if current user has liked this post
        is_liked = False
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(" ")[1]
                try:
                    data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
                    current_user = User.query.filter_by(public_id=data['public_id']).first()
                    if current_user:
                        is_liked = UserLike.query.filter_by(user_id=current_user.id, post_id=post.id).first() is not None
                except:
                    pass
        
        posts_data.append({
            'id': post.public_id,
            'title': post.title,
            'content': post.content,
            'created_at': post.created_at.isoformat(),
            'updated_at': post.updated_at.isoformat() if post.updated_at else None,
            'likes': post.likes,
            'views': post.views,
            'comment_count': len(post.comments),
            'is_liked': is_liked,
            'author': {
                'id': author.public_id,
                'username': author.username,
                'full_name': author.full_name,
                'avatar': author.avatar,
                'is_teacher': author.is_teacher
            },
            'media': [{
                'type': media.media_type,
                'url': media.media_url,
                'thumbnail': media.thumbnail_url,
                'order': media.order
            } for media in sorted(post.media, key=lambda x: x.order or 0)],
            'tags': post.tags.split(',') if post.tags else []
        })
    
    return jsonify({
        'posts': posts_data,
        'total': posts.total,
        'pages': posts.pages,
        'current_page': posts.page
    })

@app.route("/api/posts/<post_id>", methods=["GET"])
def get_post(post_id):
    post = Post.query.filter_by(public_id=post_id).first()
    if not post:
        return jsonify({'error': 'Post not found'}), 404
    
    # Increment view count
    post.views += 1
    db.session.commit()
    
    author = User.query.get(post.user_id)
    
    # Check if current user has liked this post
    is_liked = False
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization']
        if auth_header.startswith('Bearer '):
            token = auth_header.split(" ")[1]
            try:
                data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
                current_user = User.query.filter_by(public_id=data['public_id']).first()
                if current_user:
                    is_liked = UserLike.query.filter_by(user_id=current_user.id, post_id=post.id).first() is not None
            except:
                pass
    
    return jsonify({
        'id': post.public_id,
        'title': post.title,
        'content': post.content,
        'created_at': post.created_at.isoformat(),
        'updated_at': post.updated_at.isoformat() if post.updated_at else None,
        'likes': post.likes,
        'views': post.views,
        'comment_count': len(post.comments),
        'is_liked': is_liked,
        'author': {
            'id': author.public_id,
            'username': author.username,
            'full_name': author.full_name,
            'avatar': author.avatar,
            'is_teacher': author.is_teacher,
            'bio': author.bio
        },
        'media': [{
            'type': media.media_type,
            'url': media.media_url,
            'thumbnail': media.thumbnail_url,
            'order': media.order
        } for media in sorted(post.media, key=lambda x: x.order or 0)],
        'tags': post.tags.split(',') if post.tags else []
    })

@app.route("/api/posts", methods=["POST"])
@token_required
def create_post(current_user):
    data = request.form
    
    if not data or not data.get('title'):
        return jsonify({'message': 'Title is required'}), 400
    
    user = User.query.filter_by(public_id=current_user.public_id).first()
    
    new_post = Post(
        public_id=str(uuid.uuid4()),
        title=data['title'],
        content=data.get('content', ''),
        user_id=user.id,
        tags=data.get('tags', ''),
        is_published=data.get('is_published', 'true').lower() == 'true'
    )
    
    try:
        db.session.add(new_post)
        db.session.commit()
        
        # Handle media uploads
        if 'media' in request.files:
            files = request.files.getlist('media')
            for i, file in enumerate(files):
                if file and allowed_file(file.filename):
                    # Determine media type
                    ext = file.filename.rsplit('.', 1)[1].lower()
                    media_type = 'video' if ext in {'mp4', 'mov'} else 'image'
                    
                    create_media_record(file, new_post.id, media_type, i)
        
        db.session.commit()
        
        return jsonify({
            'message': 'Post created successfully',
            'post_id': new_post.public_id
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to create post', 'error': str(e)}), 500

@app.route("/api/posts/<post_id>", methods=["PUT"])
@token_required
def update_post(current_user, post_id):
    post = Post.query.filter_by(public_id=post_id).first()
    if not post:
        return jsonify({'error': 'Post not found'}), 404
    
    # Check if current user is the author or admin
    user = User.query.filter_by(public_id=current_user.public_id).first()
    if post.user_id != user.id and not user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.form
    
    if 'title' in data:
        post.title = data['title']
    if 'content' in data:
        post.content = data['content']
    if 'tags' in data:
        post.tags = data['tags']
    if 'is_published' in data:
        post.is_published = data['is_published'].lower() == 'true'
    
    post.updated_at = datetime.utcnow()
    
    try:
        db.session.commit()
        return jsonify({'message': 'Post updated successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to update post', 'error': str(e)}), 500

@app.route("/api/posts/<post_id>", methods=["DELETE"])
@token_required
def delete_post(current_user, post_id):
    post = Post.query.filter_by(public_id=post_id).first()
    if not post:
        return jsonify({'error': 'Post not found'}), 404
    
    # Check if current user is the author or admin
    user = User.query.filter_by(public_id=current_user.public_id).first()
    if post.user_id != user.id and not user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        # Delete all associated media files
        for media in post.media:
            try:
                if media.media_url.startswith('/static/uploads/'):
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], media.media_url.split('/static/uploads/')[1])
                    if os.path.exists(filepath):
                        os.remove(filepath)
                
                if media.thumbnail_url and media.thumbnail_url.startswith('/static/uploads/'):
                    thumbpath = os.path.join(app.config['UPLOAD_FOLDER'], media.thumbnail_url.split('/static/uploads/')[1])
                    if os.path.exists(thumbpath):
                        os.remove(thumbpath)
            except Exception as e:
                print(f"Error deleting media file: {e}")
        
        db.session.delete(post)
        db.session.commit()
        return jsonify({'message': 'Post deleted successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to delete post', 'error': str(e)}), 500

@app.route("/api/posts/<post_id>/like", methods=["POST"])
@token_required
def like_post(current_user, post_id):
    post = Post.query.filter_by(public_id=post_id).first()
    if not post:
        return jsonify({'error': 'Post not found'}), 404
    
    user = User.query.filter_by(public_id=current_user.public_id).first()
    existing_like = UserLike.query.filter_by(user_id=user.id, post_id=post.id).first()
    
    if existing_like:
        # Unlike
        db.session.delete(existing_like)
        post.likes -= 1
        action = 'unliked'
    else:
        # Like
        new_like = UserLike(user_id=user.id, post_id=post.id)
        db.session.add(new_like)
        post.likes += 1
        action = 'liked'
    
    db.session.commit()
    
    # Create notification if someone else liked the post
    if action == 'liked' and post.user_id != user.id:
        liker = User.query.get(user.id)
        post_author = User.query.get(post.user_id)
        
        notification = Notification(
            public_id=str(uuid.uuid4()),
            user_id=post.user_id,
            content=f"{liker.username} liked your post: {post.title}",
            link=f"/posts/{post.public_id}"
        )
        db.session.add(notification)
        db.session.commit()
    
    return jsonify({'likes': post.likes, 'action': action, 'is_liked': action == 'liked'})

# Comment Routes
@app.route("/api/comments", methods=["GET"])
def get_comments():
    post_id = request.args.get('post_id')
    if not post_id:
        return jsonify({'error': 'post_id parameter is required'}), 400
    
    post = Post.query.filter_by(public_id=post_id).first()
    if not post:
        return jsonify({'error': 'Post not found'}), 404
    
    # Get top-level comments for the post
    top_level = Comment.query.filter_by(post_id=post.id, parent_id=None).order_by(Comment.timestamp.desc()).all()
    
    def build_nested_comments(comment_list, current_user_id=None):
        result = []
        for comment in comment_list:
            is_liked = False
            if current_user_id:
                is_liked = UserLike.query.filter_by(
                    user_id=current_user_id,
                    comment_id=comment.id
                ).first() is not None
            
            comment_data = {
                'id': comment.public_id,
                'username': comment.author.username,
                'avatar': comment.author.avatar,
                'content': comment.content,
                'timestamp': comment.timestamp.isoformat(),
                'likes': comment.likes,
                'is_liked': is_liked,
                'replies': [],
                'parent_id': comment.parent.public_id if comment.parent else None,
                'user_id': comment.author.public_id
            }
            
            replies = Comment.query.filter_by(parent_id=comment.id).order_by(Comment.timestamp.desc()).all()
            if replies:
                comment_data['replies'] = build_nested_comments(replies, current_user_id)
                
            result.append(comment_data)
        return result
    
    # Check if user is authenticated to get like status
    current_user_id = None
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization']
        if auth_header.startswith('Bearer '):
            token = auth_header.split(" ")[1]
            try:
                data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
                user = User.query.filter_by(public_id=data['public_id']).first()
                if user:
                    current_user_id = user.id
            except:
                pass
    
    return jsonify(build_nested_comments(top_level, current_user_id))

@app.route("/api/comments", methods=["POST"])
@token_required
def add_comment(current_user):
    data = request.get_json()
    
    if not data or not data.get('content') or not data.get('post_id'):
        return jsonify({'message': 'Missing required fields'}), 400
    
    post = Post.query.filter_by(public_id=data['post_id']).first()
    if not post:
        return jsonify({'message': 'Post not found'}), 404
    
    parent_id = None
    if data.get('parent_id'):
        parent_comment = Comment.query.filter_by(public_id=data['parent_id']).first()
        if parent_comment:
            parent_id = parent_comment.id
    
    user = User.query.filter_by(public_id=current_user.public_id).first()
    
    new_comment = Comment(
        public_id=str(uuid.uuid4()),
        content=data['content'],
        parent_id=parent_id,
        user_id=user.id,
        post_id=post.id
    )
    
    try:
        db.session.add(new_comment)
        db.session.commit()
        
        # Create notification if someone else commented on the post
        if post.user_id != user.id:
            commenter = User.query.get(user.id)
            post_author = User.query.get(post.user_id)
            
            notification = Notification(
                public_id=str(uuid.uuid4()),
                user_id=post.user_id,
                content=f"{commenter.username} commented on your post: {post.title}",
                link=f"/posts/{post.public_id}"
            )
            db.session.add(notification)
            db.session.commit()
        
        comment_data = {
            'id': new_comment.public_id,
            'username': user.username,
            'avatar': user.avatar,
            'content': new_comment.content,
            'timestamp': new_comment.timestamp.isoformat(),
            'likes': new_comment.likes,
            'is_liked': False,
            'replies': [],
            'parent_id': data.get('parent_id'),
            'user_id': user.public_id
        }
        
        return jsonify(comment_data), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to add comment', 'error': str(e)}), 500

@app.route("/api/comments/<comment_id>/like", methods=["POST"])
@token_required
def like_comment(current_user, comment_id):
    comment = Comment.query.filter_by(public_id=comment_id).first()
    if not comment:
        return jsonify({'error': 'Comment not found'}), 404
    
    user = User.query.filter_by(public_id=current_user.public_id).first()
    existing_like = UserLike.query.filter_by(user_id=user.id, comment_id=comment.id).first()
    
    if existing_like:
        # Unlike
        db.session.delete(existing_like)
        comment.likes -= 1
        action = 'unliked'
    else:
        # Like
        new_like = UserLike(user_id=user.id, comment_id=comment.id)
        db.session.add(new_like)
        comment.likes += 1
        action = 'liked'
    
    db.session.commit()
    
    # Create notification if someone else liked the comment
    if action == 'liked' and comment.user_id != user.id:
        liker = User.query.get(user.id)
        comment_author = User.query.get(comment.user_id)
        
        notification = Notification(
            public_id=str(uuid.uuid4()),
            user_id=comment.user_id,
            content=f"{liker.username} liked your comment",
            link=f"/posts/{comment.post.public_id}"
        )
        db.session.add(notification)
        db.session.commit()
    
    return jsonify({'likes': comment.likes, 'action': action, 'is_liked': action == 'liked'})

@app.route("/api/comments/<comment_id>", methods=["DELETE"])
@token_required
def delete_comment(current_user, comment_id):
    comment = Comment.query.filter_by(public_id=comment_id).first()
    if not comment:
        return jsonify({'error': 'Comment not found'}), 404
    
    # Check if user is author or admin
    user = User.query.filter_by(public_id=current_user.public_id).first()
    if comment.author.public_id != current_user.public_id and not user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    # Delete all replies first
    for reply in comment.replies:
        # Delete all likes for replies first
        UserLike.query.filter_by(comment_id=reply.id).delete()
        db.session.delete(reply)
    
    # Delete all likes for this comment
    UserLike.query.filter_by(comment_id=comment.id).delete()
    
    db.session.delete(comment)
    db.session.commit()
    
    return jsonify({'message': 'Comment deleted'}), 200

# User Routes
@app.route("/api/users/<user_id>", methods=["GET"])
def get_user(user_id):
    user = User.query.filter_by(public_id=user_id).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Get user's posts count
    posts_count = Post.query.filter_by(user_id=user.id).count()
    
    return jsonify({
        'id': user.public_id,
        'username': user.username,
        'full_name': user.full_name,
        'avatar': user.avatar,
        'bio': user.bio,
        'is_teacher': user.is_teacher,
        'created_at': user.created_at.isoformat(),
        'posts_count': posts_count
    })

@app.route("/api/users/<user_id>/posts", methods=["GET"])
def get_user_posts(user_id):
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    
    user = User.query.filter_by(public_id=user_id).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    posts = Post.query.filter_by(user_id=user.id, is_published=True)\
                     .order_by(Post.created_at.desc())\
                     .paginate(page=page, per_page=per_page, error_out=False)
    
    posts_data = []
    for post in posts.items:
        # Check if current user has liked this post
        is_liked = False
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(" ")[1]
                try:
                    data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
                    current_user = User.query.filter_by(public_id=data['public_id']).first()
                    if current_user:
                        is_liked = UserLike.query.filter_by(user_id=current_user.id, post_id=post.id).first() is not None
                except:
                    pass
        
        posts_data.append({
            'id': post.public_id,
            'title': post.title,
            'content': post.content,
            'created_at': post.created_at.isoformat(),
            'updated_at': post.updated_at.isoformat() if post.updated_at else None,
            'likes': post.likes,
            'views': post.views,
            'comment_count': len(post.comments),
            'is_liked': is_liked,
            'media': [{
                'type': media.media_type,
                'url': media.media_url,
                'thumbnail': media.thumbnail_url,
                'order': media.order
            } for media in sorted(post.media, key=lambda x: x.order or 0)],
            'tags': post.tags.split(',') if post.tags else []
        })
    
    return jsonify({
        'posts': posts_data,
        'total': posts.total,
        'pages': posts.pages,
        'current_page': posts.page
    })

# Notification Routes
@app.route("/api/notifications", methods=["GET"])
@token_required
def get_notifications(current_user):
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    
    user = User.query.filter_by(public_id=current_user.public_id).first()
    notifications = Notification.query.filter_by(user_id=user.id)\
                                    .order_by(Notification.created_at.desc())\
                                    .paginate(page=page, per_page=per_page, error_out=False)
    
    notifications_data = []
    for notification in notifications.items:
        notifications_data.append({
            'id': notification.public_id,
            'content': notification.content,
            'is_read': notification.is_read,
            'created_at': notification.created_at.isoformat(),
            'link': notification.link
        })
    
    # Mark notifications as read
    Notification.query.filter_by(user_id=user.id, is_read=False).update({'is_read': True})
    db.session.commit()
    
    return jsonify({
        'notifications': notifications_data,
        'total': notifications.total,
        'pages': notifications.pages,
        'current_page': notifications.page,
        'unread_count': Notification.query.filter_by(user_id=user.id, is_read=False).count()
    })

# Tag Routes
@app.route("/api/tags/popular", methods=["GET"])
def get_popular_tags():
    # This is a simplified version - in a real app you'd want to calculate popularity
    popular_tags = [
        {"name": "mathematics", "post_count": Post.query.filter(Post.tags.ilike('%mathematics%')).count()},
        {"name": "programming", "post_count": Post.query.filter(Post.tags.ilike('%programming%')).count()},
        {"name": "science", "post_count": Post.query.filter(Post.tags.ilike('%science%')).count()},
        {"name": "history", "post_count": Post.query.filter(Post.tags.ilike('%history%')).count()},
        {"name": "literature", "post_count": Post.query.filter(Post.tags.ilike('%literature%')).count()},
        {"name": "physics", "post_count": Post.query.filter(Post.tags.ilike('%physics%')).count()},
        {"name": "chemistry", "post_count": Post.query.filter(Post.tags.ilike('%chemistry%')).count()},
        {"name": "biology", "post_count": Post.query.filter(Post.tags.ilike('%biology%')).count()},
    ]
    
    # Sort by post count descending
    popular_tags.sort(key=lambda x: x['post_count'], reverse=True)
    
    return jsonify(popular_tags[:10])  # Return top 10
# prevent server from spleeping testing
def wake_up():
    while True:
        # Replace with your actual Render URL
        url = "https://your-app-name.onrender.com"
        try:
            requests.get(url)
            print("Keep-alive request sent")
        except Exception as e:
            print(f"Keep-alive failed: {e}")
        time.sleep(840)  # 14 minutes

# Start the background thread
thread = threading.Thread(target=wake_up)
thread.daemon = True
thread.start()

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, host="0.0.0.0", port="5000")