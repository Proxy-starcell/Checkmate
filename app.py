from flask import Flask, request, Response, send_file, render_template, redirect, url_for, flash, jsonify
import requests
from requests.adapters import HTTPAdapter
from urllib.parse import urlparse, urljoin, quote
import os
import logging
import time
import re
import threading
import datetime
import json
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from wtforms.validators import ValidationError
from flask_socketio import SocketIO, emit, join_room, leave_room

# Setup logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Create a session with connection pooling
session = requests.Session()
adapter = HTTPAdapter(pool_connections=100, pool_maxsize=100)
session.mount('https://', adapter)
session.mount('http://', adapter)

# SQLAlchemy setup
class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

# Create the app
app = Flask(__name__)

# Secret key for sessions and CSRF protection
app.secret_key = os.environ.get("SESSION_SECRET")
if not app.secret_key:
    logger.warning("SESSION_SECRET not set, using a default key (not secure for production)")
    app.secret_key = "default-dev-secret-key-change-in-production"

# Database configuration
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
if not app.config["SQLALCHEMY_DATABASE_URI"]:
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///app.db"
    logger.info("DATABASE_URL not found, using SQLite database")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# Initialize SQLAlchemy
db.init_app(app)

# Login manager setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "Please log in to access this page."

# Path to the static files
STATIC_DIR = 'static'
TEMPLATES_DIR = 'templates'

# Caching for static resources
CACHE_TIMEOUT = 3600  # 1 hour
resource_cache = {}

# Add this dict to reuse in responses
no_cache_headers = {
    'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
    'Pragma': 'no-cache',
    'Expires': '0'
}

# Import the CSRF protection tool
from forms import csrf

# Initialize CSRF protection
csrf.init_app(app)

# Initialize SocketIO with async mode and optimized polling settings
socketio = SocketIO(app, 
                   cors_allowed_origins="*", 
                   async_mode='gevent',  # Use gevent for better performance
                   ping_timeout=5,      # Reduce ping timeout
                   ping_interval=10,    # Reduce ping interval
                   max_http_buffer_size=50 * 1024 * 1024,  # Increase buffer size
                   manage_session=False, # Don't manage sessions for better performance
                   message_queue=None,  # Use memory queue for single-process deployment
                   engineio_logger=True, # Log engine.io events for debugging
                   logger=True)         # Enable Socket.IO logger for detailed logs

# Import models after db is defined
with app.app_context():
    from models import User, IPRegistration, ChatGroup, Message
    
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))
    
    # Create tables
    db.create_all()

# Serve the main index.html from the specified location
@app.route('/')
def index():
    return render_template('index.html')

# Serve the Service Worker script
@app.route('/sw.js')
def sw():
    return send_file('static/js/sw-updated.js', mimetype='application/javascript')

# Serve a test image (dummy image file)
@app.route('/test-image.png')
def test_image():
    return send_file('test-image.png', mimetype='image/png')

# Define static file extensions for caching
STATIC_EXTENSIONS = {
    '.js', '.css', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.woff', 
    '.woff2', '.ttf', '.eot', '.mp4', '.webm', '.ogg', '.mp3', '.wav', '.pdf'
}

def is_static_resource(url):
    """Check if URL is for a static resource that can be cached"""
    parsed = urlparse(url)
    path = parsed.path.lower()
    return any(path.endswith(ext) for ext in STATIC_EXTENSIONS)

def get_cache_key(url, headers):
    """Generate a cache key from URL and relevant headers"""
    return f"{url}:{headers.get('User-Agent', '')}"

@app.route('/xorcipher')
def xorcipher_proxy():
    start_time = time.time()
    target_url = request.args.get('url')
    origin_url = request.args.get('origin')

    if not target_url:
        return "Missing 'url' parameter", 400

    excluded_headers = {
        'Content-Encoding', 'Content-Length', 'Transfer-Encoding',
        'Connection', 'Access-Control-Allow-Origin', 'X-Frame-Options',
        'Content-Security-Policy', 'Strict-Transport-Security', 'Set-Cookie',
        'Cookie', 'CF-RAY', 'CF-Cache-Status', 'CF-Visitor', 'NEL',
        'Report-To', 'X-Content-Type-Options', 'X-Chesscom-Version',
        'X-Chesscom-Request-Id-Cdn', 'X-Chesscom-Request-Id-Lb',
        'X-Chesscom-Matched', 'Alt-Svc', 'Vary', 'Server', 'Date', 'Expires'
    }

    try:
        # Check cache for static resources
        cache_key = None
        if is_static_resource(target_url):
            cache_key = get_cache_key(target_url, request.headers)
            cached_response = resource_cache.get(cache_key)
            if cached_response:
                logger.debug(f"[Proxy] Cache hit: {target_url}")
                return cached_response

        logger.debug(f"[Proxy] Fetching: {target_url} (origin: {origin_url})")

        headers = {
            'User-Agent': request.headers.get('User-Agent', 'Mozilla/5.0'),
            'Referer': origin_url or '',
            'Accept-Encoding': 'identity'  # Disable compression to avoid decompression issues
        }

        # Use the session with connection pooling
        resp = session.get(target_url, headers=headers, timeout=5)
        content_type = resp.headers.get('Content-Type', '')
        
        # Use content as-is (no decompression needed with 'identity')
        content = resp.content
        
        # Always exclude Content-Encoding header to avoid browser decompression
        excluded_headers.add('Content-Encoding')

        if 'text/html' in content_type:
            # Fast path for empty or small responses
            if len(content) < 100:
                return Response(content, status=resp.status_code, 
                                headers={'Content-Type': 'text/html', **no_cache_headers})
                
            # Decode the content safely
            try:
                html_text = content.decode('utf-8', errors='ignore')
            except Exception as e:
                logger.warning(f"Error decoding HTML: {e}, passing through as-is")
                return Response(content, status=resp.status_code, 
                                headers={'Content-Type': 'text/html', **no_cache_headers})
            
            # Process specific link types with targeted replacement patterns
            # This is much faster than using BeautifulSoup for large HTML documents
            
            # Process <a> tags with faster replacements
            def process_link(match):
                prefix = match.group(1)
                href = match.group(2)
                suffix = match.group(3)

                # Always resolve href to an absolute URL
                absolute_url = urljoin(target_url, href)

                # Build the proxied URL with both `url` and `origin` parameters
                proxied_url = f"/xorcipher?url={quote(absolute_url)}&origin={quote(target_url)}"

                return f'<a {prefix}href="{proxied_url}"{suffix}>'

            # Replace all <a href="..."> with proxied URLs
            html_text = re.sub(
                r'<a\s+([^>]*?)href=[\'"]([^\'"]+)[\'"]([^>]*?)>',
                process_link,
                html_text,
                flags=re.IGNORECASE
            )

            
            # Simplify and just return the processed HTML - no additional base tags
            # This is faster and more reliable
            
            # Create optimized headers
            response_headers = {
                'Content-Type': 'text/html',
                'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
                'Pragma': 'no-cache',
                'Expires': '0'
            }
            
            logger.debug(f"Modified HTML in {time.time() - start_time:.3f}s")
            return Response(html_text, status=resp.status_code, headers=response_headers)

        # Not HTML - return as-is with appropriate caching
        response_headers = {k: v for k, v in resp.headers.items() if k not in excluded_headers}
        
        # Cache static resources if appropriate
        if cache_key and is_static_resource(target_url):
            # Allowa caching for static resources
            response_headers['Cache-Control'] = 'public, max-age=86400'  # 24 hours
            response = Response(content, status=resp.status_code, headers=response_headers)
            resource_cache[cache_key] = response
            # Limit cache size to prevent memory issues
            if len(resource_cache) > 1000:
                # Remove random entries if cache gets too large
                for _ in range(100):
                    resource_cache.pop(next(iter(resource_cache)))
            return response
        else:
            # Dynamic content - no caching
            response_headers.update(no_cache_headers)
            return Response(content, status=resp.status_code, headers=response_headers)

    except Exception as e:
        logger.error(f"Proxy error: {e}")
        return f"Error: {e}", 500

@app.route("/iframe")
def iframe():
    """Serve the iframe content for the browser"""
    return render_template('newtab.html')

@app.route("/newtab")
def newtab():
    """Serve the tabs-based browser interface"""
    return render_template('browser.html')

# Authentication routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    # If user is already logged in, redirect to index
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    from forms import LoginForm
    form = LoginForm()
    
    if form.validate_on_submit():
        # Check if username or email was provided
        user = None
        if form.username.data and '@' in form.username.data:
            user = User.query.filter_by(email=form.username.data).first()
        else:
            user = User.query.filter_by(username=form.username.data).first()
        
        # Verify user and password
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password', 'danger')
            return redirect(url_for('login'))
        
        # Check if account is active
        if not user.is_active:
            flash('This account has been deactivated', 'danger')
            return redirect(url_for('login'))
        
        # Save fingerprint if provided
        if form.fingerprint.data:
            try:
                fingerprint_data = json.loads(form.fingerprint.data)
                user.set_fingerprint(fingerprint_data)
            except:
                logger.warning(f"Failed to parse fingerprint data for user {user.id}")
        
        # Save IP address
        user.ip_address = request.remote_addr
        
        # Login user and set session
        login_user(user, remember=form.remember_me.data)
        
        # Update last login timestamp
        user.last_login = datetime.datetime.utcnow()
        db.session.commit()
        
        # Redirect to requested page or home
        next_page = request.args.get('next')
        if not next_page or urlparse(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)
    
    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    # If user is already logged in, redirect to index
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    from forms import RegistrationForm
    form = RegistrationForm()
    
    if form.validate_on_submit():
        # Check if username already exists
        username_exists = User.query.filter_by(username=form.username.data).first()
        if username_exists:
            flash('Username already taken', 'danger')
            return render_template('signup.html', form=form)
            
        # Check if email already exists
        email_exists = User.query.filter_by(email=form.email.data).first()
        if email_exists:
            flash('Email already registered', 'danger')
            return render_template('signup.html', form=form)
            
        # Check IP restrictions
        ip_address = request.remote_addr
        existing_ip = IPRegistration.query.filter_by(ip_address=ip_address).first()
        if existing_ip:
            flash('An account already exists from this IP address.', 'danger')
            return render_template('signup.html', form=form)
            
        # Create new user
        user = User(
            username=form.username.data, 
            email=form.email.data,
            ip_address=request.remote_addr
        )
        user.set_password(form.password.data)
        
        # Save fingerprint if provided
        if form.fingerprint.data:
            try:
                fingerprint_data = json.loads(form.fingerprint.data)
                user.set_fingerprint(fingerprint_data)
            except:
                logger.warning("Failed to parse fingerprint data")
        
        # Add and commit to database
        db.session.add(user)
        db.session.flush()  # Flush to get the user ID
        
        # Create IP registration record
        ip_reg = IPRegistration(
            ip_address=request.remote_addr,
            user_id=user.id
        )
        db.session.add(ip_reg)
        
        try:
            db.session.commit()
            flash('Account created successfully! You can now log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error creating user: {e}")
            flash('There was an error creating your account. Please try again.', 'danger')
    
    return render_template('signup.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

# User profile route
@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

# Chat routes
@app.route('/chat')
@login_required
def chat_home():
    from forms import MessageForm, GroupChatForm, AddUsersForm
    from models import ChatGroup, Message
    
    message_form = MessageForm()
    group_form = GroupChatForm()
    add_users_form = AddUsersForm()
    
    # Get user's groups
    user_groups = current_user.groups
    
    # Default to first group if user has any
    active_group = None
    messages = []
    
    first_group = user_groups[0] if user_groups else None
    if first_group:
        active_group = first_group
        messages = active_group.messages.order_by(Message.timestamp).all()
    
    return render_template('chat.html', 
                          active_group=active_group, 
                          messages=messages, 
                          form=message_form, 
                          group_form=group_form,
                          add_users_form=add_users_form)

@app.route('/chat/<int:group_id>')
@login_required
def chat_group(group_id):
    from forms import MessageForm, GroupChatForm, AddUsersForm
    from models import ChatGroup, Message

    message_form = MessageForm()
    group_form = GroupChatForm()
    add_users_form = AddUsersForm()

    # Check if group exists and user is a member
    group = ChatGroup.query.get_or_404(group_id)
    if current_user not in group.members:
        flash('You are not a member of this group', 'danger')
        return redirect(url_for('chat_home'))

    # Get messages from the group
    messages = group.messages.order_by(Message.timestamp).all()

    # Get the most recent message (if exists)
    recent_message = messages[-1] if messages else None

    return render_template('chat.html', 
                          active_group=group, 
                          messages=messages, 
                          form=message_form, 
                          group_form=group_form,
                          add_users_form=add_users_form,
                          recent_message=recent_message)

@app.route('/chat/create-group', methods=['POST'])
@login_required
def create_group():
    from forms import GroupChatForm
    from models import ChatGroup, User, Message
    
    form = GroupChatForm()
    
    if form.validate_on_submit():
        # Create new group
        group = ChatGroup(
            name=form.name.data,
            description=form.description.data,
            is_private=form.is_private.data,
            created_by_id=current_user.id
        )
        
        # Add creator as a member
        group.members.append(current_user)
        
        # Save to database
        db.session.add(group)
        db.session.commit()
        
        # Process invitations if it's a private group
        if form.is_private.data and form.invite_usernames.data:
            invited_count = 0
            not_found_usernames = []
            
            # Parse the usernames from the textarea (one per line)
            usernames = []
            if form.invite_usernames.data:
                usernames = [username.strip() for username in form.invite_usernames.data.split('\n') if username.strip()]
            
            for username in usernames:
                user = User.query.filter_by(username=username).first()
                
                if user and user != current_user:  # Avoid inviting self
                    # Add user to the group
                    if user not in group.members:
                        group.members.append(user)
                        invited_count += 1
                        
                        # Create a system message in the group about the invitation
                        system_message = Message(
                            content=f"{user.username} was invited to the group by {current_user.username}",
                            sender_id=current_user.id,
                            group_id=group.id,
                            message_type="system"
                        )
                        db.session.add(system_message)
                else:
                    if username != current_user.username:  # Don't report self as not found
                        not_found_usernames.append(username)
            
            # Commit all changes
            db.session.commit()
            
            # Show feedback about invitations
            if invited_count > 0:
                flash(f'Invited {invited_count} user(s) to the group', 'success')
            
            # Report users not found
            if not_found_usernames:
                flash(f'Could not find users: {", ".join(not_found_usernames)}', 'warning')
        
        flash(f'Group "{group.name}" created successfully!', 'success')
        return redirect(url_for('chat_group', group_id=group.id))
    
    # If validation fails, return to chat home with errors
    flash('Failed to create group. Please check the form.', 'danger')
    return redirect(url_for('chat_home'))

@app.route('/chat/<int:group_id>/send', methods=['POST'])
@login_required
def send_message(group_id):
    from forms import MessageForm
    from models import ChatGroup, Message
    
    form = MessageForm()
    
    if form.validate_on_submit():
        # Check if group exists and user is a member
        group = ChatGroup.query.get_or_404(group_id)
        if current_user not in group.members:
            flash('You are not a member of this group', 'danger')
            return redirect(url_for('chat_home'))
        
        # Create new message
        message = Message(
            content=form.content.data,
            sender_id=current_user.id,
            group_id=group.id
        )
        
        # Save to database
        db.session.add(message)
        db.session.commit()
        
        # Emit socket event with the new message
        message_data = {
            'id': message.id,
            'content': message.content,
            'sender_id': message.sender_id,
            'sender_username': current_user.username,
            'timestamp': message.timestamp.strftime('%H:%M')
        }
        
        # Broadcast to all clients in the room
        socketio.emit('receive_message', message_data, to=str(group_id))
        
    return redirect(url_for('chat_group', group_id=group_id))

# API endpoint for fingerprinting
@app.route('/api/fingerprint', methods=['POST'])
@login_required
def save_fingerprint():
    if not request.is_json:
        return jsonify({'error': 'Invalid request format'}), 400
    
    data = request.get_json()
    
    fingerprint = data.get('fingerprint')
    fingerprint_hash = data.get('fingerprintHash')
    
    if not fingerprint:
        return jsonify({'error': 'Missing fingerprint data'}), 400
    
    # Save fingerprint to user
    current_user.set_fingerprint(fingerprint)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Fingerprint saved'})

# Route for adding users to an existing group
@app.route('/chat/<int:group_id>/add-users', methods=['POST'])
@login_required
def add_users_to_group(group_id):
    from forms import AddUsersForm
    from models import ChatGroup, User, Message
    
    form = AddUsersForm()
    
    # Check if group exists and user is a member
    group = ChatGroup.query.get_or_404(group_id)
    
    # Only allow adding users to private groups
    if not group.is_private:
        flash('Cannot add users to a public group', 'danger')
        return redirect(url_for('chat_group', group_id=group_id))
    
    # Only allow group creator or admin to add users
    if group.created_by_id != current_user.id:
        flash('Only the group creator can add users', 'danger')
        return redirect(url_for('chat_group', group_id=group_id))
    
    if form.validate_on_submit():
        added_count = 0
        not_found_usernames = []
        already_in_group = []
        
        # Parse the usernames from the textarea (one per line)
        usernames = []
        if form.usernames.data:
            usernames = [username.strip() for username in form.usernames.data.split('\n') if username.strip()]
        
        for username in usernames:
            user = User.query.filter_by(username=username).first()
            
            if user:
                # Check if user is already in the group
                if user in group.members:
                    already_in_group.append(username)
                    continue
                
                # Add user to the group
                group.members.append(user)
                added_count += 1
                
                # Create a system message in the group about the new user
                system_message = Message(
                    content=f"{user.username} was added to the group by {current_user.username}",
                    sender_id=current_user.id,
                    group_id=group.id,
                    message_type="system"
                )
                db.session.add(system_message)
                
                # Also prepare to emit this system message via WebSocket
            else:
                not_found_usernames.append(username)
        
        # Commit all changes
        db.session.commit()
        
        # Emit system messages via WebSocket
        if added_count > 0:
            # Create notification data for the front-end
            notification_data = {
                'content': f"{added_count} new user(s) added to the group",
                'sender_id': current_user.id,
                'sender_username': 'System',
                'timestamp': datetime.datetime.utcnow().strftime('%H:%M'),
                'message_type': 'system'
            }
            
            # Broadcast notification to all users in the group
            socketio.emit('receive_message', notification_data, to=str(group_id))
            
            # Show feedback
            flash(f'Added {added_count} user(s) to the group', 'success')
        
        # Report users not found
        if not_found_usernames:
            flash(f'Could not find users: {", ".join(not_found_usernames)}', 'warning')
            
        # Report users already in group
        if already_in_group:
            flash(f'Users already in group: {", ".join(already_in_group)}', 'info')
    
    return redirect(url_for('chat_group', group_id=group_id))

# Direct message API
@app.route('/api/messages/direct/<int:user_id>', methods=['GET', 'POST'])
@login_required
def direct_messages(user_id):
    from models import User, Message
    
    # Check if user exists
    recipient = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        # Send a direct message
        if not request.is_json:
            return jsonify({'error': 'Invalid request format'}), 400
        
        data = request.get_json()
        content = data.get('content')
        
        if not content or not content.strip():
            return jsonify({'error': 'Message cannot be empty'}), 400
        
        # Create message
        message = Message(
            content=content,
            sender_id=current_user.id,
            recipient_id=recipient.id
        )
        
        db.session.add(message)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': {
                'id': message.id,
                'content': message.content,
                'timestamp': message.timestamp.isoformat(),
                'sender': current_user.username
            }
        })
    else:
        # Get direct messages between current user and recipient
        sent_messages = Message.query.filter_by(
            sender_id=current_user.id, 
            recipient_id=recipient.id,
            group_id=None
        ).all()
        
        received_messages = Message.query.filter_by(
            sender_id=recipient.id, 
            recipient_id=current_user.id,
            group_id=None
        ).all()
        
        # Combine and sort by timestamp
        all_messages = sorted(sent_messages + received_messages, 
                            key=lambda msg: msg.timestamp)
        
        # Format for JSON
        messages_json = [{
            'id': msg.id,
            'content': msg.content,
            'timestamp': msg.timestamp.isoformat(),
            'sender': msg.sender.username,
            'is_sent': msg.sender_id == current_user.id
        } for msg in all_messages]
        
        return jsonify({
            'success': True,
            'messages': messages_json
        })

# Socket.IO event handlers
@socketio.on('connect')
def handle_connect():
    logger.info(f"Client connected: {request.sid}")

@socketio.on('disconnect')
def handle_disconnect():
    logger.info(f"Client disconnected: {request.sid}")

@socketio.on('join')
def handle_join(data):
    """Event for a client joining a chat room"""
    if not current_user.is_authenticated:
        return False
    
    room = data.get('room')
    if not room:
        return False
    
    # Check if group exists and user is a member
    group = ChatGroup.query.get(int(room))
    if not group or current_user not in group.members:
        return False
    
    join_room(room)
    logger.info(f"User {current_user.username} joined room: {room}")
    return True

@socketio.on('leave')
def handle_leave(data):
    """Event for a client leaving a chat room"""
    room = data.get('room')
    if room:
        leave_room(room)
        logger.info(f"User {current_user.username} left room: {room}")

@socketio.on('send_message')
def handle_send_message(data):
    """Event for sending a message to a chat room with enhanced performance and tracking"""
    start_time = time.time()
    logger.debug(f"Socket message received: {data}")
    
    if not current_user.is_authenticated:
        logger.warning("Unauthenticated message attempt")
        return {'success': False, 'error': 'Authentication required'}
    
    room = data.get('room')
    content = data.get('content')
    message_id = data.get('message_id')  # Client-generated message ID for tracking
    
    if not room or not content or not content.strip():
        logger.warning(f"Invalid message data: room={room}, content_empty={not content or not content.strip()}")
        return {'success': False, 'error': 'Invalid message data'}
    
    try:
        # Check if group exists and user is a member - optimized query
        group = ChatGroup.query.get(int(room))
        if not group or current_user not in group.members:
            logger.warning(f"User {current_user.id} not member of group {room}")
            return {'success': False, 'error': 'Not a member of this group'}
        
        # Create and save message - transaction optimized
        message = Message(
            content=content,
            sender_id=current_user.id,
            group_id=group.id
        )
        
        db.session.add(message)
        db.session.commit()
        
        # Broadcast message to all users in the room
        message_data = {
            'id': message.id,
            'client_message_id': message_id,  # Return the client ID for tracking
            'content': message.content,
            'sender_id': message.sender_id,
            'sender_username': current_user.username,
            'timestamp': message.timestamp.strftime('%H:%M')
        }
        
        # Force immediate broadcast to all clients in the room
        # Use method that guarantees delivery across all users
        socketio.emit('receive_message', message_data, to=room)
        
        # Log performance metrics
        processing_time = time.time() - start_time
        logger.debug(f"Message processed in {processing_time:.3f}s: user={current_user.id}, group={room}")
        
        return {'success': True, 'message_id': message.id, 'client_message_id': message_id}
    except Exception as e:
        logger.error(f"Error sending message: {e}")
        db.session.rollback()
        return {'success': False, 'error': str(e)}

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', debug=True, port=5000, allow_unsafe_werkzeug=True, use_reloader=True, log_output=True)
