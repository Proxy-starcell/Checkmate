from app import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
import json

# We will define the association table after both User and ChatGroup models

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)  # IPv6 can be up to 45 chars
    browser_fingerprint = db.Column(db.String(1024), nullable=True)  # Store fingerprint hash
    
    # Define sent messages relationship
    sent_messages = db.relationship('Message', 
                                    foreign_keys='Message.sender_id',
                                    lazy='dynamic',
                                    backref=db.backref('sender', lazy=True))
    
    # Many-to-many relationship with ChatGroup
    groups = db.relationship('ChatGroup', secondary='user_group', 
                              backref=db.backref('members', lazy='dynamic'))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
        
    def set_fingerprint(self, fingerprint_data):
        """Store browser fingerprint data"""
        if isinstance(fingerprint_data, dict):
            self.browser_fingerprint = json.dumps(fingerprint_data)
        else:
            self.browser_fingerprint = str(fingerprint_data)
            
    def get_fingerprint(self):
        """Get browser fingerprint data"""
        if not self.browser_fingerprint:
            return None
        try:
            return json.loads(self.browser_fingerprint)
        except:
            return self.browser_fingerprint
            
    def matches_fingerprint(self, new_fingerprint):
        """Compare stored fingerprint with new one"""
        stored = self.get_fingerprint()
        if not stored:
            return False
            
        # Basic matching for string fingerprints
        if isinstance(stored, str) and isinstance(new_fingerprint, str):
            return stored == new_fingerprint
            
        # Component-based matching for dictionary fingerprints
        if isinstance(stored, dict) and isinstance(new_fingerprint, dict):
            # Match critical browser components (more reliable parts)
            critical_components = ['userAgent', 'language', 'platform', 'screenResolution']
            matches = 0
            total_components = len(critical_components)
            
            for component in critical_components:
                if component in stored and component in new_fingerprint:
                    if stored[component] == new_fingerprint[component]:
                        matches += 1
            
            # Require at least 75% match
            return (matches / total_components) >= 0.75
            
        return False

    def __repr__(self):
        return f'<User {self.username}>'


class ChatGroup(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    description = db.Column(db.String(512))
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    is_private = db.Column(db.Boolean, default=False)
    
    # Creator relationship
    created_by = db.relationship('User', foreign_keys=[created_by_id])
    
    # Messages in this group - no backref to avoid conflicts
    messages = db.relationship('Message', lazy='dynamic',
                               primaryjoin="Message.group_id == ChatGroup.id")
    
    def __repr__(self):
        return f'<ChatGroup {self.name}>'


# Association table for many-to-many relationship between User and ChatGroup
user_group = db.Table('user_group',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('group_id', db.Integer, db.ForeignKey('chat_group.id'), primary_key=True),
    db.Column('joined_at', db.DateTime, default=datetime.datetime.utcnow),
    db.Column('is_admin', db.Boolean, default=False)
)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    # Sender information (who sent the message)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # Message can be in a group or directed to another user
    group_id = db.Column(db.Integer, db.ForeignKey('chat_group.id'), nullable=True)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    # Relationships for messages
    # No need to define sender relationship here since it's defined in User class
    chat_group = db.relationship('ChatGroup', foreign_keys=[group_id], overlaps="messages")
    recipient = db.relationship('User', foreign_keys=[recipient_id], backref='received_messages')

    # Message status
    read = db.Column(db.Boolean, default=False)
    read_at = db.Column(db.DateTime, nullable=True)

    # Optional: This could be an optional field to specify message type (e.g., 'text', 'image', 'file')
    message_type = db.Column(db.String(50), default='text')

    def mark_as_read(self):
        """Mark the message as read and set the timestamp"""
        self.read = True
        self.read_at = datetime.datetime.utcnow()
        db.session.commit()

    def __repr__(self):
        if self.chat_group:
            return f'<Message {self.id} in Group {self.chat_group.name} from ID {self.sender_id}>'
        elif self.recipient:
            return f'<Message {self.id} to {self.recipient.username} from ID {self.sender_id}>'
        else:
            return f'<Message {self.id} from ID {self.sender_id}>'


class IPRegistration(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False)  # IPv6 can be up to 45 chars
    first_seen = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    banned = db.Column(db.Boolean, default=False)
    
    # Relationship with User
    user = db.relationship('User')
    
    def __repr__(self):
        return f'<IPRegistration {self.ip_address}, User: {self.user_id}>'
