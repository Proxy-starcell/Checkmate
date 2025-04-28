from flask_wtf import FlaskForm, CSRFProtect
from flask import current_app

# Initialize CSRF protection for app
csrf = CSRFProtect()
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField, HiddenField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError, Optional
import re
import dns.resolver
from flask import request, current_app
import json

class LoginForm(FlaskForm):
    username = StringField('Username or Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    fingerprint = HiddenField('Browser Fingerprint')
    submit = SubmitField('Sign In')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(), 
        Length(min=3, max=64, message="Username must be between 3 and 64 characters")
    ])
    email = StringField('Email', validators=[
        DataRequired(), 
        Email(message="Not a valid email address")
    ])
    password = PasswordField('Password', validators=[
        DataRequired(), 
        Length(min=8, message="Password must be at least 8 characters")
    ])
    password2 = PasswordField('Repeat Password', validators=[
        DataRequired(), 
        EqualTo('password', message="Passwords must match")
    ])
    fingerprint = HiddenField('Browser Fingerprint')
    submit = SubmitField('Register')

    def validate_username(self, username):
        # Check if username contains only allowed characters
        pattern = r'^[a-zA-Z0-9_\-\.]+$'
        if not re.match(pattern, username.data):
            raise ValidationError('Username can only contain letters, numbers, underscores, hyphens, and periods')
        
        # We'll check if username exists in the app view function
        # to avoid circular imports

    def validate_email(self, email):
        # Regex pattern for email
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(pattern, email.data):
            raise ValidationError('Invalid email format')
        
        # We'll check if email exists in the app view function
        # to avoid circular imports
        
        # MX record lookup
        try:
            domain = email.data.split('@')[1]
            mx_records = dns.resolver.resolve(domain, 'MX')
            if not mx_records:
                raise ValidationError('Could not find mail exchange records for this domain')
        except Exception as e:
            raise ValidationError(f'Email domain validation failed: {str(e)}')
        
        # Custom business logic - check for disposable email domains
        disposable_domains = ['mailinator.com', 'tempmail.com', 'throwawaymail.com', 
                              'guerrillamail.com', 'yopmail.com', 'sharklasers.com',
                              'trashmail.com', 'temp-mail.org']
        if domain.lower() in disposable_domains:
            raise ValidationError('Disposable email domains are not allowed')
    
    # We'll do IP address validation in the route handler
    # to avoid circular imports


class MessageForm(FlaskForm):
    """Form for sending messages"""
    content = TextAreaField('Message', validators=[
        DataRequired(), 
        Length(min=1, max=2000, message="Message must be between 1 and 2000 characters")
    ])
    submit = SubmitField('Send')


class GroupChatForm(FlaskForm):
    """Form for creating a new group chat"""
    name = StringField('Group Name', validators=[
        DataRequired(),
        Length(min=3, max=64, message="Group name must be between 3 and 64 characters")
    ])
    description = TextAreaField('Description', validators=[
        Optional(),
        Length(max=512, message="Description cannot exceed 512 characters")
    ])
    is_private = BooleanField('Private Group')
    invite_usernames = TextAreaField('Invite Users (one username per line)', validators=[
        Optional()
    ])
    submit = SubmitField('Create Group')


class FingerprintForm(FlaskForm):
    """Form for handling browser fingerprint data"""
    fingerprint_data = HiddenField('Fingerprint Data')
    fingerprint_hash = HiddenField('Fingerprint Hash')
    submit = SubmitField('Update')


class AddUsersForm(FlaskForm):
    """Form for adding users to an existing group chat"""
    usernames = TextAreaField('Add Users (one username per line)', validators=[
        DataRequired(),
        Length(min=1, max=1000, message="Please enter at least one username")
    ])
    submit = SubmitField('Add Users')
