from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

db = SQLAlchemy()


class User(db.Model):
    """User model for authentication and user management"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    detections = db.relationship('MalwareDetection', backref='user', lazy=True)
    notifications = db.relationship('Notification', backref='user', lazy=True)
    datasets = db.relationship('Dataset', backref='uploader', lazy=True)

    def set_password(self, password):
        """Set the password hash"""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Check if password matches the hash"""
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        """Convert user to dictionary for JSON response"""
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "is_admin": self.is_admin,
            "created_at": self.created_at.isoformat()
        }


class Dataset(db.Model):
    """Dataset model for storing uploaded datasets"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    file_path = db.Column(db.String(255), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    description = db.Column(db.Text)

    def to_dict(self):
        """Convert dataset to dictionary for JSON response"""
        return {
            "id": self.id,
            "name": self.name,
            "uploaded_at": self.uploaded_at.isoformat(),
            "uploaded_by": self.uploaded_by,
            "description": self.description
        }


class MalwareDetection(db.Model):
    """MalwareDetection model for storing URL analysis results"""
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(2048), nullable=False)
    is_malicious = db.Column(db.Boolean, default=False)
    confidence = db.Column(db.Float)
    malware_type = db.Column(db.String(50))
    details = db.Column(db.Text)
    risk_score = db.Column(db.Integer)  # 0-100
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def to_dict(self):
        """Convert detection to dictionary for JSON response"""
        return {
            "id": self.id,
            "url": self.url,
            "is_malicious": self.is_malicious,
            "confidence": self.confidence,
            "malware_type": self.malware_type,
            "details": self.details,
            "risk_score": self.risk_score,
            "created_at": self.created_at.isoformat(),
            "user_id": self.user_id
        }


class Notification(db.Model):
    """Notification model for user and system notifications"""
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    read = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # None for global notifications

    def to_dict(self):
        """Convert notification to dictionary for JSON response"""
        return {
            "id": self.id,
            "message": self.message,
            "created_at": self.created_at.isoformat(),
            "read": self.read,
            "user_id": self.user_id
        }