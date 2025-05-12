import os
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.utils import secure_filename
import datetime
from database import db, User, Dataset, MalwareDetection, Notification
from detector import URLMalwareDetector
from config import config


def create_app(config_name='default'):
    """Create and configure the Flask application"""
    app = Flask(__name__)
    app.config.from_object(config[config_name])

    # Initialize extensions
    CORS(app)
    jwt = JWTManager(app)
    db.init_app(app)

    # Create required directories
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['MODEL_DIR'], exist_ok=True)

    # Initialize detector
    detector = URLMalwareDetector(
        model_path=app.config['MODEL_PATH'],
        word_tokenizer_path=app.config['TOKENIZER_PATH'],
        char_tokenizer_path=app.config['CHAR_TOKENIZER_PATH']
    )

    # Create database tables before first request
    with app.app_context():
        db.create_all()
        print("Database tables ensured.")

    # ==========================================================================
    # Authentication routes
    # ==========================================================================

    @app.route('/api/register', methods=['POST'])
    def register():
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        is_admin = data.get('is_admin', False)

        if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
            return jsonify({"message": "User already exists"}), 400

        user = User(username=username, email=email, is_admin=is_admin)
        user.set_password(password)

        db.session.add(user)
        db.session.commit()

        return jsonify({"message": "User created successfully"}), 201

    @app.route('/api/login', methods=['POST'])
    def login():
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            access_token = create_access_token(identity={'id': user.id, 'is_admin': user.is_admin})
            return jsonify({"token": access_token, "is_admin": user.is_admin, "user": user.email}), 200

        return jsonify({"message": "Invalid credentials"}), 401

    @app.route('/api/user/profile', methods=['GET'])
    @jwt_required()
    def get_user_profile():
        current_user_id = get_jwt_identity().get('id')
        user = User.query.get(current_user_id)

        if not user:
            return jsonify({"message": "User not found"}), 404

        return jsonify(user.to_dict()), 200

    # ==========================================================================
    # Admin routes
    # ==========================================================================

    @app.route('/api/admin/users', methods=['GET'])
    @jwt_required()
    def get_users():
        current_user = get_jwt_identity()
        if not current_user.get('is_admin'):
            return jsonify({"message": "Admin access required"}), 403

        users = User.query.all()
        return jsonify([user.to_dict() for user in users]), 200

    @app.route('/api/admin/users/<int:user_id>', methods=['PUT', 'DELETE'])
    @jwt_required()
    def manage_user(user_id):
        current_user = get_jwt_identity()
        if not current_user.get('is_admin'):
            return jsonify({"message": "Admin access required"}), 403

        user = User.query.get(user_id)
        if not user:
            return jsonify({"message": "User not found"}), 404

        if request.method == 'DELETE':
            db.session.delete(user)
            db.session.commit()
            return jsonify({"message": "User deleted successfully"}), 200

        if request.method == 'PUT':
            data = request.get_json()
            user.username = data.get('username', user.username)
            user.email = data.get('email', user.email)
            user.is_admin = data.get('is_admin', user.is_admin)

            if 'password' in data and data['password']:
                user.set_password(data['password'])

            db.session.commit()
            return jsonify({"message": "User updated successfully"}), 200

    @app.route('/api/admin/users', methods=['POST'])
    @jwt_required()
    def add_user():
        current_user = get_jwt_identity()
        if not current_user.get('is_admin'):
            return jsonify({"message": "Admin access required"}), 403

        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        is_admin = data.get('is_admin', False)

        if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
            return jsonify({"message": "User already exists"}), 400

        user = User(username=username, email=email, is_admin=is_admin)
        user.set_password(password)

        db.session.add(user)
        db.session.commit()

        return jsonify({"message": "User created successfully", "user": user.to_dict()}), 201

    @app.route('/api/admin/notifications', methods=['POST', 'GET'])
    @jwt_required()
    def manage_notifications():
        current_user = get_jwt_identity()
        if not current_user.get('is_admin'):
            return jsonify({"message": "Admin access required"}), 403

        if request.method == 'POST':
            data = request.get_json()
            message = data.get('message')
            user_id = data.get('user_id')  # Optional, None for all users

            notification = Notification(message=message, user_id=user_id)
            db.session.add(notification)
            db.session.commit()

            return jsonify({"message": "Notification created successfully"}), 201

        if request.method == 'GET':
            notifications = Notification.query.all()
            return jsonify([notification.to_dict() for notification in notifications]), 200

    @app.route('/api/admin/upload-dataset', methods=['POST'])
    @jwt_required()
    def upload_dataset():
        current_user = get_jwt_identity()
        if not current_user.get('is_admin'):
            return jsonify({"message": "Admin access required"}), 403

        if 'file' not in request.files:
            return jsonify({"message": "No file part"}), 400

        file = request.files['file']

        if file.filename == '':
            return jsonify({"message": "No selected file"}), 400

        if file:
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            dataset = Dataset(
                name=filename,
                file_path=file_path,
                uploaded_by=current_user.get('id')
            )
            db.session.add(dataset)
            db.session.commit()

            # Here you would trigger model training with the new dataset
            # For simplicity, we'll just acknowledge the upload

            return jsonify({
                "message": "Dataset uploaded successfully",
                "dataset_id": dataset.id
            }), 201

    @app.route('/api/admin/train-model', methods=['POST'])
    @jwt_required()
    def train_model():
        current_user = get_jwt_identity()
        if not current_user.get('is_admin'):
            return jsonify({"message": "Admin access required"}), 403

        data = request.get_json()
        dataset_id = data.get('dataset_id')

        dataset = Dataset.query.get(dataset_id)
        if not dataset:
            return jsonify({"message": "Dataset not found"}), 404

        try:
            # This would ideally be a background task
            # For simplicity, we'll just call it directly
            result = detector.train_model(dataset.file_path)

            return jsonify({
                "message": "Model training Finished",
                "status": result
            }), 200

        except Exception as e:
            return jsonify({
                "message": f"Error training model: {str(e)}"
            }), 500

    @app.route('/api/admin/datasets', methods=['GET'])
    @jwt_required()
    def list_datasets():
        current_user = get_jwt_identity()
        if not current_user.get('is_admin'):
            return jsonify({"message": "Admin access required"}), 403

        datasets = Dataset.query.all()
        result = [dataset.to_dict() for dataset in datasets]
        return jsonify(result), 200

    @app.route('/api/admin/stats', methods=['GET'])
    @jwt_required()
    def get_stats():
        current_user = get_jwt_identity()
        if not current_user.get('is_admin'):
            return jsonify({"message": "Admin access required"}), 403

        days = request.args.get('days', 7, type=int)
        if days not in [7, 14, 28]:
            days = 7

        # Calculate date range
        end_date = datetime.datetime.now()
        start_date = end_date - datetime.timedelta(days=days)

        # Get detections in date range
        detections = MalwareDetection.query.filter(
            MalwareDetection.created_at.between(start_date, end_date)
        ).all()

        # Count by type
        type_counts = {}
        for detection in detections:
            if detection.malware_type:
                type_counts[detection.malware_type] = type_counts.get(detection.malware_type, 0) + 1

        # Sort types by count
        sorted_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)
        top_5_types = sorted_types[:5] if len(sorted_types) > 5 else sorted_types

        # Count URLs and users
        total_urls = len(detections)
        unique_users = len(set(d.user_id for d in detections if d.user_id))

        return jsonify({
            "total_urls_detected": total_urls,
            "unique_users": unique_users,
            "top_malware_types": dict(top_5_types),
            "time_period_days": days
        }), 200

    @app.route('/api/admin/recent-detections', methods=['GET'])
    @jwt_required()
    def get_recent_detections():
        current_user = get_jwt_identity()
        if not current_user.get('is_admin'):
            return jsonify({"message": "Admin access required"}), 403

        limit = request.args.get('limit', 10, type=int)

        detections = MalwareDetection.query.order_by(
            MalwareDetection.created_at.desc()
        ).limit(limit).all()

        return jsonify([detection.to_dict() for detection in detections]), 200

    # ==========================================================================
    # User routes
    # ==========================================================================

    @app.route('/api/analyze-url', methods=['POST'])
    @jwt_required(optional=True)
    def analyze_url():
        data = request.get_json()
        url = data.get('url')

        if not url:
            return jsonify({"message": "URL is required"}), 400

        result = detector.predict(url)

        # Calculate risk score
        risk_score = int(result.get('confidence', 0) * 100) if result.get('is_malicious') else 5

        # Log the detection
        current_user = get_jwt_identity()
        user_id = current_user.get('id') if current_user else None

        detection = MalwareDetection(
            url=url,
            is_malicious=result.get('is_malicious', False),
            confidence=result.get('confidence', 0),
            malware_type=result.get('malware_type'),
            details=result.get('details'),
            risk_score=risk_score,
            user_id=user_id
        )
        db.session.add(detection)
        db.session.commit()

        return jsonify({
            "result": result,
            "detection_id": detection.id
        }), 200

    @app.route('/api/scan/<int:id>', methods=['GET'])
    @jwt_required(optional=True)
    def get_scan(id):
        detection = MalwareDetection.query.get(id)

        if not detection:
            return jsonify({"message": "Scan not found"}), 404

        # Extract URL features
        if detection.is_malicious:
            features = detector.extract_features(detection.url)
            feature_names = [
                'url_length', 'domain_length', 'path_length',
                'num_digits', 'num_letters', 'num_special',
                'dots', 'slashes', 'hyphens', 'underscores',
                'equals', 'ats', 'questions', 'ampersands',
                'percents', 'has_ip', 'suspicious_tld'
            ]
            feature_dict = dict(zip(feature_names, features))
            detection_dict = detection.to_dict()
            detection_dict['features'] = feature_dict
            return jsonify(detection_dict), 200

        return jsonify(detection.to_dict()), 200

    @app.route('/api/user/history', methods=['GET'])
    @jwt_required()
    def get_user_history():
        current_user = get_jwt_identity()
        user_id = current_user.get('id')

        detections = MalwareDetection.query.filter_by(user_id=user_id).order_by(
            MalwareDetection.created_at.desc()
        ).all()

        return jsonify([detection.to_dict() for detection in detections]), 200

    @app.route('/api/user/notifications', methods=['GET'])
    @jwt_required()
    def get_user_notifications():
        current_user = get_jwt_identity()
        user_id = current_user.get('id')

        # Get both user-specific and global notifications
        notifications = Notification.query.filter(
            (Notification.user_id == user_id) | (Notification.user_id.is_(None))
        ).order_by(Notification.created_at.desc()).all()

        return jsonify([notification.to_dict() for notification in notifications]), 200

    return app


if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)