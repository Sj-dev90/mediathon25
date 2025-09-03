# app.py
from flask import Flask, request, jsonify, send_from_directory
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
import datetime
import uuid

# ----------------------
# Init
# ----------------------
app = Flask(__name__)

# Config
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['JWT_SECRET_KEY'] = 'supersecretkey'  # change in production
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
CORS(app)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# ----------------------
# Models
# ----------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Injection(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    injection_type = db.Column(db.String(50), nullable=False)  # basal, bolus, other
    note = db.Column(db.String(250), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class Schedule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    time = db.Column(db.String(20), nullable=False)

# ----------------------
# Routes
# ----------------------

@app.route('/')
def serve_frontend():
    """Serve the frontend HTML file"""
    return send_from_directory('static', 'trial1.html')

# ---------- User Routes ----------

@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    hashed_pw = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(name=data['name'], email=data['email'], password=hashed_pw)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User created successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(email=data['email']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        token = create_access_token(identity=str(user.id))
        return jsonify({"token": token}), 200
    return jsonify({"error": "Invalid credentials"}), 401

# ---------- Injection Routes ----------

@app.route('/log-dose', methods=['POST'])
@jwt_required()
def log_dose():
    user_id = get_jwt_identity()
    data = request.json
    injection_type = data.get("injection_type", "other").lower()
    note = data.get("note", "")

    if injection_type not in ["basal", "bolus", "other"]:
        return jsonify({"error": "Invalid injection type"}), 400

    # Lockout times (minutes)
    lockout_times = {"basal": 90, "bolus": 15, "other": 0}

    last_log = (
        Injection.query.filter_by(user_id=user_id, injection_type=injection_type)
        .order_by(Injection.timestamp.desc())
        .first()
    )

    if last_log:
        diff = (datetime.datetime.utcnow() - last_log.timestamp).total_seconds() / 60
        if diff < lockout_times[injection_type]:
            return jsonify({
                "error": f"Too soon to log another {injection_type} injection. Wait {lockout_times[injection_type]-int(diff)} more minutes."
            }), 400

    new_log = Injection(user_id=user_id, injection_type=injection_type, note=note)
    db.session.add(new_log)
    db.session.commit()
    return jsonify({"message": "Dose logged"}), 201

@app.route('/injection-history', methods=['GET'])
@jwt_required()
def injection_history():
    user_id = get_jwt_identity()
    logs = Injection.query.filter_by(user_id=user_id).order_by(Injection.timestamp.desc()).all()
    return jsonify([
        {
            "id": log.id,
            "type": log.injection_type,
            "note": log.note,
            "timestamp": log.timestamp.strftime("%Y-%m-%d %H:%M")
        } for log in logs
    ])

# ---------- Schedule Routes ----------

@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    existing_user = User.query.filter_by(email=data['email']).first()
    if existing_user:
        return jsonify({"error": "User already exists"}), 400
    hashed_pw = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(name=data['name'], email=data['email'], password=hashed_pw)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User created successfully"}), 201


@app.route('/dashboard', methods=['GET'])
@jwt_required()
def dashboard():
    user_id = get_jwt_identity()
    logs = Injection.query.filter_by(user_id=user_id).order_by(Injection.timestamp.desc()).all()
    schedule = Schedule.query.filter_by(user_id=user_id).order_by(Schedule.time).all()
    user = User.query.get(user_id)
    return jsonify({
        "logs": [
            {
                "type": log.injection_type,
                "note": log.note,
                "timestamp": log.timestamp.strftime("%Y-%m-%d %H:%M")
            } for log in logs
        ],
        "schedule": [s.time for s in schedule],
        "name": user.name
    })


@app.route('/schedule', methods=['POST'])
@jwt_required()
def set_schedule():
    user_id = get_jwt_identity()
    data = request.json
    times = data.get("times", [])

    if not isinstance(times, list):
        return jsonify({"error": "Times must be a list of strings"}), 400

    # Delete existing schedules for user to avoid duplicates
    Schedule.query.filter_by(user_id=user_id).delete()

    for t in times:
        if isinstance(t, str) and t.strip():
            new_time = Schedule(user_id=user_id, time=t.strip())
            db.session.add(new_time)

    db.session.commit()
    return jsonify({"message": "Schedule saved"}), 201
