# Import necessary libraries
import os
import pyotp
import qrcode
import jwt
import datetime
from datetime import UTC
from flask import Flask, request, render_template, redirect, url_for, flash, session, make_response, send_file, abort
from cryptography.fernet import Fernet
from config import FERNET_KEY
cipher = Fernet(FERNET_KEY)
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
import re
from cryptography.fernet import Fernet
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import csv
from io import StringIO, BytesIO
from sqlalchemy.sql import text
from forms import PrescriptionForm

# Initialize Flask application
app = Flask(__name__)
app.secret_key = os.urandom(24).hex()
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///secure_health.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Email configuration (replace with your SMTP settings)
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
SMTP_USERNAME = 'mohamednasserelmasry123@gmail.com'  # Replace with your real Gmail address
SMTP_PASSWORD = 'qhvn qbnr smqp vbcz'  # Replace with your Gmail App Password

# JWT Configuration
JWT_SECRET = os.urandom(32).hex()
JWT_ALGORITHM = 'HS256'
JWT_EXPIRATION_MINUTES = 30



# Initialize SQLAlchemy
db = SQLAlchemy(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@app.template_filter('attribute')
def attribute(obj, attr):
    return getattr(obj, attr)

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200))
    totp_secret = db.Column(db.String(32))
    role = db.Column(db.String(10), default='Patient')  # Admin, Doctor, Patient
    email = db.Column(db.String(150), unique=True, nullable=False)
    name = db.Column(db.String(150))
    is_active = db.Column(db.Boolean, default=True)
    permission = db.Column(db.String(10), default='read')
    phone_number = db.Column(db.String(20), nullable=True)
    specialty = db.Column(db.String(100), nullable=True)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def verify_totp(self, token):
        totp = pyotp.TOTP(self.totp_secret)
        return totp.verify(token)

class Patient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    medical_history = db.Column(db.Text)  # Encrypted
    user = db.relationship('User', backref=db.backref('patient', lazy=True))

class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), default='Scheduled')
    patient = db.relationship('User', foreign_keys=[patient_id], backref='appointments_as_patient')
    doctor = db.relationship('User', foreign_keys=[doctor_id], backref='appointments_as_doctor')

class Prescription(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    medication = db.Column(db.Text)  # Encrypted
    dosage = db.Column(db.Text)  # Encrypted
    issued_at = db.Column(db.DateTime, default=datetime.datetime.now(UTC))

class Diagnosis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    diagnosis = db.Column(db.Text)  # Encrypted
    notes = db.Column(db.Text)  # Encrypted
    created_at = db.Column(db.DateTime, default=datetime.datetime.now(UTC))

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    action = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.now(UTC))
    details = db.Column(db.Text)

class PasswordResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(100), unique=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)

# Flask-Login user loader
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Role-based decorator
def role_required(roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role not in roles:
                flash('Access denied.')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Password policy validation
def validate_password(password):
    if len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'[0-9]', password):
        return False
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False
    return True

# Generate JWT
def generate_jwt(username):
    payload = {
        'sub': username,
        'exp': datetime.datetime.now(UTC) + datetime.timedelta(minutes=JWT_EXPIRATION_MINUTES)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

# Verify JWT
def verify_jwt(token):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None

# Log actions
def log_action(user_id, action, details=None):
    audit_log = AuditLog(user_id=user_id, action=action, details=details)
    db.session.add(audit_log)
    db.session.commit()

# Send reset email
def send_reset_email(email, token):
    msg = MIMEMultipart()
    msg['From'] = SMTP_USERNAME
    msg['To'] = email
    msg['Subject'] = 'Password Reset Request'
    reset_url = url_for('reset_password', token=token, _external=True, _scheme='https')
    body = f"""
    Hello,
    Please click the link to reset your password: {reset_url}
    This link expires in 1 hour.
    """
    msg.attach(MIMEText(body, 'plain'))
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"Email error: {str(e)}")
        return False

# Initialize admin user
def init_admin_user():
    admin_username = 'admin'
    admin_email = 'admin@securehealth.com'
    admin_password = 'Admin123!'
    if not User.query.filter_by(username=admin_username).first():
        totp_secret = pyotp.random_base32()
        password_hash = generate_password_hash(admin_password)
        admin_user = User(
            username=admin_username,
            password_hash=password_hash,
            totp_secret=totp_secret,
            role='Admin',
            email=admin_email,
            name='Administrator'
        )
        db.session.add(admin_user)
        db.session.commit()
        log_action(admin_user.id, 'Admin Creation', 'Created admin user')

# Generate CSRF token
@app.before_request
def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = os.urandom(16).hex()

# Initialize database
with app.app_context():
    db.create_all()
    init_admin_user()

# Routes
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password_confirm = request.form['password_confirm']
        email = request.form['email']
        name = request.form['name']
        role = request.form['role']

        if password != password_confirm:
            flash('Passwords do not match.')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
            flash('Username or email already exists.')
            return redirect(url_for('register'))

        if not validate_password(password):
            flash('Password must be at least 8 characters with uppercase, lowercase, numbers, and special characters.')
            return redirect(url_for('register'))

        totp_secret = pyotp.random_base32()
        password_hash = generate_password_hash(password)
        user = User(username=username, password_hash=password_hash, totp_secret=totp_secret, email=email, name=name, role=role)
        db.session.add(user)
        db.session.commit()

        if role == 'Patient':
            patient = Patient(user_id=user.id, medical_history=cipher.encrypt(b"").decode())
            db.session.add(patient)
            db.session.commit()

        uri = pyotp.TOTP(totp_secret).provisioning_uri(name=username, issuer_name="SecureHealth")
        img = qrcode.make(uri)
        os.makedirs("static/qrcodes", exist_ok=True)
        img_path = f"static/qrcodes/{username}.png"
        img.save(img_path)

        log_action(user.id, 'User Registration', f'User {username} registered as {role}')
        flash("Scan the QR code and login with your OTP.")
        return redirect(url_for('two_factor', username=username))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.verify_password(password):
            log_action(user.id, 'Login Attempt', 'Successful password verification')
            return redirect(url_for('two_factor', username=username))
        else:
            log_action(None, 'Login Attempt', f'Failed login for {username}')
            flash('Invalid username or password.')
    return render_template('login.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('Email not registered.')
            return redirect(url_for('forgot_password'))

        token = os.urandom(32).hex()
        expires_at = datetime.datetime.now(UTC) + datetime.timedelta(hours=1)
        reset_token = PasswordResetToken(user_id=user.id, token=token, expires_at=expires_at, used=False)
        db.session.add(reset_token)
        db.session.commit()

        if send_reset_email(email, token):
            log_action(user.id, 'Password Reset Request', f'Reset requested for {email}')
            flash('Password reset link sent to your email.')
        else:
            flash('Error sending email.')
        return redirect(url_for('forgot_password'))

    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    reset_token = PasswordResetToken.query.filter_by(token=token, used=False).first()
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    if not reset_token or reset_token.expires_at.replace(tzinfo=datetime.timezone.utc) < now_utc:
        flash('Invalid or expired reset link.')
        return redirect(url_for('forgot_password'))

    user = db.session.get(User, reset_token.user_id)
    if not user:
        flash('User not found.')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form['password']
        password_confirm = request.form['password_confirm']
        if password != password_confirm:
            flash('Passwords do not match.')
            return redirect(url_for('reset_password', token=token))
        if not validate_password(password):
            flash('Password must meet the policy requirements.')
            return redirect(url_for('reset_password', token=token))
        user.password_hash = generate_password_hash(password)
        reset_token.used = True
        db.session.commit()
        log_action(user.id, 'Password Reset', f'Password reset for {user.email}')
        flash('Password reset successfully. You can now log in with your new password.')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)

@app.route('/reset_password/2fa/<token>', methods=['GET', 'POST'])
def reset_password_2fa(token):
    reset_token = PasswordResetToken.query.filter_by(token=token, used=False).first()
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    if not reset_token or reset_token.expires_at.replace(tzinfo=datetime.timezone.utc) < now_utc:
        flash('Invalid or expired reset link.')
        return redirect(url_for('forgot_password'))

    user = db.session.get(User, reset_token.user_id)
    if not user:
        flash('User not found.')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        otp = request.form['otp']
        if user.verify_totp(otp):
            session[f'reset_2fa_verified_{token}'] = True
            flash('2FA verified. Please reset your password.')
            return redirect(url_for('reset_password', token=token))
        else:
            flash('Invalid OTP.')

    uri = pyotp.TOTP(user.totp_secret).provisioning_uri(name=user.username, issuer_name="SecureHealth")
    img = qrcode.make(uri)
    os.makedirs("static/qrcodes", exist_ok=True)
    img_path = f"static/qrcodes/{user.username}_reset.png"
    img.save(img_path)
    return render_template('two_factor.html', username=user.username, qr_path=img_path, reset_password=True)

@app.route('/2fa', methods=['GET', 'POST'])
def two_factor():
    if request.method == 'POST':
        otp = request.form['otp']
        username = request.form['username']
        user = User.query.filter_by(username=username).first()
        if user and user.verify_totp(otp):
            login_user(user)
            session['is_2fa_verified'] = True
            token = generate_jwt(username)
            session['jwt'] = token
            log_action(user.id, '2FA Login', 'Successful 2FA verification')
            return redirect(url_for('dashboard'))
        else:
            log_action(user.id if user else None, '2FA Attempt', 'Failed 2FA verification')
            flash('Invalid OTP.')
            return redirect(url_for('two_factor', username=username))

    username = request.args.get('username')
    user = User.query.filter_by(username=username).first()
    if not user:
        flash("User not found.")
        return redirect(url_for('login'))

    uri = pyotp.TOTP(user.totp_secret).provisioning_uri(name=username, issuer_name="SecureHealth")
    img = qrcode.make(uri)
    os.makedirs("static/qrcodes", exist_ok=True)
    img_path = f"static/qrcodes/{username}.png"
    img.save(img_path)
    return render_template('two_factor.html', username=username, qr_path=img_path)

@app.route('/dashboard')
@login_required
def dashboard():
    if not session.get('is_2fa_verified'):
        return redirect(url_for('two_factor', username=current_user.username))

    token = session.get('jwt')
    decoded = verify_jwt(token)
    if not decoded:
        log_action(current_user.id, 'Session Expired', 'Session expired')
        flash('Session expired. Please login again.')
        return redirect(url_for('login'))

    if current_user.role == 'Patient':
        appointments = Appointment.query.filter_by(patient_id=current_user.id).all()
        prescriptions = (
            Prescription.query
            .filter_by(patient_id=current_user.id)
            .join(User, Prescription.doctor_id == User.id)
            .add_entity(User)
            .all()
        )
        class PrescriptionWithDoctor:
            def __init__(self, presc, doctor):
                self.id = presc.id
                self.patient_id = presc.patient_id
                self.doctor_id = presc.doctor_id
                try:
                    self.medication = cipher.decrypt(presc.medication.encode()).decode()
                except Exception:
                    self.medication = '[Decryption Failed]'
                try:
                    self.dosage = cipher.decrypt(presc.dosage.encode()).decode()
                except Exception:
                    self.dosage = '[Decryption Failed]'
                self.issued_at = presc.issued_at
                self.doctor = doctor

        prescriptions_with_doctor = [
            PrescriptionWithDoctor(presc, doctor) for presc, doctor in prescriptions
        ]
        response = make_response(render_template(
            'dashboard.html',
            role=current_user.role,
            appointments=appointments,
            prescriptions=prescriptions_with_doctor
        ))
    elif current_user.role == 'Doctor':
        # Get all appointments for the doctor
        appointments = Appointment.query.filter_by(doctor_id=current_user.id).all()
        
        # Get unique patients from appointments with full user details
        assigned_patients = (
            User.query
            .join(Appointment, User.id == Appointment.patient_id)
            .filter(Appointment.doctor_id == current_user.id)
            .distinct()
            .all()
        )
        
        response = make_response(render_template(
            'dashboard.html',
            role=current_user.role,
            appointments=appointments,
            assigned_patients=assigned_patients
        ))
    else:  # Admin
        appointments = Appointment.query.all()
        users = User.query.all()
        response = make_response(render_template('dashboard.html', role=current_user.role, appointments=appointments, users=users))

    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    return response

@app.route('/appointments/book', methods=['GET', 'POST'])
@login_required
@role_required(['Patient'])
def book_appointment():
    if request.method == 'POST':
        doctor_id = request.form['doctor_id']
        date = datetime.datetime.strptime(request.form['date'], '%Y-%m-%dT%H:%M')
        appointment = Appointment(patient_id=current_user.id, doctor_id=doctor_id, date=date)
        db.session.add(appointment)
        db.session.commit()
        log_action(current_user.id, 'Book Appointment', f'Booked appointment with doctor {doctor_id}')
        flash('Appointment booked successfully.')
        return redirect(url_for('dashboard'))
    specialties = db.session.query(User.specialty)\
                    .filter(User.role=='Doctor', User.specialty != None)\
                    .distinct().all()
    selected_specialty = request.args.get('specialty')
    doctors = []
    if selected_specialty:
        doctors = User.query.filter_by(role='Doctor', specialty=selected_specialty).all()
    return render_template('appointments.html', specialties=specialties, selected_specialty=selected_specialty, doctors=doctors)

@app.route('/appointments/cancel/<int:appt_id>', methods=['POST'])
@login_required
@role_required(['Patient'])
def cancel_appointment(appt_id):
    appt = Appointment.query.get_or_404(appt_id)
    if appt.patient_id != current_user.id:
        flash('You are not authorized to cancel this appointment.')
        return redirect(url_for('dashboard'))
    db.session.delete(appt)
    db.session.commit()
    log_action(current_user.id, 'Cancel Appointment', f'Cancelled appointment {appt_id}')
    flash('Appointment cancelled.')
    return redirect(url_for('dashboard'))

@app.route('/prescriptions/add', methods=['GET', 'POST'])
@login_required
@role_required(['Doctor'])
def add_prescription():
    # Show all patients (not just those with appointments)
    patients = Patient.query.join(User, Patient.user_id == User.id).all()
    # If you want only assigned patients, keep the old logic, but for all patients, use the above line.

    if request.method == 'POST':
        patient_id = request.form['patient_id']
        medication = cipher.encrypt(request.form['medication'].encode()).decode()
        dosage = cipher.encrypt(request.form['dosage'].encode()).decode()
        prescription = Prescription(patient_id=patient_id, doctor_id=current_user.id, medication=medication, dosage=dosage)
        db.session.add(prescription)
        db.session.commit()
        log_action(current_user.id, 'Add Prescription', f'Added prescription for patient {patient_id}')
        flash('Prescription added successfully.')
        return redirect(url_for('dashboard'))
    return render_template('prescriptions.html', patients=patients)

@app.route('/admin/manage_users', methods=['GET', 'POST'])
@login_required
@role_required(['Admin'])
def manage_users():
    if request.method == 'POST':
        action = request.form['action']
        if action == 'add_user':
            username = request.form['username']
            email = request.form['email']
            name = request.form['name']
            password = request.form['password']
            role = request.form['role']
            if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
                flash('Username or email exists.')
                return redirect(url_for('manage_users'))
            if not validate_password(password):
                flash('Invalid password format.')
                return redirect(url_for('manage_users'))
            totp_secret = pyotp.random_base32()
            password_hash = generate_password_hash(password)
            user = User(username=username, password_hash=password_hash, totp_secret=totp_secret, email=email, name=name, role=role)
            db.session.add(user)
            db.session.commit()
            log_action(current_user.id, 'User Creation', f'Created user: {username}')
            flash('User created.')
        elif action == 'delete':
            user_id = request.form['user_id']
            user = db.session.get(User, user_id)
            patient = Patient.query.filter_by(user_id=user_id).first()
            if patient:
                for appt in Appointment.query.filter_by(patient_id=user_id).all():
                    db.session.delete(appt)
                for presc in Prescription.query.filter_by(patient_id=user_id).all():
                    db.session.delete(presc)
                for diag in Diagnosis.query.filter_by(patient_id=user_id).all():
                    db.session.delete(diag)
                db.session.delete(patient)
            for appt in Appointment.query.filter_by(doctor_id=user_id).all():
                db.session.delete(appt)
            for presc in Prescription.query.filter_by(doctor_id=user_id).all():
                db.session.delete(presc)
            for diag in Diagnosis.query.filter_by(doctor_id=user_id).all():
                db.session.delete(diag)
            db.session.delete(user)
            db.session.commit()
            log_action(current_user.id, 'User Deletion', f'Deleted user: {user.username}')
            flash('User deleted.')
        elif action == 'toggle_active':
            user_id = request.form['user_id']
            user = db.session.get(User, user_id)
            user.is_active = not user.is_active
            db.session.commit()
            log_action(current_user.id, 'User Activation', f'Toggled active for user: {user.username}')
            flash('User activation status changed.')
        elif action == 'change_permission':
            user_id = request.form['user_id']
            permission = request.form['permission']
            user = db.session.get(User, user_id)
            user.permission = permission
            db.session.commit()
            log_action(current_user.id, 'Permission Change', f'Changed permission for user: {user.username} to {permission}')
            flash('User permission updated.')
        elif action == 'change_role':
            user_id = request.form['user_id']
            role = request.form['role']
            user = db.session.get(User, user_id)
            user.role = role
            db.session.commit()
            log_action(current_user.id, 'Role Change', f'Changed role for user: {user.username} to {role}')
            flash('User role updated.')
    users = User.query.all()
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(100).all()
    return render_template('admin.html', users=users, logs=logs)

@app.route('/admin_table/<table>', methods=['GET', 'POST'])
@login_required
@role_required(['Admin'])
def admin_table(table):
    model_map = {
        'user': User,
        'patient': Patient,
        'appointment': Appointment,
        'prescription': Prescription,
        'diagnosis': Diagnosis,
        'audit_log': AuditLog,
    }
    model = model_map.get(table)
    if not model:
        flash('Invalid table.')
        return redirect(url_for('manage_users'))

    if request.method == 'POST':
        if 'delete_id' in request.form:
            obj = model.query.get(request.form['delete_id'])
            db.session.delete(obj)
            db.session.commit()
            log_action(current_user.id, 'DB Delete', f'Deleted from {table}: {request.form["delete_id"]}')
            flash('Record deleted.')
    records = model.query.all()
    return render_template('admin_table.html', table=table, records=records)

@app.route('/admin_table/<table>/add', methods=['GET', 'POST'])
@login_required
@role_required(['Admin'])
def admin_table_add(table):
    model_map = {
        'user': User,
        'patient': Patient,
        'appointment': Appointment,
        'prescription': Prescription,
        'diagnosis': Diagnosis,
    }
    model = model_map.get(table)
    if not model:
        flash('Invalid table.')
        return redirect(url_for('admin_table', table=table))

    if request.method == 'POST':
        if table == 'user':
            username = request.form['username']
            email = request.form['email']
            name = request.form['name']
            password = request.form['password']
            role = request.form['role']
            is_active = 'is_active' in request.form
            permission = request.form['permission']
            if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
                flash('Username or email exists.')
                return redirect(url_for('admin_table_add', table=table))
            if not validate_password(password):
                flash('Invalid password format.')
                return redirect(url_for('admin_table_add', table=table))
            totp_secret = pyotp.random_base32()
            password_hash = generate_password_hash(password)
            user = User(username=username, password_hash=password_hash, totp_secret=totp_secret, email=email, name=name, role=role, is_active=is_active, permission=permission)
            db.session.add(user)
            db.session.commit()
            log_action(current_user.id, 'DB Insert', f'Added user: {username}')
            flash('User added.')
            return redirect(url_for('admin_table', table=table))
        flash('Add not implemented for this table.')
        return redirect(url_for('admin_table', table=table))

    return render_template('admin_table_add.html', table=table)

@app.route('/admin_table/<table>/edit/<int:record_id>', methods=['GET', 'POST'])
@login_required
@role_required(['Admin'])
def admin_table_edit(table, record_id):
    model_map = {
        'user': User,
        'patient': Patient,
        'appointment': Appointment,
        'prescription': Prescription,
        'diagnosis': Diagnosis,
    }
    model = model_map.get(table)
    if not model:
        flash('Invalid table.')
        return redirect(url_for('admin_table', table=table))

    obj = model.query.get(record_id)
    if not obj:
        abort(404)

    if request.method == 'POST':
        if table == 'user':
            obj.username = request.form['username']
            obj.email = request.form['email']
            obj.name = request.form['name']
            obj.role = request.form['role']
            obj.is_active = 'is_active' in request.form
            obj.permission = request.form['permission']
            password = request.form.get('password')
            if password:
                if not validate_password(password):
                    flash('Invalid password format.')
                    return redirect(url_for('admin_table_edit', table=table, record_id=record_id))
                obj.password_hash = generate_password_hash(password)
            db.session.commit()
            log_action(current_user.id, 'DB Update', f'Edited user: {obj.username}')
            flash('User updated.')
            return redirect(url_for('admin_table', table=table))
        flash('Edit not implemented for this table.')
        return redirect(url_for('admin_table', table=table))

    return render_template('admin_table_edit.html', table=table, record=obj)

@app.route('/admin/logs/export')
@login_required
@role_required(['Admin'])
def export_logs():
    logs = AuditLog.query.all()
    format = request.args.get('format', 'csv')
    if format == 'log':
        output = StringIO()
        for log in logs:
            output.write(f"{log.timestamp} | User {log.user_id} | {log.action} | {log.details}\n")
        data = output.getvalue().encode('utf-8')
        output_bytes = BytesIO(data)
        output_bytes.seek(0)
        return send_file(output_bytes, mimetype='text/plain', as_attachment=True, download_name='audit_logs.log')
    else:
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(['ID', 'User ID', 'Action', 'Timestamp', 'Details'])
        for log in logs:
            writer.writerow([log.id, log.user_id, log.action, log.timestamp, log.details])
        data = output.getvalue().encode('utf-8')
        output_bytes = BytesIO(data)
        output_bytes.seek(0)
        return send_file(output_bytes, mimetype='text/csv', as_attachment=True, download_name='audit_logs.csv')

@app.route('/logout')
@login_required
def logout():
    user_id = current_user.id
    logout_user()
    session.pop('jwt', None)
    session.pop('is_2fa_verified', None)
    log_action(user_id, 'Logout', 'User logged out')
    flash('Logged out successfully.')
    return redirect(url_for('login'))

@app.after_request
def apply_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if not session.get('is_2fa_verified'):
        return redirect(url_for('two_factor', username=current_user.username))

    token = session.get('jwt')
    decoded = verify_jwt(token)
    if not decoded:
        log_action(current_user.id, 'Session Expired', 'Session expired')
        flash('Session expired. Please login again.')
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        phone_number = request.form.get('phone_number')
        password = request.form.get('password')
        password_confirm = request.form.get('password_confirm')

        if not name or not email:
            flash('Name and email are required.')
            return redirect(url_for('profile'))

        existing_user = User.query.filter_by(email=email).first()
        if existing_user and existing_user.id != current_user.id:
            flash('Email already in use.')
            return redirect(url_for('profile'))

        current_user.name = name
        current_user.email = email
        current_user.phone_number = phone_number
        if current_user.role == 'Doctor':
            specialty = request.form.get('specialty')
            current_user.specialty = specialty
        if password and password_confirm:
            if password != password_confirm:
                flash('Passwords do not match.')
                return redirect(url_for('profile'))
            if not validate_password(password):
                flash('Password must meet the policy requirements.')
                return redirect(url_for('profile'))
            current_user.password_hash = generate_password_hash(password)

        db.session.commit()
        log_action(current_user.id, 'Profile Update', f'Updated profile for {current_user.username}')
        flash('Profile updated successfully.')
        return redirect(url_for('profile'))

    response = make_response(render_template('profile.html', user=current_user))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    return response

@app.route('/doctor/patient/<int:patient_id>')
@login_required
@role_required(['Doctor'])
def view_patient(patient_id):
    patient = Patient.query.filter_by(user_id=patient_id).first()
    if not patient:
        flash('Patient not found.')
        return redirect(url_for('dashboard'))

    prescriptions = Prescription.query.filter_by(patient_id=patient_id, doctor_id=current_user.id).all()
    diagnoses = Diagnosis.query.filter_by(patient_id=patient_id, doctor_id=current_user.id).all()

    decrypted_prescriptions = []
    for pres in prescriptions:
        try:
            medication = cipher.decrypt(pres.medication.encode()).decode()
        except Exception:
            medication = '[Decryption Failed]'

        try:
            dosage = cipher.decrypt(pres.dosage.encode()).decode()
        except Exception:
            dosage = '[Decryption Failed]'

        decrypted_prescriptions.append({
            'id': pres.id,
            'doctor_id': pres.doctor_id,
            'patient_id': pres.patient_id,
            'medication': medication,
            'dosage': dosage,
            'issued_at': pres.issued_at
        })

    decrypted_diagnoses = []
    for diag in diagnoses:
        try:
            diagnosis_text = cipher.decrypt(diag.diagnosis.encode()).decode()
        except Exception:
            diagnosis_text = '[Decryption Failed]'

        try:
            notes_text = cipher.decrypt(diag.notes.encode()).decode()
        except Exception:
            notes_text = '[Decryption Failed]'

        decrypted_diagnoses.append({
            'id': diag.id,
            'doctor_id': diag.doctor_id,
            'patient_id': diag.patient_id,
            'diagnosis': diagnosis_text,
            'notes': notes_text,
            'created_at': diag.created_at
        })

    return render_template(
        'view_patient.html',
        patient=patient,
        prescriptions=decrypted_prescriptions,
        diagnoses=decrypted_diagnoses
    )


@app.route('/diagnosis/add/<int:patient_id>', methods=['GET', 'POST'])
@login_required
@role_required(['Doctor'])
def add_diagnosis(patient_id):
    if request.method == 'POST':
        diagnosis = cipher.encrypt(request.form['diagnosis'].encode()).decode()
        notes = cipher.encrypt(request.form['notes'].encode()).decode()
        diag = Diagnosis(patient_id=patient_id, doctor_id=current_user.id, diagnosis=diagnosis, notes=notes)
        db.session.add(diag)
        db.session.commit()
        log_action(current_user.id, 'Add Diagnosis', f'Added diagnosis for patient {patient_id}')
        flash('Diagnosis added successfully.')
        return redirect(url_for('view_patient', patient_id=patient_id))
    return render_template('add_diagnosis.html', patient_id=patient_id)

@app.route('/diagnosis/edit/<int:diagnosis_id>', methods=['GET', 'POST'])
@login_required
@role_required(['Doctor'])
def edit_diagnosis(diagnosis_id):
    diag = Diagnosis.query.get_or_404(diagnosis_id)
    if diag.doctor_id != current_user.id:
        flash('Access denied.')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        diag.diagnosis = cipher.encrypt(request.form['diagnosis'].encode()).decode()
        diag.notes = cipher.encrypt(request.form['notes'].encode()).decode()
        db.session.commit()
        log_action(current_user.id, 'Edit Diagnosis', f'Edited diagnosis {diagnosis_id}')
        flash('Diagnosis updated successfully.')
        return redirect(url_for('view_patient', patient_id=diag.patient_id))
    diagnosis_text = cipher.decrypt(diag.diagnosis.encode()).decode()
    notes_text = cipher.decrypt(diag.notes.encode()).decode()
    return render_template('edit_diagnosis.html', diagnosis=diag, diagnosis_text=diagnosis_text, notes_text=notes_text)

@app.route('/diagnosis/delete/<int:diagnosis_id>', methods=['POST'])
@login_required
@role_required(['Doctor'])
def delete_diagnosis(diagnosis_id):
    diag = Diagnosis.query.get_or_404(diagnosis_id)
    if diag.doctor_id != current_user.id:
        flash('Access denied.')
        return redirect(url_for('dashboard'))
    db.session.delete(diag)
    db.session.commit()
    log_action(current_user.id, 'Delete Diagnosis', f'Deleted diagnosis {diagnosis_id}')
    flash('Diagnosis deleted.')
    return redirect(url_for('view_patient', patient_id=diag.patient_id))

@app.route('/prescription/delete/<int:prescription_id>', methods=['POST'])
@login_required
@role_required(['Doctor'])
def delete_prescription(prescription_id):
    presc = Prescription.query.get_or_404(prescription_id)
    if presc.doctor_id != current_user.id:
        flash('Access denied.')
        return redirect(url_for('dashboard'))
    db.session.delete(presc)
    db.session.commit()
    log_action(current_user.id, 'Delete Prescription', f'Deleted prescription {prescription_id}')
    flash('Prescription deleted.')
    return redirect(url_for('view_patient', patient_id=presc.patient_id))

@app.route('/edit_prescription/<int:prescription_id>', methods=['GET', 'POST'])
@login_required
@role_required(['Doctor'])
def edit_prescription(prescription_id):
    prescription = Prescription.query.get_or_404(prescription_id)

    # Ensure the current doctor is the owner of the prescription
    if prescription.doctor_id != current_user.id:
        flash('Unauthorized access.')
        return redirect(url_for('dashboard'))

    # Decrypt current values to display in the form
    try:
        medication_plain = cipher.decrypt(prescription.medication.encode()).decode()
    except Exception:
        medication_plain = ''

    try:
        dosage_plain = cipher.decrypt(prescription.dosage.encode()).decode()
    except Exception:
        dosage_plain = ''

    # Populate the form with decrypted values
    form = PrescriptionForm()
    if request.method == 'GET':
        form.medication.data = medication_plain
        form.dosage.data = dosage_plain

    # Handle form submission
    if form.validate_on_submit():
        # Encrypt updated values before saving
        prescription.medication = cipher.encrypt(form.medication.data.encode()).decode()
        prescription.dosage = cipher.encrypt(form.dosage.data.encode()).decode()
        db.session.commit()
        flash('Prescription updated successfully.')
        return redirect(url_for('view_patient', patient_id=prescription.patient_id))

    return render_template('edit_prescription.html', form=form, prescription=prescription)

if __name__ == '__main__':
    app.run(ssl_context=('certs/server.crt', 'certs/server.key'), host='0.0.0.0', port=5000, debug=True)