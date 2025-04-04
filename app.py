import io
import base64
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from config import SECRET_KEY
import requests
import random
import pyotp
import qrcode
import sys
from datetime import datetime, timedelta
import secrets  # For generating secure tokens
sys.path.append(".")

app = Flask(__name__)
app.secret_key = SECRET_KEY

# UltraMSG API Credentials
ULTRAMSG_INSTANCE_ID = "instance112532"
API_TOKEN = "198yh97ulky7c0lz"
ULTRAMSG_URL = f"https://api.ultramsg.com/{ULTRAMSG_INSTANCE_ID}/messages/chat"

# Configure Database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Configure Mail Server
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'gujarat123eb@gmail.com'
app.config['MAIL_PASSWORD'] = 'xigahusckdgioceu'
mail = Mail(app)

# Database Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100))
    phone = db.Column(db.String(15))
    password = db.Column(db.String(255))
    totp_secret = db.Column(db.String(16))
    reset_token = db.Column(db.String(100), nullable=True)
    reset_token_expiration = db.Column(db.DateTime, nullable=True)
    last_otp_request = db.Column(db.DateTime, nullable=True)
    failed_login_attempts = db.Column(db.Integer, default=0)  # New field for failed attempts
    suspension_timestamp = db.Column(db.DateTime, nullable=True)  # New field for suspension time

# class User(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     name = db.Column(db.String(100))
#     email = db.Column(db.String(100))
#     phone = db.Column(db.String(15))
#     password = db.Column(db.String(255))
#     totp_secret = db.Column(db.String(16))
#     reset_token = db.Column(db.String(100), nullable=True)
#     reset_token_expiration = db.Column(db.DateTime, nullable=True)
#     last_otp_request = db.Column(db.DateTime, nullable=True)  # New field for OTP request timestamp

# Function to send OTP via WhatsApp
def send_otp_via_whatsapp(phone_number, otp):
    payload = {
        "token": API_TOKEN,
        "to": phone_number,
        "body": f"Your OTP is: {otp}",
        "priority": 10
    }
    response = requests.post(ULTRAMSG_URL, data=payload)
    return response.json()

# Function to generate QR code as a base64 string
def generate_qr_code(provisioning_uri):
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    img_base64 = base64.b64encode(buffered.getvalue()).decode('utf-8')
    return f"data:image/png;base64,{img_base64}"

# Route to request a password reset
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        try:
            user = User.query.filter_by(email=email).first()
        except Exception as e:
            flash('An error occurred while accessing the database. Please try again later.', 'danger')
            return redirect(url_for('forgot_password'))

        if not user:
            flash('No account found with that email address.', 'danger')
            return redirect(url_for('forgot_password'))

        # Check if the user can request a new OTP (60-second cooldown)
        cooldown_period = 60  # seconds
        if user.last_otp_request:
            time_since_last_request = (datetime.utcnow() - user.last_otp_request).total_seconds()
            if time_since_last_request < cooldown_period:
                remaining_time = int(cooldown_period - time_since_last_request)
                flash(f'Please wait {remaining_time} seconds before requesting a new reset link.', 'danger')
                return redirect(url_for('forgot_password'))

        # Generate a secure token
        token = secrets.token_urlsafe(32)
        # Set token expiration (30 minutes from now)
        expiration = datetime.utcnow() + timedelta(minutes=30)

        # Update the last OTP request timestamp
        user.last_otp_request = datetime.utcnow()
        user.reset_token = token
        user.reset_token_expiration = expiration
        try:
            db.session.commit()
        except Exception as e:
            flash('An error occurred while saving the reset token. Please try again.', 'danger')
            return redirect(url_for('forgot_password'))

        # Send the reset link via email
        reset_link = url_for('reset_password', token=token, _external=True)
        msg = Message('Password Reset Request',
                      sender=app.config['MAIL_USERNAME'],
                      recipients=[email])
        msg.body = f'Click the following link to reset your password: {reset_link}\nThis link will expire in 30 minutes.'
        try:
            mail.send(msg)
        except Exception as e:
            flash('An error occurred while sending the email. Please try again.', 'danger')
            return redirect(url_for('forgot_password'))

        flash('A password reset link has been sent to your email.', 'success')
        return redirect(url_for('login'))

    return render_template('forgot_password.html')

# Route to reset the password
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()

    if not user:
        flash('Invalid or expired reset token.', 'danger')
        return redirect(url_for('login'))

    # Check if the token has expired
    if user.reset_token_expiration < datetime.utcnow():
        flash('The reset token has expired.', 'danger')
        # Clear the token and expiration
        user.reset_token = None
        user.reset_token_expiration = None
        db.session.commit()
        return redirect(url_for('login'))

    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not password or not confirm_password:
            flash('Please fill in all fields.', 'danger')
            return redirect(url_for('reset_password', token=token))

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('reset_password', token=token))

        # Update the user's password
        user.password = generate_password_hash(password)
        # Clear the reset token and expiration
        user.reset_token = None
        user.reset_token_expiration = None
        db.session.commit()

        flash('Your password has been reset successfully. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)

# Existing Routes (unchanged)
@app.route('/send_otp', methods=['POST'])
def send_otp():
    data = request.get_json()
    phone = data.get("phone")
    
    if not phone:
        return jsonify({"error": "Phone number is required"}), 400

    # Check if the user exists and apply cooldown
    user = User.query.filter_by(phone=phone).first()
    if user:
        cooldown_period = 60  # seconds
        if user.last_otp_request:
            time_since_last_request = (datetime.utcnow() - user.last_otp_request).total_seconds()
            if time_since_last_request < cooldown_period:
                remaining_time = int(cooldown_period - time_since_last_request)
                return jsonify({"error": f"Please wait {remaining_time} seconds before requesting a new OTP."}), 429

    otp = str(random.randint(100000, 999999))
    response = send_otp_via_whatsapp(phone, otp)
    
    # Update the last OTP request timestamp
    if user:
        user.last_otp_request = datetime.utcnow()
        db.session.commit()
    else:
        # If user doesn't exist, you might want to handle this differently
        pass

    return jsonify({"message": "OTP sent successfully", "response": response})

@app.route('/')
def home():
    return render_template('signup.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form.get('phone')
        password = generate_password_hash(request.form['password'])
        totp_secret = pyotp.random_base32()

        # Check if the user already exists (to apply cooldown or update)
        user = User.query.filter_by(email=email).first()
        if user:
            # Check cooldown for existing user
            cooldown_period = 30  # seconds
            if user.last_otp_request:
                time_since_last_request = (datetime.utcnow() - user.last_otp_request).total_seconds()
                if time_since_last_request < cooldown_period:
                    remaining_time = int(cooldown_period - time_since_last_request)
                    flash(f'Please wait {remaining_time} seconds before requesting a new OTP.', 'danger')
                    return redirect(url_for('verify_otp'))

        otp_email = str(random.randint(100000, 999999))
        msg = Message('Your OTP Code', sender=app.config['MAIL_USERNAME'], recipients=[email])
        msg.body = f'Your email OTP code is: {otp_email}'
        try:
            mail.send(msg)
        except Exception as e:
            flash('An error occurred while sending the email OTP. Please try again.', 'danger')
            return redirect(url_for('signup'))

        otp_whatsapp = str(random.randint(100000, 999999))
        try:
            send_otp_via_whatsapp(phone, otp_whatsapp)
        except Exception as e:
            flash('An error occurred while sending the WhatsApp OTP. Please try again.', 'danger')
            return redirect(url_for('signup'))

        # If user doesn't exist, create a new one
        if not user:
            new_user = User(name=name, email=email, phone=phone, password=password, totp_secret=totp_secret)
            db.session.add(new_user)
        else:
            # Update existing user (in case they are retrying signup)
            user.name = name
            user.phone = phone
            user.password = password
            user.totp_secret = totp_secret

        # Update the last OTP request timestamp
        if user:
            user.last_otp_request = datetime.utcnow()
        else:
            new_user.last_otp_request = datetime.utcnow()
        db.session.commit()

        session['email'] = email
        session['otp_email'] = otp_email
        session['otp_whatsapp'] = otp_whatsapp
        return redirect(url_for('verify_otp'))

    return render_template('signup.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    email = session.get('email')
    user = User.query.filter_by(email=email).first()

    if not user:
        flash('User not found. Please sign up.', 'danger')
        return redirect(url_for('signup'))

    if request.method == 'POST':
        entered_email_otp = request.form['otp_email']
        entered_whatsapp_otp = request.form['otp_whatsapp']

        if session.get('otp_email') != entered_email_otp:
            flash('Invalid email OTP.', 'danger')
            return redirect(url_for('verify_otp'))

        if session.get('otp_whatsapp') != entered_whatsapp_otp:
            flash('Invalid WhatsApp OTP.', 'danger')
            return redirect(url_for('verify_otp'))

        # Clear session data after successful verification
        session.pop('email', None)
        session.pop('otp_email', None)
        session.pop('otp_whatsapp', None)
        return redirect(url_for('login'))

    # Handle resend OTP request via GET parameter
    if request.args.get('resend'):
        cooldown_period = 30  # seconds
        if user.last_otp_request:
            time_since_last_request = (datetime.utcnow() - user.last_otp_request).total_seconds()
            if time_since_last_request < cooldown_period:
                remaining_time = int(cooldown_period - time_since_last_request)
                flash(f'Please wait {remaining_time} seconds before requesting a new OTP.', 'danger')
                return redirect(url_for('verify_otp'))

        # Resend OTPs
        otp_email = str(random.randint(100000, 999999))
        msg = Message('Your OTP Code', sender=app.config['MAIL_USERNAME'], recipients=[email])
        msg.body = f'Your new email OTP code is: {otp_email}'
        try:
            mail.send(msg)
        except Exception as e:
            flash('An error occurred while sending the email OTP. Please try again.', 'danger')
            return redirect(url_for('verify_otp'))

        otp_whatsapp = str(random.randint(100000, 999999))
        try:
            send_otp_via_whatsapp(user.phone, otp_whatsapp)
        except Exception as e:
            flash('An error occurred while sending the WhatsApp OTP. Please try again.', 'danger')
            return redirect(url_for('verify_otp'))

        session['otp_email'] = otp_email
        session['otp_whatsapp'] = otp_whatsapp
        user.last_otp_request = datetime.utcnow()
        db.session.commit()
        flash('New OTPs have been sent to your email and phone.', 'success')
        return redirect(url_for('verify_otp'))

    return render_template('verify_otp.html')

# @app.route('/signup', methods=['GET', 'POST'])
# def signup():
#     if request.method == 'POST':
#         name = request.form['name']
#         email = request.form['email']
#         phone = request.form.get('phone')
#         password = generate_password_hash(request.form['password'])
#         totp_secret = pyotp.random_base32()

#         # Check if the user already exists (to apply cooldown)
#         user = User.query.filter_by(email=email).first()
#         if user:
#             # Check cooldown
#             cooldown_period = 60  # seconds
#             if user.last_otp_request:
#                 time_since_last_request = (datetime.utcnow() - user.last_otp_request).total_seconds()
#                 if time_since_last_request < cooldown_period:
#                     remaining_time = int(cooldown_period - time_since_last_request)
#                     flash(f'Please wait {remaining_time} seconds before requesting a new OTP.', 'danger')
#                     return redirect(url_for('signup'))

#         otp_email = str(random.randint(100000, 999999))
#         msg = Message('Your OTP Code', sender=app.config['MAIL_USERNAME'], recipients=[email])
#         msg.body = f'Your email OTP code is: {otp_email}'
#         try:
#             mail.send(msg)
#         except Exception as e:
#             flash('An error occurred while sending the email OTP. Please try again.', 'danger')
#             return redirect(url_for('signup'))

#         otp_whatsapp = str(random.randint(100000, 999999))
#         try:
#             send_otp_via_whatsapp(phone, otp_whatsapp)
#         except Exception as e:
#             flash('An error occurred while sending the WhatsApp OTP. Please try again.', 'danger')
#             return redirect(url_for('signup'))

#         # If user doesn't exist, create a new one
#         if not user:
#             new_user = User(name=name, email=email, phone=phone, password=password, totp_secret=totp_secret)
#             db.session.add(new_user)
#         else:
#             # Update existing user (in case they are retrying signup)
#             user.name = name
#             user.phone = phone
#             user.password = password
#             user.totp_secret = totp_secret

#         # Update the last OTP request timestamp
#         if user:
#             user.last_otp_request = datetime.utcnow()
#         else:
#             new_user.last_otp_request = datetime.utcnow()
#         db.session.commit()

#         session['email'] = email
#         session['otp_email'] = otp_email
#         session['otp_whatsapp'] = otp_whatsapp
#         return redirect(url_for('verify_otp'))

#     return render_template('signup.html')

# @app.route('/verify_otp', methods=['GET', 'POST'])
# def verify_otp():
#     email = session.get('email')
#     user = User.query.filter_by(email=email).first()

#     if not user:
#         flash('User not found. Please sign up.', 'danger')
#         return redirect(url_for('signup'))

#     if request.method == 'POST':
#         entered_email_otp = request.form['otp_email']
#         entered_whatsapp_otp = request.form['otp_whatsapp']

#         if session.get('otp_email') != entered_email_otp:
#             flash('Invalid email OTP.', 'danger')
#             return redirect(url_for('verify_otp'))

#         if session.get('otp_whatsapp') != entered_whatsapp_otp:
#             flash('Invalid WhatsApp OTP.', 'danger')
#             return redirect(url_for('verify_otp'))

#         return redirect(url_for('login'))

#     return render_template('verify_otp.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        if user:
            # Check if account is suspended
            if user.suspension_timestamp and user.suspension_timestamp > datetime.utcnow():
                time_remaining = (user.suspension_timestamp - datetime.utcnow()).total_seconds()
                hours_remaining = int(time_remaining // 3600)
                minutes_remaining = int((time_remaining % 3600) // 60)
                flash(f'Account is suspended. Please wait {hours_remaining}h {minutes_remaining}m before trying again.', 'danger')
                return render_template('login.html', suspension_time_remaining=time_remaining)

            # Check password
            if user and check_password_hash(user.password, password):
                # Reset failed attempts and suspension on successful login
                user.failed_login_attempts = 0
                user.suspension_timestamp = None
                db.session.commit()
                session['email'] = email
                return redirect(url_for('google_auth'))
            else:
                # Increment failed attempts
                user.failed_login_attempts += 1
                if user.failed_login_attempts >= 3:
                    # Suspend account for 24 hours
                    user.suspension_timestamp = datetime.utcnow() + timedelta(hours=24)
                    user.failed_login_attempts = 0  # Reset attempts after suspension
                    db.session.commit()
                    flash('Account suspended for 24 hours due to 3 failed login attempts.', 'danger')
                else:
                    remaining_attempts = 3 - user.failed_login_attempts
                    flash(f'Invalid credentials. You have {remaining_attempts} attempts left.', 'danger')
                db.session.commit()

        else:
            flash('Invalid credentials. Please try again.', 'danger')

    return render_template('login.html')

@app.route('/google_auth', methods=['GET', 'POST'])
def google_auth():
    email = session.get('email')
    user = User.query.filter_by(email=email).first()

    if not user:
        flash('User not found. Please sign up.', 'danger')
        return redirect(url_for('signup'))

    totp = pyotp.TOTP(user.totp_secret)
    provisioning_uri = totp.provisioning_uri(name=email, issuer_name="MFA Project")

    if request.method == 'POST':
        otp_code = request.form.get('otp')
        if not otp_code:
            flash('Please enter the Google Authenticator code.', 'danger')
            return redirect(url_for('google_auth'))

        if totp.verify(otp_code):
            return redirect(url_for('success'))
        else:
            flash('Invalid Google Authenticator code.', 'danger')

    qr_code_image = generate_qr_code(provisioning_uri)
    return render_template('google_auth.html', qr_code=qr_code_image)

@app.route('/success')
def success():
    return redirect("https://www.youtube.com")

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)