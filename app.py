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
import secrets

sys.path.append(".")

app = Flask(__name__)
app.secret_key = SECRET_KEY

# UltraMSG API Credentials
ULTRAMSG_INSTANCE_ID = "instance112532"
API_TOKEN = "qdm3lf3irjyf5255"
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
    failed_login_attempts = db.Column(db.Integer, default=0)
    suspension_timestamp = db.Column(db.DateTime, nullable=True)

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

# Existing Routes (unchanged parts omitted for brevity)
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
        password = request.form['password']

        # Check if the user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('User already exists.', 'danger')
            return redirect(url_for('signup'))

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

        # Store temporary session data for verification
        session['name'] = name
        session['email'] = email
        session['phone'] = phone
        session['password'] = password
        session['otp_email'] = otp_email
        session['otp_whatsapp'] = otp_whatsapp
        return redirect(url_for('verify_otp'))

    return render_template('signup.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    email = session.get('email')
    if not email:
        return jsonify({'success': False, 'message': 'Session expired. Please sign up again.'})

    # Check if the user exists in the session instead of the database
    if request.method == 'POST':
        entered_email_otp = request.form.get('otp_email')
        entered_whatsapp_otp = request.form.get('otp_whatsapp')

        if session.get('otp_email') != entered_email_otp:
            return jsonify({'success': False, 'message': 'Invalid email OTP.'})
        if session.get('otp_whatsapp') != entered_whatsapp_otp:
            return jsonify({'success': False, 'message': 'Invalid WhatsApp OTP.'})

        # Keep email in session for google_auth, clear OTPs
        session.pop('otp_email', None)
        session.pop('otp_whatsapp', None)
        return jsonify({'success': True, 'message': 'OTP successfully verified', 'redirect': url_for('google_auth')})

    elif request.method == 'GET':
        # Handle resend request
        if request.args.get('resend') == 'true':
            channel = request.args.get('channel')
            cooldown_period = 30  # seconds
            last_otp_request = session.get('last_otp_request')
            if last_otp_request:
                time_since_last_request = (datetime.utcnow() - last_otp_request).total_seconds()
                if time_since_last_request < cooldown_period:
                    remaining_time = int(cooldown_period - time_since_last_request)
                    return jsonify({'success': False, 'message': f'Please wait {remaining_time} seconds before requesting a new OTP.'})

            new_otp = str(random.randint(100000, 999999))
            if channel == 'email':
                msg = Message('Your OTP Code', sender=app.config['MAIL_USERNAME'], recipients=[email])
                msg.body = f'Your email OTP code is: {new_otp}'
                try:
                    mail.send(msg)
                    session['otp_email'] = new_otp
                    session['last_otp_request'] = datetime.utcnow()
                    return jsonify({'success': True, 'message': 'New OTP sent to your email.'})
                except Exception as e:
                    return jsonify({'success': False, 'message': 'An error occurred while sending the email OTP.'})
            elif channel == 'whatsapp':
                try:
                    send_otp_via_whatsapp(session.get('phone'), new_otp)
                    session['otp_whatsapp'] = new_otp
                    session['last_otp_request'] = datetime.utcnow()
                    return jsonify({'success': True, 'message': 'New OTP sent to your WhatsApp.'})
                except Exception as e:
                    return jsonify({'success': False, 'message': 'An error occurred while sending the WhatsApp OTP.'})
            else:
                return jsonify({'success': False, 'message': 'Invalid channel specified.'})

    return render_template('verify_otp.html')

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
            if check_password_hash(user.password, password):
                # Reset failed attempts and suspension on successful login
                user.failed_login_attempts = 0
                user.suspension_timestamp = None
                db.session.commit()
                session['email'] = email
                return redirect(url_for('login_verify'))
            else:
                user.failed_login_attempts += 1
                if user.failed_login_attempts >= 3:
                    user.suspension_timestamp = datetime.utcnow() + timedelta(hours=3)
                    user.failed_login_attempts = 0
                    db.session.commit()
                    flash('Account suspended for 3 hours due to 3 failed login attempts.', 'danger')
                else:
                    remaining_attempts = 3 - user.failed_login_attempts
                    flash(f'Invalid credentials. You have {remaining_attempts} attempts left.', 'danger')
                db.session.commit()
        else:
            flash('User not found. Please sign up.', 'danger')
    return render_template('login.html')


@app.route('/google_auth', methods=['GET', 'POST'])
def google_auth():
    email = session.get('email')
    if not email:
        flash('Session expired. Please log in again.', 'danger')
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first()
    if not user:
        totp_secret = pyotp.random_base32()
        user = User(
            name=session.get('name'),
            email=email,
            phone=session.get('phone'),
            password=generate_password_hash(session.get('password')),
            totp_secret=totp_secret
        )
        db.session.add(user)
        db.session.commit()

    totp = pyotp.TOTP(user.totp_secret)
    provisioning_uri = totp.provisioning_uri(name=email, issuer_name="MFA Project")

    if request.method == 'POST':
        otp_code = request.form.get('otp')
        if not otp_code:
            flash('Please enter the Google Authenticator code.', 'danger')
            return redirect(url_for('google_auth'))

        if totp.verify(otp_code):
            session.pop('email', None)
            session.pop('name', None)
            session.pop('phone', None)
            session.pop('password', None)
            flash('User registered successfully.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid Google Authenticator code.', 'danger')

    qr_code_image = generate_qr_code(provisioning_uri)
    return render_template('google_auth.html', qr_code=qr_code_image)

@app.route('/login_verify', methods=['GET', 'POST'])
def login_verify():
    email = session.get('email')
    if not email:
        flash('Session expired. Please log in again.', 'danger')
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash('User not found. Please sign up.', 'danger')
        return redirect(url_for('signup'))

    if request.method == 'POST':
        option = request.form.get('option')
        entered_otp = request.form.get('otp')

        if option == 'whatsapp':
            if session.get('whatsapp_otp') == entered_otp:
                session.pop('whatsapp_otp', None)
                session.pop('email', None)
                return redirect(url_for('success'))
               
            else:
                return jsonify({
                    'success': False,
                    'message': 'Invalid WhatsApp OTP'
                })

        elif option == 'google_auth':
            totp = pyotp.TOTP(user.totp_secret)
            if totp.verify(entered_otp):
                session.pop('email', None)
                return redirect(url_for('success'))
            else:
                return jsonify({
                    'success': False,
                    'message': 'Invalid Google Authenticator code'
                })

    # Handle WhatsApp OTP sending
    if request.args.get('send_whatsapp_otp'):
        cooldown_period = 30  # seconds
        if user.last_otp_request:
            time_since_last_request = (datetime.utcnow() - user.last_otp_request).total_seconds()
            if time_since_last_request < cooldown_period:
                remaining_time = int(cooldown_period - time_since_last_request)
                return jsonify({
                    'success': False,
                    'message': f'Please wait {remaining_time} seconds before requesting a new OTP.'
                })

        otp = str(random.randint(100000, 999999))
        try:
            send_otp_via_whatsapp(user.phone, otp)
            session['whatsapp_otp'] = otp
            user.last_otp_request = datetime.utcnow()
            db.session.commit()
            return jsonify({
                'success': True,
                'message': 'OTP sent to WhatsApp'
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'message': 'Error sending WhatsApp OTP. Please try again.'
            })

    return render_template('login_verify.html')

# @app.route('/login_verify', methods=['GET', 'POST'])
# def login_verify():
#     email = session.get('email')
#     if not email:
#         flash('Session expired. Please log in again.', 'danger')
#         return redirect(url_for('login'))

#     user = User.query.filter_by(email=email).first()
#     if not user:
#         flash('User not found. Please sign up.', 'danger')
#         return redirect(url_for('signup'))

#     if request.method == 'POST':
#         option = request.form.get('option')
#         entered_otp = request.form.get('otp')

#         if option == 'whatsapp':
#             # Verify WhatsApp OTP
#             if session.get('whatsapp_otp') == entered_otp:
#                 session.pop('whatsapp_otp', None)
#                 session.pop('email', None)
#                 return jsonify({
#                     'success': True,
#                     'message': 'WhatsApp verification successful',
#                     'redirect': url_for('success')
#                 })
#             else:
#                 return jsonify({
#                     'success': False,
#                     'message': 'Invalid WhatsApp OTP'
#                 })

#         elif option == 'google_auth':
#             # Verify Google Authenticator OTP
#             totp = pyotp.TOTP(user.totp_secret)
#             if totp.verify(entered_otp):
#                 session.pop('email', None)
#                 return jsonify({
#                     'success': True,
#                     'message': 'Google Authenticator verification successful',
#                     'redirect': url_for('success')
#                 })
#             else:
#                 return jsonify({
#                     'success': False,
#                     'message': 'Invalid Google Authenticator code'
#                 })

#     # Handle WhatsApp OTP sending
#     if request.args.get('send_whatsapp_otp'):
#         # Cooldown check
#         cooldown_period = 30  # seconds
#         if user.last_otp_request:
#             time_since_last_request = (datetime.utcnow() - user.last_otp_request).total_seconds()
#             if time_since_last_request < cooldown_period:
#                 remaining_time = int(cooldown_period - time_since_last_request)
#                 return jsonify({
#                     'success': False,
#                     'message': f'Please wait {remaining_time} seconds before requesting a new OTP.'
#                 })

#         otp = str(random.randint(100000, 999999))
#         try:
#             send_otp_via_whatsapp(user.phone, otp)
#             session['whatsapp_otp'] = otp
#             user.last_otp_request = datetime.utcnow()
#             db.session.commit()
#             return jsonify({
#                 'success': True,
#                 'message': 'OTP sent to WhatsApp'
#             })
#         except Exception as e:
#             return jsonify({
#                 'success': False,
#                 'message': 'Error sending WhatsApp OTP. Please try again.'
#             })

#     return render_template('login_verify.html')

@app.route('/success')
def success():
    return redirect("https://identityreview.com/wp-content/uploads/2021/08/multi-factor-1536x639.png")
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)