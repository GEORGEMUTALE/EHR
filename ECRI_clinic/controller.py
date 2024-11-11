import os
import mysql.connector
from flask import Flask, render_template, request, redirect, session, url_for,flash
from oauthlib.oauth2.rfc6749.errors import TokenExpiredError
from flask_dance.contrib.google import make_google_blueprint, google
import re
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
# Path where uploaded images will be stored (e.g., within the 'static' directory)

# Initialize the Flask app and Mail
controller = Flask(__name__)
UPLOAD_FOLDER = 'static/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
controller.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# Configuration
controller.secret_key = 'Health01'
controller.config['MAIL_SERVER'] = 'smtp.gmail.com'
controller.config['MAIL_PORT'] = 587
controller.config['MAIL_USERNAME'] = 'mutalegeorge367@gmail.com'
controller.config['MAIL_PASSWORD'] = 'hqqwbjuwzohvyszk' 
controller.config['MAIL_USE_TLS'] = True
mail = Mail(controller)

# Google OAuth Configuration
google_bp = make_google_blueprint(
    client_id="218393485164-ueft5o9k841djcrdp8f6a0dkdcm70ktn.apps.googleusercontent.com",
    client_secret="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",
    redirect_to="google_login",
    scope=["openid", "https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"]
)
controller.register_blueprint(google_bp, url_prefix="/google_login")


# Establish a global database connection and cursor
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",
    database="clinic_data"
)
cursor = db.cursor()

# Helper function to check allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Function to generate unique IDs
def generate_id(first_name, last_name, table_name):
    prefix = (first_name[:3] + last_name[:3]).upper()
    cursor.execute(f"SELECT COUNT(*) FROM doctors WHERE doctor_id LIKE '{prefix}%'")
    count = cursor.fetchone()[0] + 1
    return f"{prefix}{count:03d}"

@controller.route('/')
def welcome():
    return render_template('welcome.html')

@controller.route("/signup", methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        # Retrieve form data
        title = request.form.get('title')
        department_id = request.form.get('department_id')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        date_of_birth = request.form.get('dob')
        position = request.form.get('position')
        password = request.form.get('createPassword')
        confirm_password = request.form.get('repeatPassword')
        street = request.form.get('street')
        zip_code = request.form.get('zip_code')
        place = request.form.get('place')
        country = request.form.get('country')
        phone = request.form.get('phone')
        email = request.form.get('email')
        terms_accepted = request.form.get('terms')

        # Password validation
        if password != confirm_password:
            flash("Passwords do not match.")
            return redirect(url_for('signup'))
        if len(password) < 8 or len(password) > 20:
            flash("Password must be between 8-20 characters.")
            return redirect(url_for('signup'))
        hashed_password = generate_password_hash(password)

        # Basic email format check
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash("Invalid email format.")
            return redirect(url_for('signup'))

        try:
            # Insert data into the database
            sql = """
                INSERT INTO doctors (title, department_id, first_name, last_name, date_of_birth, position, password, 
                                   street, zip_code, place, country, phone, email, terms_accepted)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            values = (title, department_id, first_name, last_name, date_of_birth, position, hashed_password,
                      street, zip_code, place, country, phone, email, terms_accepted)

            cursor.execute(sql, values)
            db.commit()

            # Send a welcome email upon successful registration
            msg = Message("Welcome to our EHR System!", sender='your_email@gmail.com', recipients=[email])
            msg.body = f"Hello {first_name} {last_name},\n\nThank you for registering with us!"
            msg.html = f"<h3>Hello {first_name} {last_name},</h3><p>Thank you for registering with us!</p>"
            mail.send(msg)

            flash("Signup successful!")
            return redirect(url_for('login'))

        except mysql.connector.Error as err:
            flash(f"Database error: {err}")
            return redirect(url_for('signup'))

    return render_template('signup_form.html')

@controller.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        department_id = request.form.get('department_id')
        password = request.form.get('password')

        cursor.execute("SELECT department_id, password FROM doctors WHERE department_id = %s", (department_id,))
        doctor = cursor.fetchone()

        if doctor and check_password_hash(doctor[1], password):
            session['department_id'] = doctor[0]
            return redirect(url_for('view_patients'))
        else:
            flash("Invalid department ID or password", "danger")

    return render_template('login_form.html')

@controller.route('/patients')
def view_patients():
    if 'department_id' not in session:
        return redirect(url_for('login'))
    
    cursor.execute("SELECT department_id FROM doctors WHERE department_id = %s", (session['department_id'],))
    if cursor.fetchone() is None:
        session.pop('department_id', None)
        return redirect(url_for('login'))
    
    department_id = session['department_id']
    cursor.execute("SELECT * FROM patients WHERE doctor_id = %s", (department_id,))
    patients = cursor.fetchall()
    patients = [dict(zip([column[0] for column in cursor.description], row)) for row in patients]

    return render_template('doctors_patient.html', patients=patients)

@controller.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for('login'))

@controller.route('/add_patient', methods=['GET', 'POST'])
def add_patient():
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        date_of_birth = request.form.get('dob')
        date_of_visit = request.form.get('dateOfVisit')
        chief_complaint = request.form.get('chiefComplaint')
        medical_history = request.form.get('medicalHistory')
        medications = request.form.get('medications')
        allergies = request.form.get('allergies')
        vital_signs = request.form.get('vitalSigns')
        doctor_id = session.get('department_id')
        patient_id = generate_id(first_name, last_name, "patients")

        file = request.files['patient_image']
        image_data = None
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            file.save(file_path)
            with open(file_path, 'rb') as img_file:
                image_data = img_file.read()

        cursor.execute("""
            INSERT INTO patients (patient_id, first_name, last_name, date_of_birth, date_of_visit, 
                                  chief_complaint, medical_history, medications, 
                                  allergies, vital_signs, patient_image, doctor_id)
            VALUES (%s,%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (patient_id, first_name, last_name, date_of_birth, date_of_visit, chief_complaint,
              medical_history, medications, allergies, vital_signs, image_data, doctor_id))
        db.commit()

        return redirect(url_for('view_patients'))
    
    return render_template('edit_patient.html')

@controller.route('/edit_patient/<string:patient_id>', methods=['GET', 'POST'])
def edit_patient(patient_id):
    if request.method == 'GET':
        # Fetch patient data for editing
        cursor.execute("SELECT * FROM patients WHERE patient_id = %s", (patient_id,))
        patient = cursor.fetchone()
        if patient:
            # Convert patient tuple to dictionary for easier access in template
            patient = dict(zip([column[0] for column in cursor.description], patient))
        return render_template('edit_patient.html', patient=patient)

    # Handle POST request for saving edits
    elif request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        date_of_birth = request.form.get('dob')
        date_of_visit = request.form.get('dateOfVisit')
        chief_complaint = request.form.get('chiefComplaint')
        medical_history = request.form.get('medicalHistory')
        medications = request.form.get('medications')
        allergies = request.form.get('allergies')
        vital_signs = request.form.get('vitalSigns')
        image_file = request.files['patient_image']

        # Optional: handle image upload if a file is provided
        image_data = None
        if image_file and image_file.filename:
            filename = secure_filename(image_file.filename)
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            image_file.save(file_path)
            with open(file_path, 'rb') as img_file:
                image_data = img_file.read()

        # Update patient information in the database
        if image_data:
            cursor.execute("""
                UPDATE patients
                SET first_name = %s, last_name = %s, date_of_birth = %s, date_of_visit = %s,
                    chief_complaint = %s, medical_history = %s, medications = %s, 
                    allergies = %s, vital_signs = %s, patient_image = %s
                WHERE patient_id = %s
            """, (first_name, last_name, date_of_birth, date_of_visit, chief_complaint, medical_history,
                  medications, allergies, vital_signs, image_data, patient_id))
        else:
            cursor.execute("""
                UPDATE patients
                SET first_name = %s, last_name = %s, date_of_birth = %s, date_of_visit = %s,
                    chief_complaint = %s, medical_history = %s, medications = %s, 
                    allergies = %s, vital_signs = %s
                WHERE patient_id = %s
            """, (first_name, last_name, date_of_birth, date_of_visit, chief_complaint, medical_history,
                  medications, allergies, vital_signs, patient_id))

        db.commit()
        return redirect(url_for('view_patients'))

@controller.route('/delete_patient/<string:patient_id>', methods=['POST'])
def delete_patient(patient_id):
    cursor.execute("DELETE FROM patients WHERE patient_id = %s", (patient_id,))
    db.commit()
    return redirect(url_for('view_patients'))

if __name__ == '__main__':
    controller.run(debug=True)
