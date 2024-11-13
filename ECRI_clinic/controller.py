import os
import pandas as pd
from flask import send_file
from io import BytesIO
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
s = URLSafeTimedSerializer(controller.secret_key)
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

def generate_id(first_name, last_name, table_name):
    # Generate prefix from first and last name
    prefix = (first_name[:3] + last_name[:3]).upper()
    
    # Use parameterized queries to avoid SQL injection
    cursor.execute(f"SELECT COUNT(*) FROM {table_name} WHERE patient_id LIKE %s", (f"{prefix}%",))
    count = cursor.fetchone()[0] + 1  # Add 1 to the count to generate a unique ID
    
    # Generate the ID (prefix + number with leading zeros)
    return f"{prefix}{count:03d}"


@controller.route('/')
def welcome():
    return render_template('welcome.html')

#forgot password
@controller.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        
        # Verify that email exists in database
        cursor = db.cursor()
        cursor.execute("SELECT department_id FROM doctors WHERE email = %s", (email,))
        doctor = cursor.fetchone()
        cursor.close()
        
        if doctor:
            # Generate a token
            token = s.dumps(email, salt='password-reset-salt')
            
            # Create reset link
            reset_link = url_for('reset_password', token=token, _external=True)
            
            # Send email
            msg = Message('Password Reset Request', sender='mutalegeorge367@gmail.com', recipients=[email])
            msg.body = f'Click the link to reset your password: {reset_link}'
            mail.send(msg)
            
            return "Password reset link has been sent to your email."

        return "Email address is not registered."
    
    return render_template('forgot_password.html')

@controller.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        # Validate the token (expires after 1 hour)
        email = s.loads(token, salt='password-reset-salt', max_age=3600)
    except:
        return "The reset link is invalid or has expired."
    
    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        # Check if passwords match
        if new_password != confirm_password:
            return "Passwords do not match!"
        
        hashed_password = generate_password_hash(new_password)
        
        # Update the password in the database
        cursor = db.cursor()
        cursor.execute("UPDATE doctors SET password = %s WHERE email = %s", (hashed_password, email))
        db.commit()
        cursor.close()
        
        return redirect(url_for('login'))

    # Render the reset password form for GET requests
    return render_template('reset_password.html', token=token)


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
            msg = Message("Welcome to our EHR System!", sender='mutalegeorge367@gmail.com', recipients=[email])
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

@controller.route('/google_login')
def google_login():
    # Force login prompt
    if not google.authorized:
        return redirect(url_for("google.login", prompt="consent"))
    
    try:
        resp = google.get("/oauth2/v2/userinfo")
        resp.raise_for_status()  # Raise an error for bad responses
    except TokenExpiredError:
        return redirect(url_for("google.login"))
    except Exception as e:
        flash(f"An error occurred while fetching user info: {str(e)}", "danger")
        return redirect(url_for('login'))

    # Get the user info
    info = resp.json()
    email = info.get("email")

    if not email:
        flash("Error: Email not found in the response. Please check your Google account permissions.", "danger")
        return redirect(url_for('login'))

    # Check if the email exists in the database
    cursor.execute("SELECT department_id FROM doctors WHERE email = %s", (email,))
    doctor = cursor.fetchone()

    if not doctor:
        flash("Error: Email not found in our records. Please contact support or sign up.", "danger")
        return redirect(url_for('login'))
    
    # Extract department_id from the database result
    department_id = doctor[0]

    # If all checks pass, set the session
    session['department_id'] = department_id
    flash("Login successful!", "success")
    return redirect(url_for('view_patients'))



@controller.route('/patients')
def view_patients():
    if 'department_id' not in session:
        return redirect(url_for('login'))
    
    cursor.execute("SELECT department_id FROM doctors WHERE department_id = %s", (session['department_id'],))
    if cursor.fetchone() is None:
        session.pop('department_id', None)
        return redirect(url_for('login'))
    
    department_id = session['department_id']
    cursor.execute("SELECT * FROM patients WHERE doctor_id = %s", (session['department_id'],))
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

# Export all patients for the logged-in doctor's department as Excel
@controller.route('/export_all_patients_excel')
def export_all_patients_excel():
    department_id = session.get('department_id')  # Get the department's ID from the session
    
    if not department_id:
        return "Department not logged in", 403  # If the department is not logged in, return a 403 error
    
    # Fetch all patients for the department, using the doctor_id that references department_id
    cursor.execute("""
    SELECT p.patient_id, p.first_name, p.last_name, p.date_of_birth, p.date_of_visit,
           p.chief_complaint, p.medical_history, p.medications, p.allergies, p.vital_signs, 
           p.doctor_id
    FROM patients p
    JOIN doctors d ON p.doctor_id = d.department_id
    WHERE d.department_id = %s
    """, (department_id,))
    patients = cursor.fetchall()

    if not patients:
        return "No patients found for this department", 404  # Return 404 if no patients are found
    
    # Get column names from the cursor description
    column_names = [desc[0] for desc in cursor.description]

    # Convert the patients data into a DataFrame
    df = pd.DataFrame(patients, columns=column_names)

    # Save DataFrame to an in-memory file (BytesIO)
    output = BytesIO()
    df.to_excel(output, index=False, engine='openpyxl')

    # Seek to the beginning of the in-memory file before sending it
    output.seek(0)

    # Return the Excel file as a download
    return send_file(output, as_attachment=True,
                     download_name='patients.xlsx',
                     mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')


# Export a single patient for the logged-in doctor's department as Excel
@controller.route('/export_patient_excel/<string:patient_id>')
def export_patient_excel(patient_id):
    department_id = session.get('department_id')  # Get the department's ID from the session
    
    if not department_id:
        return "Department not logged in", 403  # If the department is not logged in, return a 403 error

    # Fetch single patient data for the department, using the doctor_id that references department_id
    cursor.execute("""
    SELECT p.patient_id, p.first_name, p.last_name, p.date_of_birth, p.date_of_visit,
           p.chief_complaint, p.medical_history, p.medications, p.allergies, p.vital_signs, 
           p.doctor_id
    FROM patients p
    JOIN doctors d ON p.doctor_id = d.department_id
    WHERE d.department_id = %s AND p.patient_id = %s
    """, (department_id, patient_id))
    patient = cursor.fetchone()

    if not patient:
        return "Patient not found or access denied", 404  # If no such patient exists for the department

    # Get column names from the cursor description
    column_names = [desc[0] for desc in cursor.description]

    # Convert the fetched patient data into a dictionary
    patient_data = dict(zip(column_names, patient))

    # Convert to DataFrame
    df = pd.DataFrame([patient_data])

    # Define an in-memory file (BytesIO)
    output = BytesIO()

    # Save DataFrame to an in-memory Excel file (no index)
    df.to_excel(output, index=False, engine='openpyxl')

    # Seek to the beginning of the in-memory file before sending it
    output.seek(0)

    # Send the Excel file as a response
    return send_file(output, as_attachment=True,
                     download_name=f'{patient_data["patient_id"]}_patient.xlsx',
                     mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

@controller.route('/update_password', methods=['GET', 'POST'])
def update_password():
    if request.method == 'POST':
        # Get form data
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        # Check if user is logged in
        department_id = session.get('department_id')
        if not department_id:
            flash("You must be logged in to update your password.", "warning")
            return redirect(url_for('login'))

        # Retrieve the current password from the database
        cursor.execute("SELECT password FROM doctors WHERE department_id = %s", (department_id,))
        doctor = cursor.fetchone()

        # Validate existence of doctor and old password
        if doctor is None:
            flash("Doctor not found.", "danger")
            return redirect(url_for('login'))

        if not check_password_hash(doctor[0], old_password):
            flash("Current password is incorrect.", "danger")
            return redirect(url_for('update_password'))

        # Confirm new passwords match
        if new_password != confirm_password:
            flash("New password and confirmation do not match.", "danger")
            return redirect(url_for('update_password'))

        # Update password in the database
        new_password_hash = generate_password_hash(new_password)
        cursor.execute("UPDATE doctors SET password = %s WHERE department_id = %s", (new_password_hash, department_id))
        db.commit()

        # Success feedback
        flash("Password updated successfully!", "success")
        return redirect(url_for('view_patients'))
    
    # Render password update form
    return render_template('update_password.html')

@controller.route('/delete_account', methods=['GET', 'POST'])
def delete_account():
    if request.method == 'POST':
        # Get form data (password entered by the doctor)
        password = request.form['password']

        # Check if user is logged in
        department_id = session.get('department_id')
        if not department_id:
            flash("You must be logged in to delete your account.", "warning")
            return redirect(url_for('login'))

        # Retrieve the doctor's hashed password from the database
        cursor.execute("SELECT password FROM doctors WHERE department_id = %s", (department_id,))
        doctor = cursor.fetchone()

        # Check if doctor exists and password is correct
        if doctor is None:
            flash("Doctor not found.", "danger")
            return redirect(url_for('login'))
        
        if not check_password_hash(doctor[0], password):
            flash("Incorrect password. Account deletion failed.", "danger")
            return redirect(url_for('delete_account'))

        # Delete the doctor's account
        cursor.execute("DELETE FROM doctors WHERE department_id = %s", (department_id,))
        db.commit()

        # Clear session and confirm deletion
        session.pop('department_id', None)
        flash("Your account has been deleted successfully.", "success")
        return redirect(url_for('login'))

    # Render the account deletion confirmation form
    return render_template('delete_account.html')


if __name__ == '__main__':
    controller.run(debug=True)
