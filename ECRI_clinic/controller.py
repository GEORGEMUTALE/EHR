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
from pydicom import dcmread
from datetime import datetime
from PIL import Image
import numpy as np
from dotenv import load_dotenv



# Load environment variables from .env
load_dotenv()

# Flask app and configurations
controller = Flask(__name__)
controller.secret_key = os.getenv('SECRET_KEY')
controller.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER')
ALLOWED_EXTENSIONS = set(os.getenv('ALLOWED_EXTENSIONS').split(','))

# Mail configurations
controller.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
controller.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
controller.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS') == 'True'
controller.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL') == 'True'
controller.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
controller.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')

mail = Mail(controller)
s = URLSafeTimedSerializer(controller.secret_key)

# Google OAuth configuration
google_bp = make_google_blueprint(
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    redirect_to="google_login",
    scope=[
        "openid",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile"
    ]
)
controller.register_blueprint(google_bp, url_prefix="/google_login")

# Database connection
db = mysql.connector.connect(
    host=os.getenv('DB_HOST'),
    user=os.getenv('DB_USER'),
    password=os.getenv('DB_PASSWORD'),
    database=os.getenv('DB_NAME')
)
cursor = db.cursor()

# Set additional environment variables
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = os.getenv('OAUTHLIB_INSECURE_TRANSPORT', '1')

# Utility function to save the image and return the URL path
def save_image(file, filename):
     # Retrieve UPLOAD_FOLDER from the environment variable
    UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER')
    if not UPLOAD_FOLDER:
        raise EnvironmentError("UPLOAD_FOLDER environment variable is not set.")

    # Ensure the upload folder exists
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)

    """Saves uploaded image, converts DICOM if needed, and returns its URL path."""
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    
    if filename.endswith(".dcm"):
        # Convert DICOM to JPEG
        dicom = dcmread(file)
        pixel_array = dicom.pixel_array
        
        # Normalize the pixel array to 8-bit if needed
        if pixel_array.dtype != np.uint8:
            pixel_array = (pixel_array / pixel_array.max() * 255).astype(np.uint8)
        
        # Convert pixel array to PIL Image in grayscale mode
        image = Image.fromarray(pixel_array, mode='L')
        
        # Save the converted image as JPEG
        jpg_path = file_path.replace(".dcm", ".jpg")
        image.save(jpg_path, format="JPEG")
        
        # Return the relative URL path to the converted JPEG
        return f"{UPLOAD_FOLDER}/{os.path.basename(jpg_path)}"
    else:
        # Save JPEG or PNG image directly
        file.save(file_path)
        return f"{UPLOAD_FOLDER}/{os.path.basename(file_path)}"

# Helper function to validate allowed file extensions.
def allowed_file(filename):
    """Checks if the file has an allowed extension."""
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
            msg.body = f'The link expires in 5 minutes. We request you utilise the time and Click the link below to reset your password: {reset_link}'
            mail.send(msg)
            
            flash("Password reset link has been sent to your email.", "success")
        else:
            flash("Email address is not registered.", "error") 
    
    return render_template('forgot_password.html')

@controller.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=300)
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
        first_name = request.form.get('first_name').upper()
        last_name = request.form.get('last_name').upper()
        date_of_birth = request.form.get('dob')
        gender = request.form.get('gender')
        position = request.form.get('position').upper()
        password = request.form.get('createPassword')
        confirm_password = request.form.get('repeatPassword')
        street = request.form.get('street')
        zip_code = request.form.get('zip_code')
        place = request.form.get('place').upper()
        country = request.form.get('country').upper()
        phone = request.form.get('phone')
        email = request.form.get('email')
        terms_accepted = request.form.get('terms')

        # Password validation
        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for('signup'))
        
        if not re.match(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&#!])[A-Za-z\d@$!%*?&#!]{6,}$', password):
            flash("Password must be at least 6 characters long and contain letters, numbers, and special characters.", "danger")
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password)
        

        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash("Invalid email format.", "danger")
            return redirect(url_for('signup'))

        try:
            # Insert data into the database
            sql = """
                INSERT INTO doctors (title, department_id, first_name, last_name, gender, date_of_birth, position, password, 
                                   street, zip_code, place, country, phone, email, terms_accepted)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            values = (title, department_id, first_name, last_name, gender, date_of_birth, position, hashed_password,
                      street, zip_code, place, country, phone, email, terms_accepted)

            cursor.execute(sql, values)
            db.commit()

            # Send a welcome mail
            msg = Message("Welcome to our EHR System!", sender='mutalegeorge367@gmail.com', recipients=[email])
            msg.body = f"Hello {first_name} {last_name},\n\nThank you for registering with us!"
            msg.html = f"<h3>Hello {first_name} {last_name},</h3><p>Thank you for registering with us!</p>"
            mail.send(msg)

            flash("Signup successful!", "success")
            return redirect(url_for('login'))

        except mysql.connector.Error as err:
            flash(f"Database error: {err}", "warning")
            return redirect(url_for('signup'))

    return render_template('signup_form.html')

@controller.route("/update_profile", methods=['GET', 'POST'])
def update_profile():
    department_id = session.get('department_id')  
    if 'department_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        # Retrieve form data from the POST request
        title = request.form.get('title')
        department_id = request.form.get('department_id')
        first_name = request.form.get('first_name').upper()
        last_name = request.form.get('last_name').upper()
        date_of_birth = request.form.get('dob')
        gender = request.form.get('gender')
        position = request.form.get('position').upper()
        street = request.form.get('street')
        zip_code = request.form.get('zip_code')
        place = request.form.get('place').upper()
        country = request.form.get('country').upper()
        phone = request.form.get('phone')
        email = request.form.get('email')

        # checking mail
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash("Invalid email format.", "danger")
            return redirect(url_for('update_profile'))

        try:
            # Updating data in the database
            update_sql = """
                UPDATE doctors
                SET title = %s, department_id = %s, first_name = %s, last_name = %s, gender = %s, 
                    date_of_birth = %s, position = %s, street = %s, zip_code = %s, place = %s, 
                    country = %s, phone = %s, email = %s
                WHERE department_id = %s
            """
            values = (title, department_id, first_name, last_name, gender, date_of_birth, position, 
                      street, zip_code, place, country, phone, email, department_id)

            cursor.execute(update_sql, values)
            db.commit()

            # Optionally send an update confirmation email
            msg = Message("Your Profile has been Updated", sender='mutalegeorge367@gmail.com', recipients=[email])
            msg.body = f"Hello {first_name} {last_name},\n\nYour profile information has been successfully updated!"
            msg.html = f"<h3>Hello {first_name} {last_name},</h3><p>Your profile information has been successfully updated!</p>"
            mail.send(msg)

            flash("Profile updated successfully!", "success")
            return redirect(url_for('view_patients'))

        except mysql.connector.Error as err:
            flash(f"Database error: {err}", "danger")
            return redirect(url_for('update_profile'))

    else:
        # Fetch current doctor information from the database
        cursor.execute("SELECT * FROM doctors WHERE department_id = %s", (department_id,))
        doctor_data = cursor.fetchall()  # Fetches all rows (if there are any matching)

        # If no data is found, we can handle that scenario as well
        if not doctor_data:
            flash("No doctor found with this ID.")
            return redirect(url_for('view_patients'))

        # Convert the doctor data to a dictionary using zip and cursor.description
        doctor = [dict(zip([column[0] for column in cursor.description], row)) for row in doctor_data][0]

        return render_template('update_profile.html', doctor=doctor)

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
    department_id = session.get('department_id')  
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
    department_id = session.get('department_id')  
    if 'department_id' not in session:
        return redirect(url_for('login'))
    
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for('login'))

# Route for adding a new patient
@controller.route('/add_patient', methods=['GET', 'POST'])
def add_patient():
    department_id = session.get('department_id')
    if not department_id:
        return redirect(url_for('login'))

    # Handle form submission (POST)
    if request.method == 'POST':
        # Collect form data
        first_name = request.form.get('first_name').upper()
        last_name = request.form.get('last_name').upper()
        date_of_birth = request.form.get('dob')
        gender = request.form.get('gender').upper()
        date_of_visit = request.form.get('dateOfVisit')
        chief_complaint = request.form.get('chiefComplaint')
        medical_history = request.form.get('medicalHistory')
        medications = request.form.get('medications')
        allergies = request.form.get('allergies')
        vital_signs = request.form.get('vitalSigns')
        terms_accepted = request.form.get('terms')

        # Generate a new patient ID
        patient_id = generate_id(first_name, last_name, "patients")
        doctor_id = department_id

        # Handle image uploads
        image_urls = []
        files = request.files.getlist('patient_image')  # Multiple files
        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                image_url = save_image(file, filename)
                image_urls.append(image_url)

        # Insert new patient data into the database
        cursor.execute("""
            INSERT INTO patients (patient_id, first_name, last_name, date_of_birth, gender, date_of_visit,
                                  chief_complaint, medical_history, medications, allergies, vital_signs, patient_image, terms_accepted, doctor_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (patient_id, first_name, last_name, date_of_birth, gender, date_of_visit, chief_complaint,
              medical_history, medications, allergies, vital_signs, ",".join(image_urls), terms_accepted, doctor_id))

        db.commit()
        flash("Patient added successfully.", "success")
        return redirect(url_for('view_patients'))

    # Render the form for adding a new patient
    return render_template('edit_patient.html', patient=None)
@controller.route('/edit_patient/<string:patient_id>', methods=['GET', 'POST'])
def edit_patient(patient_id):
    department_id = session.get('department_id')
    if not department_id:
        return redirect(url_for('login'))

    # Handle GET request to fetch existing patient data
    if request.method == 'GET':
        cursor.execute("SELECT * FROM patients WHERE patient_id = %s", (patient_id,))
        patient = cursor.fetchone()
        if patient:
            # Convert patient tuple to dictionary for easier access in template
            patient = dict(zip([column[0] for column in cursor.description], patient))
        return render_template('edit_patient.html', patient=patient)

    # Handle POST request to update patient details
    elif request.method == 'POST':
        first_name = request.form.get('first_name').upper()
        last_name = request.form.get('last_name').upper()
        date_of_birth = request.form.get('dob')
        gender = request.form.get('gender').upper()
        date_of_visit = request.form.get('dateOfVisit')
        chief_complaint = request.form.get('chiefComplaint')
        medical_history = request.form.get('medicalHistory')
        medications = request.form.get('medications')
        allergies = request.form.get('allergies')
        vital_signs = request.form.get('vitalSigns')
        terms_accepted = request.form.get('terms')

        image_file = request.files.get('patient_image')

        # Fetch the existing image URLs from the database
        cursor.execute("SELECT patient_image FROM patients WHERE patient_id = %s", (patient_id,))
        existing_image = cursor.fetchone()
        if existing_image:
            existing_image_urls = existing_image[0]  # Extract the stored image URLs (as a string)
        else:
            existing_image_urls = ""

        new_image_url = None
        if image_file and image_file.filename:  # A new image is uploaded
            filename = secure_filename(image_file.filename)
            new_image_url = save_image(image_file, filename)  # Save the new image and get its URL

        # Append the new image URL to the existing list, if present
        if new_image_url:
            if existing_image_urls:  # If there are existing URLs
                updated_image_urls = f"{existing_image_urls},{new_image_url}"
            else:  # No existing URLs
                updated_image_urls = new_image_url
        else:
            updated_image_urls = existing_image_urls  # Keep existing URLs if no new image

        # Update patient details in the database
        cursor.execute("""
            UPDATE patients
            SET first_name = %s, last_name = %s, date_of_birth = %s, gender = %s, date_of_visit = %s,
                chief_complaint = %s, medical_history = %s, medications = %s, 
                allergies = %s, vital_signs = %s, patient_image = %s, terms_accepted = %s
            WHERE patient_id = %s
        """, (first_name, last_name, date_of_birth, gender, date_of_visit, chief_complaint, medical_history,
              medications, allergies, vital_signs, updated_image_urls, terms_accepted, patient_id))

        db.commit()
        flash("Patient details updated successfully.", "success")
        return redirect(url_for('view_patients'))


@controller.route('/delete_image/<string:patient_id>/<path:image_url>')
def delete_image(patient_id, image_url):
    # Check if the user is logged in
    if 'department_id' not in session:
        return redirect(url_for('login'))
    
    department_id = session.get('department_id')
    
    cursor = db.cursor(dictionary=True)
    
    # Retrieve patient images from the database
    cursor.execute("SELECT patient_image FROM patients WHERE patient_id = %s", (patient_id,))
    patient = cursor.fetchone()
    
    if patient:
        current_images = patient['patient_image'].split(",")
        
        # Ensure the image URL exists in the list
        if image_url in current_images:
            current_images.remove(image_url)
            new_image_urls = ",".join(current_images)
            
            # Update the database with the new list
            cursor.execute("UPDATE patients SET patient_image = %s WHERE patient_id = %s", (new_image_urls, patient_id))
            db.commit()
            
            # Delete the file from the server
            file_path = os.path.join(image_url) 
            if os.path.exists(file_path):
                os.remove(file_path)
    
    # Redirect back to the patient edit page
    return redirect(url_for('edit_patient', patient_id=patient_id))

@controller.route('/view_images/<string:patient_id>')
def view_images(patient_id):
    # Verify if the user is authenticated
    department_id = session.get('department_id')
    if not department_id:
        return redirect(url_for('login'))
    
    # Retrieve patient data from the database
    cursor.execute("SELECT first_name, last_name, date_of_birth, gender, patient_image FROM patients WHERE patient_id = %s", (patient_id,))
    patient = cursor.fetchone()

    if patient:
        # Convert the fetched data to a dictionary with column names
        patient_dict = dict(zip([column[0] for column in cursor.description], patient))
        
        # Calculate age from date of birth
        dob = patient_dict.get('date_of_birth')
        try:
            if isinstance(dob, str):  # Convert to datetime if DOB is a string
                dob = datetime.strptime(dob, "%d-%m-%y")  # Adjust format if needed
            age = (datetime.today().date() - dob).days // 365
            patient_dict['age'] = age
        except ValueError:
            patient_dict['age'] = "Unknown"  # Handle DOB parsing error gracefully

        # Split image URLs if they exist
        image_urls = patient_dict['patient_image'].split(",") if patient_dict['patient_image'] else []
        
        # Create a list of images with descriptions
        images = [{"url": url, "description": "Uploaded Patient Image"} for url in image_urls]
    else:
        images = []
        patient_dict = {}

    # Render the template with patient data and images
    return render_template('patient_image.html', images=images, patient=patient_dict)

@controller.route('/delete_patient/<string:patient_id>', methods=['POST'])
def delete_patient(patient_id):
    department_id = session.get('department_id')  
    if 'department_id' not in session:
        return redirect(url_for('login'))
    
    cursor.execute("DELETE FROM patients WHERE patient_id = %s", (patient_id,))
    db.commit()
    return redirect(url_for('view_patients'))

# Export all patients for the logged-in doctor's department as Excel
@controller.route('/export_all_patients_excel')
def export_all_patients_excel():
    department_id = session.get('department_id')  # Get the department's ID from the session
    
    if not department_id:
        return "Please log in first", 403  # If the department is not logged in, return a 403 error
    
    # Fetch all patients for the department, using the doctor_id that references department_id
    cursor.execute("""
    SELECT p.patient_id, p.first_name, p.last_name, p.date_of_birth, p.gender, p.date_of_visit,
           p.chief_complaint, p.medical_history, p.medications, p.allergies, p.vital_signs, 
           p.doctor_id
    FROM patients p
    JOIN doctors d ON p.doctor_id = d.department_id
    WHERE d.department_id = %s
    """, (department_id,))
    patients = cursor.fetchall()

    if not patients:
        return "No patients found for this department", 404  # Return 404 if no patients are found
    
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
    department_id = session.get('department_id')  
    if 'department_id' not in session:
        return redirect(url_for('login'))
    
    # Fetch single patient data for the department, using the doctor_id that references department_id
    cursor.execute("""
    SELECT p.patient_id, p.first_name, p.last_name, p.date_of_birth, p.gender, p.date_of_visit,
           p.chief_complaint, p.medical_history, p.medications, p.allergies, p.vital_signs, p.terms_accepted,
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
@controller.route('/search', methods=['GET'])
def search():
    # Ensure doctor is logged in
    department_id = session.get('department_id')
    if not department_id:
        return redirect(url_for('login'))  # Redirect to login if not authenticated

    # Fetch the corresponding doctor_id based on department_id
    cursor = db.cursor(dictionary=True)
    cursor.execute("""
        SELECT department_id FROM doctors WHERE department_id = %s
    """, (department_id,))
    doctor = cursor.fetchone()
    
    if not doctor:
        return "No associated doctor found for this department.", 404  # Handle no doctor found

    doctor_id = doctor['department_id']

    # Get the search query (default is an empty string)
    query = request.args.get('query', '').strip()

    if query:
        # Use LIKE for partial matching
        cursor.execute("""
            SELECT * FROM patients 
            WHERE doctor_id = %s AND (first_name LIKE %s OR last_name LIKE %s)
        """, (doctor_id, f"%{query.upper()}%", f"%{query.upper()}%"))
    else:
        # Fetch all patients for the logged-in doctor
        cursor.execute("""
            SELECT * FROM patients
            WHERE doctor_id = %s
        """, (doctor_id,))

    patients = cursor.fetchall()  # Fetch all matching records
    cursor.close()  # Close the cursor after the query

    return render_template('doctors_patient.html', patients=patients)

@controller.route('/update_password', methods=['GET', 'POST'])
def update_password():
    department_id = session.get('department_id')  
    if 'department_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        # Get form data
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        # Check if user is logged in
        department_id = session.get('department_id')
        if not department_id:
            flash("You must be logged in to update your password.", "error")
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
            flash("New password and confirmation do not match.", "error")
            return redirect(url_for('update_password'))
        
          # Validate new password complexity
        if not re.match(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,}$', new_password):
            flash("Password must be at least 6 characters long and contain letters, numbers, and special characters.", "error")
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
    department_id = session.get('department_id')  
    if 'department_id' not in session:
        return redirect(url_for('login'))
    
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
 