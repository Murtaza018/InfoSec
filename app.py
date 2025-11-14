import streamlit as st
import sqlite3
import hashlib
import pandas as pd
from datetime import datetime
# ... (your other imports)
from cryptography.fernet import Fernet

# --- (Keep your existing functions: get_db_conn, log_action, etc.) ---

# --- New Bonus Functions: Fernet Encryption ---

def load_key():
    """Loads the encryption key from the 'secret.key' file."""
    try:
        return open("secret.key", "rb").read()
    except FileNotFoundError:
        st.error("Encryption key 'secret.key' not found. Please run generate_key.py")
        return None

def initialize_fernet():
    """Initializes the Fernet cipher suite."""
    key = load_key()
    if key:
        return Fernet(key)
    return None

def encrypt_data(data, fernet_obj):
    """Encrypts data (must be bytes)."""
    if not fernet_obj:
        return None
    # We encode the string to bytes before encrypting
    return fernet_obj.encrypt(data.encode())

def decrypt_data(data, fernet_obj):
    """Decrypts data (must be bytes) and returns a string."""
    if not fernet_obj or not data:
        return "N/A"
    try:
        # Decrypts the bytes and decodes them back to a string
        return fernet_obj.decrypt(data).decode()
    except Exception:
        return "DECRYPTION_ERROR"

# --- (Keep your existing functions: convert_df_to_csv, mask_contact) ---


@st.cache_data
def convert_df_to_csv(df):
    """Converts a DataFrame to a CSV string for download."""
    return df.to_csv(index=False).encode('utf-8')

def mask_contact(contact):
    """
    Applies masking to a contact number as per requirement.
    Example: 555-123-4567 -> XXX-XXX-4567
    [cite: 37]
    """
    if contact and len(contact) >= 4:
        return f"XXX-XXX-{contact[-4:]}"
    return "XXX-XXX-XXXX"

def anonymize_patient_data():
    """
    Finds patients without anonymized data and updates their records.
    This is triggered by the Admin. 
    """
    try:
        conn = get_db_conn()
        cursor = conn.cursor()
        
        # Find all patients that haven't been anonymized yet
        cursor.execute("SELECT patient_id, name, contact FROM patients WHERE anonymized_name IS NULL")
        patients_to_anonymize = cursor.fetchall()
        
        if not patients_to_anonymize:
            st.info("All patient data is already anonymized.")
            return

        update_count = 0
        for patient in patients_to_anonymize:
            # Create anonymized data as per requirements [cite: 36, 37]
            anon_name = f"ANON_{patient['patient_id'] + 1000}" # e.g., ANON_1001
            anon_contact = mask_contact(patient['contact'])
            
            # Update the database
            cursor.execute(
                "UPDATE patients SET anonymized_name = ?, anonymized_contact = ? WHERE patient_id = ?",
                (anon_name, anon_contact, patient['patient_id'])
            )
            update_count += 1
            
        conn.commit()
        conn.close()
        
        st.success(f"Successfully anonymized {update_count} new patient records.")
        # Integrity: Log this critical action
        log_action(
            st.session_state.user_id, 
            st.session_state.role, 
            "DATA ANONYMIZATION", 
            f"Anonymized {update_count} records."
        )

    except Exception as e:
        st.error(f"Database error during anonymization: {e}")
        log_action(
            st.session_state.user_id, 
            st.session_state.role, 
            "ANONYMIZATION FAIL", 
            str(e)
        )
# --- Database Setup ---

def get_db_conn():
    """Establishes a connection to the SQLite database."""
    conn = sqlite3.connect('hospital.db')
    conn.row_factory = sqlite3.Row
    return conn

# --- Core Requirement: Integrity (Logging) ---

def log_action(user_id, role, action, details=""):
    """
    Records an action in the logs table.
    This is a core function for the Integrity requirement. [cite: 48, 49]
    """
    try:
        conn = get_db_conn()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO logs (user_id, role, action, details) VALUES (?, ?, ?, ?)",
            (user_id, role, action, details)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error logging action: {e}") # Log to console, not to user

# --- Core Requirement: Confidentiality (Authentication) ---

def hash_password(password):
    """Hashes a password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

def login_page():
    """
    Displays the login page and handles user authentication. 
    """
    st.title("🏥 Hospital Management System Login")
    
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submit_button = st.form_submit_button("Login")

        if submit_button:
            hashed_password = hash_password(password)
            
            # Availability Requirement: Error handling for DB query 
            try:
                conn = get_db_conn()
                cursor = conn.cursor()
                
                cursor.execute(
                    "SELECT user_id, password, role FROM users WHERE username = ?", 
                    (username,)
                )
                user = cursor.fetchone()
                conn.close()

                if user and user['password'] == hashed_password:
                    # Authentication successful
                    st.session_state.logged_in = True
                    st.session_state.user_id = user['user_id']
                    st.session_state.username = username
                    st.session_state.role = user['role']
                    
                    # Log the successful login (Integrity) [cite: 49]
                    log_action(user['user_id'], user['role'], "LOGIN_SUCCESS", 
                               f"User {username} logged in.")
                    
                    st.rerun() # Refresh the app to show the main dashboard
                else:
                    st.error("Invalid username or password.")
                    # Log the failed login attempt
                    log_action(None, "guest", "LOGIN_FAIL", 
                               f"Failed login attempt for user {username}.")

            except Exception as e:
                st.error(f"An error occurred during login. Please try again. {e}")

# --- Role-Specific Dashboards (Placeholders) ---

# --- ADMIN DASHBOARD ---

def admin_dashboard():
    st.title("Admin Dashboard")
    st.write(f"Welcome, **{st.session_state.username}**!")
    st.write("You have full access to all system functions.")

    # --- Availability Requirement: Data Export  ---
    st.sidebar.header("Data Export (Availability)")
    try:
        conn = get_db_conn()
        backup_df = pd.read_sql_query("SELECT * FROM patients", conn)
        conn.close()
        
        csv_data = convert_df_to_csv(backup_df)
        
        st.sidebar.download_button(
            label="Export All Patient Data (CSV)",
            data=csv_data,
            file_name="patient_data_export.csv",
            mime="text/csv",
        )
    except Exception as e:
        st.sidebar.error(f"Failed to load data for export: {e}")


    # --- Dashboard Tabs ---
    tab1, tab2, tab3, tab4 = st.tabs([
        "Process Anonymization", 
        "Raw Patient Data (Admin Only)", 
        "Anonymized Patient View", 
        "Integrity Audit Log (Admin Only)"
    ])

    # --- Tab 1: Anonymization Trigger ---
    with tab1:
        st.subheader("Process Data for Anonymization")
        st.warning("This action is irreversible.")
        st.markdown("""
        Click the button below to find all patient records that have not been anonymized
        and apply the masking rules (`ANON_...` and `XXX-XXX-...`).
        This makes the data ready for the Doctor role. 
        """)
        
        if st.button("Run Anonymization Process"):
            anonymize_patient_data()
            st.rerun() # Refresh data in other tabs

    # --- Tab 2: Raw Patient Data (Confidentiality) ---
    with tab2:
        st.subheader("Raw Patient Data")
        st.markdown("This view shows the **original, unmasked** patient data. [cite: 41]")
        try:
            conn = get_db_conn()
            raw_df = pd.read_sql_query(
                "SELECT patient_id, name, contact, diagnosis, date_added FROM patients", 
                conn
            )
            conn.close()
            st.dataframe(raw_df)
            
            # Integrity: Log the view action
            log_action(
                st.session_state.user_id, 
                st.session_state.role, 
                "VIEW RAW DATA",
                f"Viewed {len(raw_df)} raw records."
            )
        except Exception as e:
            st.error(f"Database error: {e}")

    # --- Tab 3: Anonymized Patient View ---
    with tab3:
        st.subheader("Anonymized Patient Data")
        st.markdown("This view shows the **anonymized** patient data, as it would appear for a Doctor. ")
        try:
            conn = get_db_conn()
            # Doctors can see the diagnosis, but not the patient's real name or contact
            anon_df = pd.read_sql_query(
                "SELECT patient_id, anonymized_name, anonymized_contact, diagnosis, date_added FROM patients", 
                conn
            )
            conn.close()
            st.dataframe(anon_df)
        except Exception as e:
            st.error(f"Database error: {e}")
            
    # --- Tab 4: Integrity Audit Log (Integrity) ---
    with tab4:
        st.subheader("Integrity Audit Log")
        st.markdown("This log tracks all user actions in the system. [cite: 51]")
        try:
            conn = get_db_conn()
            logs_df = pd.read_sql_query(
                "SELECT * FROM logs ORDER BY timestamp DESC", 
                conn
            )
            conn.close()
            st.dataframe(logs_df)
            
            # Integrity: Log the view action
            log_action(
                st.session_state.user_id, 
                st.session_state.role, 
                "VIEW AUDIT LOG",
                f"Viewed {len(logs_df)} log entries."
            )
        except Exception as e:
            st.error(f"Database error: {e}")


# --- DOCTOR DASHBOARD ---

def doctor_dashboard():
    st.title("Doctor Dashboard")
    st.write(f"Welcome, **{st.session_state.username}**!")
    
    st.subheader("Anonymized Patient View")
    st.markdown("""
    This view protects patient **Confidentiality**. 
    You can see diagnoses, but patient identifiers (name and contact)
    have been masked. [cite: 42, 35]
    """)
    
    # Availability: Use try/except for DB queries
    try:
        conn = get_db_conn()
        # Doctor only sees anonymized data. 
        # They can see the diagnosis, but not the PII (name, contact).
        query = """
        SELECT patient_id, anonymized_name, anonymized_contact, diagnosis, date_added 
        FROM patients
        WHERE anonymized_name IS NOT NULL
        """
        doctor_df = pd.read_sql_query(query, conn)
        conn.close()

        if doctor_df.empty:
            st.info("No anonymized patient records are available to display.")
        else:
            st.dataframe(doctor_df)

        # Integrity: Log the doctor's view action
        log_action(
            st.session_state.user_id, 
            st.session_state.role, 
            "VIEW ANONYMIZED DATA",
            f"Viewed {len(doctor_df)} anonymized records."
        )

    except Exception as e:
        st.error(f"An error occurred while fetching patient data: {e}")
        log_action(
            st.session_state.user_id, 
            st.session_state.role, 
            "VIEW DATA FAIL",
            str(e)
        )


# --- RECEPTIONIST DASHBOARD ---

def receptionist_dashboard():
    """
    Dashboard for the Receptionist.
    - Can add new patients.
    - Can edit existing patient contact info.
    - CANNOT view sensitive data (diagnosis). [cite: 43]
    """
    st.title("Receptionist Dashboard")
    st.write(f"Welcome, **{st.session_state.username}**!")
    st.write("You can add or edit patient records.")

    tab1, tab2 = st.tabs(["Add New Patient", "Edit Patient Information"])

    # --- Tab 1: Add New Patient ---
    with tab1:
        st.subheader("Add a New Patient Record")
        with st.form("add_patient_form"):
            name = st.text_input("Patient Name")
            contact = st.text_input("Patient Contact (e.g., Phone or Email)")
            diagnosis = st.text_area("Patient Diagnosis (Sensitive)")
            
            submitted = st.form_submit_button("Add Patient")
            
            if submitted:
                if not name or not contact or not diagnosis:
                    st.error("All fields are required.")
                else:
                    # Availability/Integrity: Use try/except for DB operations
                    try:
                        conn = get_db_conn()
                        cursor = conn.cursor()
                        cursor.execute(
                            "INSERT INTO patients (name, contact, diagnosis) VALUES (?, ?, ?)",
                            (name, contact, diagnosis)
                        )
                        conn.commit()
                        conn.close()
                        
                        # Integrity: Log this action
                        log_action(
                            st.session_state.user_id, 
                            st.session_state.role, 
                            "ADD PATIENT", 
                            f"Added new patient: {name}"
                        )
                        st.success(f"Successfully added patient: {name}")
                    except Exception as e:
                        st.error(f"Database error: {e}")
                        log_action(
                            st.session_state.user_id, 
                            st.session_state.role, 
                            "ADD PATIENT FAIL", 
                            f"Failed to add patient: {name}. Error: {e}"
                        )

    # --- Tab 2: Edit Patient Information ---
    with tab2:
        st.subheader("Edit Existing Patient Information")
        
        try:
            # Get list of patients for selection
            conn = get_db_conn()
            cursor = conn.cursor()
            cursor.execute("SELECT patient_id, name FROM patients")
            patients = cursor.fetchall()
            conn.close()
            
            # Create a dictionary for the selectbox: 'Patient Name (ID: 1)' -> 1
            patient_dict = {f"{p['name']} (ID: {p['patient_id']})": p['patient_id'] for p in patients}
            selected_patient_str = st.selectbox("Select Patient to Edit", patient_dict.keys())
            
            if selected_patient_str:
                selected_patient_id = patient_dict[selected_patient_str]
                
                # Get *only* non-sensitive data for the selected patient
                conn = get_db_conn()
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT name, contact FROM patients WHERE patient_id = ?", 
                    (selected_patient_id,)
                )
                patient_data = cursor.fetchone()
                conn.close()
                
                if patient_data:
                    with st.form("edit_patient_form"):
                        st.write(f"Editing Patient ID: {selected_patient_id}")
                        
                        # Populate form with existing non-sensitive data
                        new_name = st.text_input("Patient Name", value=patient_data['name'])
                        new_contact = st.text_input("Patient Contact", value=patient_data['contact'])
                        
                        # Confidentiality: Note that 'diagnosis' is NOT fetched or displayed [cite: 43]
                        
                        edit_submitted = st.form_submit_button("Update Information")
                        
                        if edit_submitted:
                            try:
                                conn = get_db_conn()
                                cursor = conn.cursor()
                                cursor.execute(
                                    "UPDATE patients SET name = ?, contact = ? WHERE patient_id = ?",
                                    (new_name, new_contact, selected_patient_id)
                                )
                                conn.commit()
                                conn.close()
                                
                                # Integrity: Log this action
                                log_action(
                                    st.session_state.user_id, 
                                    st.session_state.role, 
                                    "UPDATE PATIENT", 
                                    f"Updated info for patient ID: {selected_patient_id}"
                                )
                                st.success(f"Successfully updated info for {new_name}.")
                                st.rerun() # Refresh the page to show updated data
                            except Exception as e:
                                st.error(f"Database error: {e}")
                                log_action(
                                    st.session_state.user_id, 
                                    st.session_state.role, 
                                    "UPDATE PATIENT FAIL", 
                                    f"Failed to update patient ID: {selected_patient_id}. Error: {e}"
                                )
                else:
                    st.error("Could not find patient data.")
                    
        except Exception as e:
            st.error(f"Error loading patient list: {e}")


# --- Main Application Router ---

def main():
    """
    Main application router.
    Checks if the user is logged in and displays the appropriate page.
    """
    # Initialize session state if not already done
    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False
        st.session_state.user_id = None
        st.session_state.username = None
        st.session_state.role = None

    if st.session_state.logged_in:
        # --- Main App Interface ---
        st.sidebar.title("Navigation")
        st.sidebar.markdown(f"User: **{st.session_state.username}**")
        st.sidebar.markdown(f"Role: **{st.session_state.role.capitalize()}**")

        if st.sidebar.button("Logout"):
            log_action(st.session_state.user_id, st.session_state.role, "LOGOUT")
            
            # Clear session state
            st.session_state.logged_in = False
            st.session_state.user_id = None
            st.session_state.username = None
            st.session_state.role = None
            st.rerun()

        # --- Role-Based Access Control (RBAC) ---
        # This logic implements requirement 1.iii [cite: 39]
        role = st.session_state.role
        if role == 'admin':
            admin_dashboard()
        elif role == 'doctor':
            doctor_dashboard()
        elif role == 'receptionist':
            receptionist_dashboard()
        else:
            st.error("Unknown role. Please contact support.")

        # --- Availability Requirement: Footer [cite: 58] ---
        st.caption(f"System Status: OK | Last Sync: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    else:
        # --- Show Login Page ---
        login_page()

if __name__ == "__main__":
    main()