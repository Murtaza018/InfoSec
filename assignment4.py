import streamlit as st
import sqlite3
import hashlib
import pandas as pd
from datetime import datetime
from cryptography.fernet import Fernet

def load_key():
#Loads the encryption key from 'secret.key'
    try:
        return open("secret.key", "rb").read()
    except FileNotFoundError:
        st.error("Encryption key 'secret.key' not found. Please run generateKey.py")
        return None

def initialize_fernet():
#Initializes the Fernet cipher suite.
    key = load_key()
    if key:
        return Fernet(key)
    return None

def encrypt_data(data, fernet_obj):
#Encrypts data.
    if not fernet_obj:
        return None
    #Encode the string to bytes
    return fernet_obj.encrypt(data.encode())

def decrypt_data(data, fernet_obj):
#Decrypts data and returns a string.
    if not fernet_obj or not data:
        return "N/A"
    try:
        #Decrypts bytes and decodes to string
        return fernet_obj.decrypt(data).decode()
    except Exception:
        return "DECRYPTION_ERROR"

@st.cache_data
def convert_df_to_csv(df):
#Converts a DataFrame to a CSV string.
    return df.to_csv(index=False).encode('utf-8')

def mask_contact(contact):
#Applies masking to a contact number.
    if contact and len(contact) >= 4:
        return f"XXX-XXX-{contact[-4:]}"
    return "XXX-XXX-XXXX"

def anonymize_patient_data():
#Encrypts PII for patients using Fernet.
    fernet_obj = initialize_fernet()
    if not fernet_obj:
        st.error("Cannot perform encryption: Fernet not initialized.")
        return

    try:
        conn = get_db_conn()
        cursor = conn.cursor()
        
        #Find patients needing anonymization
        cursor.execute("SELECT patient_id, name, contact FROM patients WHERE anonymized_name IS NULL")
        patients_to_anonymize = cursor.fetchall()
        
        if not patients_to_anonymize:
            st.info("All patient data is already anonymized.")
            return

        update_count = 0
        for patient in patients_to_anonymize:
            #Encrypt the PII
            #Store encrypted bytes
            encrypted_name = encrypt_data(patient['name'], fernet_obj)
            encrypted_contact = encrypt_data(patient['contact'], fernet_obj)
            
            #Update the database
            cursor.execute(
                "UPDATE patients SET anonymized_name = ?, anonymized_contact = ? WHERE patient_id = ?",
                (encrypted_name, encrypted_contact, patient['patient_id'])
            )
            update_count += 1
            
        conn.commit()
        conn.close()
        
        st.success(f"Successfully encrypted {update_count} new patient records.")
        #Log this action
        log_action(
            st.session_state.user_id, 
            st.session_state.role, 
            "DATA ENCRYPTION (BONUS)", 
            f"Encrypted {update_count} records."
        )

    except Exception as e:
        st.error(f"Database error during encryption: {e}")
        log_action(
            st.session_state.user_id, 
            st.session_state.role, 
            "ENCRYPTION FAIL", 
            str(e)
        )
    
def get_db_conn():
#Establishes SQLite database connection.
    conn = sqlite3.connect('hospital.db')
    conn.row_factory = sqlite3.Row
    return conn

def log_action(user_id, role, action, details=""):
#Records an action in the logs table.
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
        print(f"Error logging action: {e}") #Log error to console

def hash_password(password):
#Hashes a password using SHA-256.
    return hashlib.sha256(password.encode()).hexdigest()

def login_page():
#Displays the login page and handles authentication.
    st.title("Hospital Management System Login")
    
    st.info("""
    **Notice of Data Processing**
    By logging in, you acknowledge that you are an authorized user and consent 
    to your actions being monitored and logged for security and auditing purposes 
    in accordance with data protection policies.
    """)
    
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        
        #Consent checkbox
        consent_given = st.checkbox("I acknowledge and consent to the notice above.")
        
        submit_button = st.form_submit_button("Login")

        if submit_button:
            #Check for consent
            if not consent_given:
                st.error("You must acknowledge the data processing notice to log in.")
                return 

            hashed_password = hash_password(password)
            
            #Error handling for DB query
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
                    st.session_state.logged_in = True
                    st.session_state.user_id = user['user_id']
                    st.session_state.username = username
                    st.session_state.role = user['role']
                    
                    #Log the successful login
                    log_action(user['user_id'], user['role'], "LOGIN_SUCCESS", 
                               f"User {username} logged in (Consent Given).")
                    
                    st.rerun() #Refresh the app
                else:
                    st.error("Invalid username or password.")
                    #Log the failed login attempt
                    log_action(None, "guest", "LOGIN_FAIL", 
                               f"Failed login attempt for user {username}.")

            except Exception as e:
                st.error(f"An error occurred during login. Please try again. {e}")

def admin_dashboard():
#Admin dashboard with nested tabs.
    st.title("Admin Dashboard")
    st.write(f"Welcome, **{st.session_state.username}**!")
    st.write("You have full access to all system functions.")

    #Data Export (Availability)
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

    #Main admin tabs
    op_tab, data_tab, audit_tab = st.tabs([
        "Main Operations", 
        "Patient Data Views", 
        "Audit & Security"
    ])

    #Tab 1: Main Operations
    with op_tab:
        
        encrypt_sub, retention_sub = st.tabs([
            "Process Encryption (Bonus)", 
            "Data Retention (Bonus)"
        ])
        
        with encrypt_sub:
            st.subheader("Process Data for Encryption")
            st.warning("This action will encrypt PII using the 'secret.key'.")
            
            if st.button("Run Encryption Process"):
                anonymize_patient_data()
                st.rerun()

        with retention_sub:
            st.subheader("Data Retention Policy Management")
            st.warning("DANGER: This action is irreversible and will permanently delete data.")
            
            days_to_keep = st.number_input(
                "Delete data older than (days):", 
                min_value=30, 
                value=365
            )
            
            target_date = datetime.now() - pd.Timedelta(days=days_to_keep)
            st.write(f"This will delete records created before: **{target_date.strftime('%Y-%m-%d')}**")
            
            if st.button("DELETE OLD RECORDS"):
                try:
                    conn = get_db_conn()
                    cursor = conn.cursor()
                    
                    cursor.execute("DELETE FROM patients WHERE date_added < ?", (target_date,))
                    patients_deleted = cursor.rowcount
                    
                    cursor.execute("DELETE FROM logs WHERE timestamp < ?", (target_date,))
                    logs_deleted = cursor.rowcount
                    
                    conn.commit()
                    conn.close()
                    
                    st.success(f"Data purge complete. "
                               f"Deleted {patients_deleted} patient records and {logs_deleted} log entries.")
                    
                    log_action(
                        st.session_state.user_id, st.session_state.role,
                        "DATA PURGE (RETENTION)",
                        f"Deleted records older than {days_to_keep} days."
                    )
                    st.rerun()
                    
                except Exception as e:
                    st.error(f"Error during data purge: {e}")
                    log_action(
                        st.session_state.user_id, st.session_state.role,
                        "DATA PURGE FAIL", str(e)
                    )

    #Tab 2: Patient Data Views
    with data_tab:
        
        raw_sub, enc_sub, dec_sub = st.tabs([
            "Raw Patient Data (Admin Only)", 
            "Encrypted (Doctor's View)", 
            "Decrypted (Admin View)"
        ])

        with raw_sub:
            st.subheader("Raw Patient Data")
            try:
                conn = get_db_conn()
                raw_df = pd.read_sql_query("SELECT patient_id, name, contact, diagnosis, date_added FROM patients", conn)
                conn.close()
                st.dataframe(raw_df)
                log_action(st.session_state.user_id, st.session_state.role, "VIEW RAW DATA", f"Viewed {len(raw_df)} raw records.")
            except Exception as e:
                st.error(f"Database error: {e}")

        with enc_sub:
            st.subheader("Encrypted Patient Data (Doctor's View)")
            try:
                conn = get_db_conn()
                anon_df = pd.read_sql_query("SELECT patient_id, anonymized_name, anonymized_contact, diagnosis, date_added FROM patients", conn)
                conn.close()
                st.dataframe(anon_df)
            except Exception as e:
                st.error(f"Database error: {e}")
                
        with dec_sub:
            st.subheader("Decrypted Patient View (Reversible)")
            fernet_obj = initialize_fernet()
            if not fernet_obj:
                st.error("Cannot decrypt data: Fernet not initialized.")
            else:
                try:
                    conn = get_db_conn()
                    encrypted_df = pd.read_sql_query("SELECT patient_id, anonymized_name, anonymized_contact, diagnosis FROM patients", conn)
                    conn.close()
                    
                    decrypted_df = encrypted_df.copy()
                    decrypted_df['anonymized_name'] = decrypted_df['anonymized_name'].apply(lambda x: decrypt_data(x, fernet_obj))
                    decrypted_df['anonymized_contact'] = decrypted_df['anonymized_contact'].apply(lambda x: decrypt_data(x, fernet_obj))
                    
                    decrypted_df.rename(columns={'anonymized_name': 'Decrypted Name', 'anonymized_contact': 'Decrypted Contact'}, inplace=True)
                    st.dataframe(decrypted_df)
                    log_action(st.session_state.user_id, st.session_state.role, "VIEW DECRYPTED DATA", f"Viewed {len(decrypted_df)} decrypted records.")
                except Exception as e:
                    st.error(f"Database error during decryption: {e}")

    #Tab 3: Audit & Security
    with audit_tab:
        
        graph_sub, log_sub = st.tabs([
            "Activity Graphs (Bonus)", 
            "Integrity Audit Log (Admin Only)"
        ])

        with graph_sub:
            st.subheader("Real-time Activity Graphs")
            try:
                conn = get_db_conn()
                logs_df = pd.read_sql_query("SELECT timestamp, role FROM logs", conn)
                conn.close()
                
                if logs_df.empty:
                    st.info("No activity logs to display yet.")
                else:
                    logs_df['timestamp'] = pd.to_datetime(logs_df['timestamp'])
                    st.markdown("##### Total Actions Per Day")
                    logs_df['date'] = logs_df['timestamp'].dt.date
                    actions_per_day = logs_df.groupby('date').size().reset_index(name='actions')
                    actions_per_day = actions_per_day.set_index('date')
                    st.bar_chart(actions_per_day)

                    st.markdown("##### Total Actions by Role")
                    actions_by_role = logs_df.groupby('role').size().reset_index(name='actions')
                    actions_by_role = actions_by_role.set_index('role')
                    st.bar_chart(actions_by_role)
            except Exception as e:
                st.error(f"Error generating graphs: {e}")
                
        with log_sub:
            st.subheader("Integrity Audit Log")
            try:
                conn = get_db_conn()
                logs_df = pd.read_sql_query("SELECT * FROM logs ORDER BY timestamp DESC", conn)
                conn.close()
                st.dataframe(logs_df)
                log_action(st.session_state.user_id, st.session_state.role, "VIEW AUDIT LOG", f"Viewed {len(logs_df)} log entries.")
            except Exception as e:
                st.error(f"Database error: {e}")

def doctor_dashboard():
#Doctor dashboard - shows anonymized data only.
    st.title("Doctor Dashboard")
    st.write(f"Welcome, **{st.session_state.username}**!")
    
    st.subheader("Anonymized Patient View")
    st.markdown("""
    This view protects patient **Confidentiality**. 
    You can see diagnoses, but patient identifiers (name and contact)
    have been masked.
    """)
    
    #Use try/except for DB queries
    try:
        conn = get_db_conn()
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

        #Log the doctor's view action
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

def receptionist_dashboard():
#Receptionist dashboard - add/edit patients.
    st.title("Receptionist Dashboard")
    st.write(f"Welcome, **{st.session_state.username}**!")
    st.write("You can add or edit patient records.")

    tab1, tab2 = st.tabs(["Add New Patient", "Edit Patient Information"])

    #Tab 1: Add New Patient
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
                    #Use try/except for DB operations
                    try:
                        conn = get_db_conn()
                        cursor = conn.cursor()
                        cursor.execute(
                            "INSERT INTO patients (name, contact, diagnosis) VALUES (?, ?, ?)",
                            (name, contact, diagnosis)
                        )
                        conn.commit()
                        conn.close()
                        
                        #Log this action
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

    #Tab 2: Edit Patient Information
    with tab2:
        st.subheader("Edit Existing Patient Information")
        
        try:
            #Get patient list for selectbox
            conn = get_db_conn()
            cursor = conn.cursor()
            cursor.execute("SELECT patient_id, name FROM patients")
            patients = cursor.fetchall()
            conn.close()
            
            #Create dict for selectbox
            patient_dict = {f"{p['name']} (ID: {p['patient_id']})": p['patient_id'] for p in patients}
            selected_patient_str = st.selectbox("Select Patient to Edit", patient_dict.keys())
            
            if selected_patient_str:
                selected_patient_id = patient_dict[selected_patient_str]
                
                #Get non-sensitive data for selected patient
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
                        
                        new_name = st.text_input("Patient Name", value=patient_data['name'])
                        new_contact = st.text_input("Patient Contact", value=patient_data['contact'])
                        
                        #Diagnosis is NOT fetched or displayed
                        
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
                                
                                #Log this action
                                log_action(
                                    st.session_state.user_id, 
                                    st.session_state.role, 
                                    "UPDATE PATIENT", 
                                    f"Updated info for patient ID: {selected_patient_id}"
                                )
                                st.success(f"Successfully updated info for {new_name}.")
                                st.rerun() #Refresh page
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

def main():
#Main application router.
    #Initialize session state
    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False
        st.session_state.user_id = None
        st.session_state.username = None
        st.session_state.role = None

    if st.session_state.logged_in:
        #Main App Interface
        st.sidebar.title("Navigation")
        st.sidebar.markdown(f"User: **{st.session_state.username}**")
        st.sidebar.markdown(f"Role: **{st.session_state.role.capitalize()}**")

        if st.sidebar.button("Logout"):
            log_action(st.session_state.user_id, st.session_state.role, "LOGOUT")
            
            #Clear session state
            st.session_state.logged_in = False
            st.session_state.user_id = None
            st.session_state.username = None
            st.session_state.role = None
            st.rerun()

        #Role-Based Access Control (RBAC)
        role = st.session_state.role
        if role == 'admin':
            admin_dashboard()
        elif role == 'doctor':
            doctor_dashboard()
        elif role == 'receptionist':
            receptionist_dashboard()
        else:
            st.error("Unknown role. Please contact support.")

        #Availability Footer
        st.caption(f"System Status: OK | Last Sync: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    else:
        #Show Login Page
        login_page()

if __name__ == "__main__":
    main()