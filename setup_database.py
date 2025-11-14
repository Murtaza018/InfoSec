import sqlite3
import hashlib

def hash_password(password):
    """Hashes a password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

def setup_database():
    """
    Creates the hospital.db file, defines the schema, 
    and inserts initial user data.
    """
    conn = sqlite3.connect('hospital.db')
    cursor = conn.cursor()
    
    # --- Create users table ---
    # Stores login credentials and roles [cite: 60]
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        user_id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('admin', 'doctor', 'receptionist'))
    );
    ''')
    print("Users table created successfully.")

    # --- Create patients table ---
    # Stores patient records, including fields for anonymized data [cite: 62, 63]
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS patients (
        patient_id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        contact TEXT NOT NULL,
        diagnosis TEXT NOT NULL,
        anonymized_name TEXT,
        anonymized_contact TEXT,
        date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    ''')
    print("Patients table created successfully.")

    # --- Create logs table ---
    # Stores audit trail for all user actions [cite: 64, 65]
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS logs (
        log_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        role TEXT,
        action TEXT NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        details TEXT,
        FOREIGN KEY (user_id) REFERENCES users (user_id)
    );
    ''')
    print("Logs table created successfully.")

    # --- Insert initial users ---
    # 
    # We hash the passwords for better security than plaintext.
    initial_users = [
        ('admin', hash_password('admin123'), 'admin'),
        ('Dr. Bob', hash_password('doc123'), 'doctor'),
        ('Alice_recep', hash_password('rec123'), 'receptionist')
    ]
    
    try:
        cursor.executemany("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", initial_users)
        conn.commit()
        print(f"Successfully inserted {len(initial_users)} initial users.")
    except sqlite3.IntegrityError:
        # This error happens if you run the script more than once
        print("Initial users already exist in the database.")
    except Exception as e:
        print(f"An error occurred while inserting users: {e}")

    # --- Add sample patient data (optional, for testing) ---
    try:
        cursor.execute("INSERT INTO patients (name, contact, diagnosis) VALUES (?, ?, ?)", 
                       ('John Doe', '555-123-4567', 'Common Cold'))
        cursor.execute("INSERT INTO patients (name, contact, diagnosis) VALUES (?, ?, ?)", 
                       ('Jane Smith', '555-987-6543', 'Flu'))
        conn.commit()
        print("Added sample patient data.")
    except Exception:
        print("Sample patient data already exists.")

    conn.close()
    print("Database setup complete. 'hospital.db' is ready.")

if __name__ == "__main__":
    setup_database()