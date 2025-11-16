import sqlite3
import hashlib

def hash_password(password):
    #hash password using SHA-256
    return hashlib.sha256(password.encode()).hexdigest()

def setup_database():
    #create or connect to hospital.db
    conn = sqlite3.connect('hospital.db')
    cursor = conn.cursor()
    
    #create users table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        user_id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('admin', 'doctor', 'receptionist'))
    );
    ''')
    print("Users table created.")

    #create patients table
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
    print("Patients table created.")

    #create logs table
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
    print("Logs table created.")

    #add initial users with hashed passwords
    initial_users = [
        ('admin', hash_password('admin123'), 'admin'),
        ('Dr. Bob', hash_password('doc123'), 'doctor'),
        ('Alice_recep', hash_password('rec123'), 'receptionist')
    ]
    
    try:
        cursor.executemany(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
            initial_users
        )
        conn.commit()
        print("Initial users added.")
    except sqlite3.IntegrityError:
        print("Initial users already exist.")
    except Exception as e:
        print(f"Error inserting users: {e}")

    #add test patient data
    try:
        cursor.execute(
            "INSERT INTO patients (name, contact, diagnosis) VALUES (?, ?, ?)", 
            ('John Doe', '555-123-4567', 'Common Cold')
        )
        cursor.execute(
            "INSERT INTO patients (name, contact, diagnosis) VALUES (?, ?, ?)", 
            ('Jane Smith', '555-987-6543', 'Flu')
        )
        conn.commit()
        print("Sample patients added.")
    except Exception:
        print("Sample patients already exist.")

    conn.close()
    print("Database setup complete.")

if __name__ == "__main__":
    setup_database()
