import sqlite3
from datetime import datetime
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'users.db')

def init_db():
    """Initialize the database with users table"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Drop old table if exists and create new one with email
    cursor.execute('DROP TABLE IF EXISTS users')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()
    print("Database initialized successfully with email support")

def create_user(email):
    """Create a new user with email"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute(
            'INSERT INTO users (email, last_login) VALUES (?, ?)',
            (email, datetime.now())
        )
        
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        # User already exists
        return False

def get_user_by_email(email):
    """Get user by email"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('SELECT id, email, created_at, last_login FROM users WHERE email = ?', (email,))
    user = cursor.fetchone()
    
    conn.close()
    
    if user:
        return {
            'id': user[0],
            'email': user[1],
            'created_at': user[2],
            'last_login': user[3]
        }
    return None

def update_last_login(email):
    """Update last login timestamp"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute(
        'UPDATE users SET last_login = ? WHERE email = ?',
        (datetime.now(), email)
    )
    
    conn.commit()
    conn.close()

# Initialize database on import
init_db()
