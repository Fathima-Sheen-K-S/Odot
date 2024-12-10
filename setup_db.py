import sqlite3

# Connect to the database (creates the file if it doesn't exist)
connection = sqlite3.connect('database.db')

# Create the users table
with connection:
    connection.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    ''')
print("Database and 'users' table created successfully!")

connection.close()
