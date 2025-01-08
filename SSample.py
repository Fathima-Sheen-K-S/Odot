import sqlite3

try:
    # Connect to the database
    with sqlite3.connect('database.db') as connection:
        cursor = connection.cursor()

        # Insert admin record with plain text password
        cursor.execute('''
            INSERT INTO admins (username, password, email)
            VALUES (?, ?, ?)
        ''', ('ODOT', 'odot123', 'adminodot@gmail.com'))

        # Commit changes
        connection.commit()

        print("Admin inserted successfully!")
except sqlite3.Error as e:
    print(f"An error occurred: {e}")
