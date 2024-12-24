# # import sqlite3

# # with sqlite3.connect('database.db') as connection:
# #     cursor = connection.cursor()

# #     # Create users table
# #     cursor.execute('''
# #     CREATE TABLE IF NOT EXISTS users (
# #         id INTEGER PRIMARY KEY AUTOINCREMENT,
# #         username TEXT NOT NULL,
# #         email TEXT UNIQUE NOT NULL,
# #         password TEXT NOT NULL
# #     )
# #     ''')

# #     # Create tasks table
# #     cursor.execute('''
# #     CREATE TABLE IF NOT EXISTS tasks (
# #         id INTEGER PRIMARY KEY AUTOINCREMENT,
# #         user_id INTEGER NOT NULL,
# #         task TEXT NOT NULL,
# #         priority INTEGER NOT NULL,
# #         FOREIGN KEY (user_id) REFERENCES users (id)
# #     )
# #     ''')

# #     print("Database setup completed!")

# #     import sqlite3

# # conn = sqlite3.connect('database.db')
# # cursor = conn.cursor()

# # # Add the 'status' column to track if a task is done
# # cursor.execute('ALTER TABLE tasks ADD COLUMN status INTEGER DEFAULT 0')

# # conn.commit()
# # conn.close()
# # print("Column 'status' added successfully.")

# import sqlite3

# # Connect to the database
# conn = sqlite3.connect('database.db')
# cursor = conn.cursor()

# # Add a new 'category' column to the 'tasks' table
# cursor.execute('''
#     ALTER TABLE tasks ADD COLUMN category TEXT;
# ''')

# # Commit changes and close the connection
# conn.commit()
# conn.close()

# print("Category column added successfully to the 'tasks' table.")