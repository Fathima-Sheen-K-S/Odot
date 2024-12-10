from flask import Flask, render_template, request, redirect, flash, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Secret key for flash messages and session management
app.secret_key = 'your_secret_key_here'

# Home route
@app.route('/')
def home():
    return render_template('index.html')

# Register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Hash the password for security
        hashed_password = generate_password_hash(password)

        try:
            # Insert user data into the database
            with sqlite3.connect('database.db') as connection:
                cursor = connection.cursor()
                cursor.execute('''
                    INSERT INTO users (username, email, password) 
                    VALUES (?, ?, ?)
                ''', (username, email, hashed_password))
                connection.commit()
                flash('Registration successful!', 'success')
                return redirect('/login')  # Redirect to login page after successful registration
        except sqlite3.IntegrityError:
            flash('Email already exists!', 'error')
            return redirect('/register')
    return render_template('userregister.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        try:
            # Query the database for the user
            with sqlite3.connect('database.db') as connection:
                cursor = connection.cursor()
                cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
                user = cursor.fetchone()

                if user and check_password_hash(user[3], password):  # Password is hashed in DB
                    # Login successful
                    session['user_id'] = user[0]
                    session['username'] = user[1]
                    flash('Login successful!', 'success')
                    return redirect('/')
                else:
                    # Invalid credentials
                    flash('Invalid email or password!', 'error')
        except Exception as e:
            flash('An error occurred. Please try again.', 'error')

    return render_template('login.html')

if __name__ == '__main__':
    app.run(debug=True)
