import os

import matplotlib
matplotlib.use('Agg')  # Disable GUI backend for matplotlib
import matplotlib.pyplot as plt
from flask import Flask, render_template, request, redirect, flash, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
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

        try:
            with sqlite3.connect('database.db') as connection:
                cursor = connection.cursor()
                cursor.execute('''
                    INSERT INTO users (username, email, password) 
                    VALUES (?, ?, ?)
                ''', (username, email, password))  # Store the password as plain text
                connection.commit()
                flash('Registration successful!', 'success')
                return redirect('/login')
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
            with sqlite3.connect('database.db') as connection:
                cursor = connection.cursor()

                # Check if the user is an admin
                cursor.execute('SELECT * FROM admins WHERE email = ?', (email,))
                admin = cursor.fetchone()

                if admin:
                    print(f'Admin found: {admin}')
                    if admin[2] == password:  # Admin login
                        session['admin_id'] = admin[0]
                        session['admin_username'] = admin[1]
                        flash('Admin login successful!', 'success')
                        return redirect('/admindashboard')
                    else:
                        print('Admin password mismatch')

                # Check if the user is a regular user
                cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
                user = cursor.fetchone()

                if user:
                    print(f'User found: {user}')
                    if user[3] == password:  # User login
                        session['user_id'] = user[0]
                        session['username'] = user[1]
                        flash('Login successful!', 'success')
                        return redirect('/userhome')
                    else:
                        print('User password mismatch')

                print(f'Failed login attempt for email: {email}')
                flash('Invalid email or password!', 'error')

        except Exception as e:
            flash(f'An error occurred: {str(e)}', 'error')

    return render_template('login.html')
# User Home
@app.route('/userhome')
def userhome():
    if 'user_id' in session:
        return render_template('userhome.html', username=session['username'])
    else:
        flash('Please log in to access this page.', 'error')
        return redirect('/login')

# Add Task

    if 'user_id' not in session:
        flash('Please log in to access this page.', 'error')
        return redirect('/login')

    if request.method == 'POST':
        task = request.form['task']
        priority = request.form['priority']

        if not task or not priority.isdigit() or int(priority) not in [1, 2, 3]:
            flash('Invalid task or priority.', 'error')
            return redirect('/add-task')

        try:
            with sqlite3.connect('database.db') as connection:
                cursor = connection.cursor()
                cursor.execute('INSERT INTO tasks (user_id, task, priority) VALUES (?, ?, ?)', 
                               (session['user_id'], task, int(priority)))
                connection.commit()
                flash('Task added successfully!', 'success')
        except Exception:
            flash('An error occurred. Please try again.', 'error')
        return redirect('/view-tasks')

    return render_template('addtask.html')
@app.route('/add-task', methods=['GET', 'POST'])
def add_task():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'error')
        return redirect('/login')

    if request.method == 'POST':
        task = request.form['task']
        priority = request.form['priority']
        category = request.form['category']

        with sqlite3.connect('database.db') as connection:
            cursor = connection.cursor()
            cursor.execute('''
                INSERT INTO tasks (user_id, task, priority, category) 
                VALUES (?, ?, ?, ?)
            ''', (session['user_id'], task, priority, category))
            connection.commit()
        flash('Task added successfully!', 'success')
        return redirect('/view-tasks')

    return render_template('addtask.html')

# View Tasks Route
@app.route('/view-tasks')
def view_tasks():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'error')
        return redirect('/login')

    try:
        with sqlite3.connect('database.db') as connection:
            cursor = connection.cursor()
            cursor.execute('''
                SELECT id, task, priority, category, status 
                FROM tasks 
                WHERE user_id = ? 
                ORDER BY priority ASC
            ''', (session['user_id'],))
            tasks = cursor.fetchall()
    except Exception:
        tasks = []
        flash('An error occurred while retrieving tasks.', 'error')

    return render_template('viewtasks.html', tasks=tasks)

# Mark Task as Done/Undone
@app.route('/mark-task-done/<int:task_id>', methods=['POST'])
def mark_task_done(task_id):
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'error')
        return redirect('/login')

    try:
        with sqlite3.connect('database.db') as connection:
            cursor = connection.cursor()
            cursor.execute('''
                UPDATE tasks
                SET status = CASE WHEN status = 1 THEN 0 ELSE 1 END
                WHERE id = ? AND user_id = ?
            ''', (task_id, session['user_id']))
            connection.commit()
            flash('Task status updated!', 'success')
    except Exception:
        flash('An error occurred while updating task status.', 'error')

    return redirect('/view-tasks')

# Delete Task Route
@app.route('/delete-task/<int:task_id>', methods=['POST'])
def delete_task(task_id):
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'error')
        return redirect('/login')

    try:
        with sqlite3.connect('database.db') as connection:
            cursor = connection.cursor()
            cursor.execute('DELETE FROM tasks WHERE id = ? AND user_id = ?', (task_id, session['user_id']))
            connection.commit()
        flash('Task deleted successfully!', 'success')
    except Exception:
        flash('An error occurred while deleting the task.', 'error')

    return redirect('/view-tasks')


@app.route('/view-report')
def view_report():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'error')
        return redirect('/login')

    try:
        with sqlite3.connect('database.db') as connection:
            cursor = connection.cursor()

            # Fetch total tasks grouped by category
            cursor.execute('''
                SELECT category, COUNT(*) AS total_tasks
                FROM tasks
                WHERE user_id = ?
                GROUP BY category
            ''', (session['user_id'],))
            total_data = cursor.fetchall()

        # Convert data into a dictionary
        total_tasks_dict = {row[0]: row[1] for row in total_data}

        # Prepare data for the pie chart
        categories = list(total_tasks_dict.keys())
        total_tasks = list(total_tasks_dict.values())

        # Handle edge cases for empty data
        if not categories:
            flash('No tasks found for generating the report.', 'info')
            return redirect('/userhome')

    except Exception as e:
        flash(f"An error occurred while fetching data: {str(e)}", 'error')
        return redirect('/userhome')

    try:
        # Generate the chart
        plt.figure(figsize=(6, 6))

        # Total tasks by category (Pie Chart)
        plt.pie(total_tasks, labels=categories, autopct='%1.1f%%', startangle=140, colors=plt.cm.Paired.colors)
        plt.title("Total Tasks by Category")

        # Save the chart to a static file
        chart_path = os.path.join('static', 'report_chart.png')
        plt.savefig(chart_path)
        plt.close()

    except Exception as e:
        flash(f"An error occurred while generating the chart: {str(e)}", 'error')
        return redirect('/userhome')

    # Pass chart URL to the template
    chart_url = f'/{chart_path}'  # Path relative to the static folder
    return render_template('viewreport.html', chart_url=chart_url)


@app.route('/view-priority-report')
def view_priority_report():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'error')
        return redirect('/login')

    # Debugging: Print session data
    print("Session Data:", session)

    # Fetch completed task data
    try:
        with sqlite3.connect('database.db') as connection:
            cursor = connection.cursor()

            # Debugging: Check database schema
            cursor.execute("PRAGMA table_info(tasks)")
            schema_info = cursor.fetchall()
            print("Tasks Table Schema:", schema_info)

            # Fetch completed tasks grouped by category
            cursor.execute('''
                SELECT category, COUNT(*) AS completed_tasks
                FROM tasks
                WHERE user_id = ? AND status = 1
                GROUP BY category
            ''', (session['user_id'],))
            completed_data = cursor.fetchall()

            # Debugging: Log fetched data
            print("Completed Data:", completed_data)

        if not completed_data:
            flash('No completed tasks found for generating the priority report.', 'info')
            return redirect('/userhome')

        # Prepare data for the graph
        completed_tasks_dict = {row[0]: row[1] for row in completed_data}
        categories = list(completed_tasks_dict.keys())
        completed_tasks = list(completed_tasks_dict.values())

    except Exception as e:
        print(f"Error while fetching data: {str(e)}")
        flash(f"An error occurred while fetching data: {str(e)}", 'error')
        return redirect('/userhome')

    # Generate the graph
    try:
        plt.figure(figsize=(8, 6))
        plt.bar(categories, completed_tasks, color='skyblue', edgecolor='black')
        plt.xlabel("Categories")
        plt.ylabel("Completed Tasks")
        plt.title("Priority by Category (Based on Completed Tasks)")
        plt.xticks(rotation=45, ha='right')

        # Save the graph to the static folder
        os.makedirs('static', exist_ok=True)
        graph_path = os.path.join('static', 'priority_report_chart.png')

        # Debugging: Log graph save path
        print("Saving graph to:", graph_path)

        plt.savefig(graph_path)
        plt.close()

    except Exception as e:
        print(f"Graph Generation Error: {str(e)}")
        flash(f"An error occurred while generating the graph: {str(e)}", 'error')
        return redirect('/userhome')

    # Return the generated graph in a template
    graph_url = '/static/priority_report_chart.png'
    return render_template('priorityreport.html', graph_url=graph_url)

@app.route('/view-profile')
def view_profile():
    if 'user_id' not in session:
        flash('Please log in to access your profile.', 'error')
        return redirect('/login')

    try:
        with sqlite3.connect('database.db') as connection:
            cursor = connection.cursor()
            cursor.execute("SELECT username, email FROM users WHERE id = ?", (session['user_id'],))
            user_data = cursor.fetchone()

        if not user_data:
            flash('User not found.', 'error')
            return redirect('/userhome')

        username, email = user_data
        return render_template('viewprofile.html', username=username, email=email)

    except Exception as e:
        print(f"Error fetching profile: {str(e)}")
        flash('An error occurred while fetching your profile.', 'error')
        return redirect('/userhome')


# Route to render the Edit Profile page
@app.route('/edit-profile')
def edit_profile():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'error')
        return redirect('/login')

    return render_template('editprofile.html', username=session.get('username'))


# Route to update the username
@app.route('/edit-username', methods=['POST'])
def edit_username():
    if 'user_id' not in session:
        flash('Please log in to edit your profile.', 'error')
        return redirect('/login')

    new_username = request.form.get('new_username')

    if not new_username:
        flash('Username cannot be empty.', 'error')
        return redirect('/edit-profile')

    try:
        with sqlite3.connect('database.db') as connection:
            cursor = connection.cursor()
            cursor.execute('UPDATE users SET username = ? WHERE id = ?', (new_username, session['user_id']))
            connection.commit()

        session['username'] = new_username  # Update the session with the new username
        flash('Username updated successfully!', 'success')
        return redirect('/view-profile')

    except Exception as e:
        print(f"Error updating username: {str(e)}")
        flash('An error occurred while updating your username.', 'error')
        return redirect('/edit-profile')

# Route for changing password (placeholder)
@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session:
        flash('Please log in to change your password.', 'error')
        return redirect('/login')

    if request.method == 'POST':
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        # Validate the input
        if not old_password or not new_password or not confirm_password:
            flash('All fields are required.', 'error')
            return redirect('/change-password')

        if new_password != confirm_password:
            flash('New password and confirm password do not match.', 'error')
            return redirect('/change-password')

        try:
            # Check if old password matches the current password in the database
            with sqlite3.connect('database.db') as connection:
                cursor = connection.cursor()
                cursor.execute("SELECT password FROM users WHERE id = ?", (session['user_id'],))
                user_data = cursor.fetchone()

            if not user_data or user_data[0] != old_password:
                flash('Incorrect old password.', 'error')
                return redirect('/change-password')

            # Update the password in the database
            cursor.execute("UPDATE users SET password = ? WHERE id = ?", (new_password, session['user_id']))
            connection.commit()

            flash('Password changed successfully!', 'success')
            return redirect('/userhome')

        except Exception as e:
            print(f"Error changing password: {str(e)}")
            flash('An error occurred while changing your password.', 'error')
            return redirect('/change-password')

    return render_template('changepassword.html')  # Render the change password form if GET request


@app.route('/logout', methods=['POST'])  # Add methods=['POST']
def logout():
    # Remove the user from the session
    session.pop('user_id', None)
    session.pop('username', None)
    
    flash('You have been logged out successfully.', 'success')
    
    return redirect('/login')  # Redirect to the login page after logging out

@app.route('/admin-logout', methods=['POST'])
def admin_logout():
    # Remove the admin from the session
    session.pop('admin_id', None)
    session.pop('admin_username', None)
    
    flash('Admin has been logged out successfully.', 'success')
    
    return redirect('/login')  # Redirect to the login page after logging out



@app.route('/admindashboard')
def admindashboard():
    if 'admin_id' not in session:
        flash('Please log in as an admin to access this page.', 'error')
        return redirect('/login')

    return render_template('admindashboard.html', admin_username=session['admin_username'])

@app.route('/view-users')
def view_users():
    try:
        with sqlite3.connect('database.db') as connection:
            cursor = connection.cursor()
            cursor.execute('SELECT username, email FROM users')
            users = cursor.fetchall()
        return render_template('view_users.html', users=users)
    except Exception as e:
        flash(f"An error occurred: {str(e)}", 'error')
        return redirect('/admindashboard')

@app.route('/view-complaints', methods=['GET', 'POST'])
def view_complaints():
    try:
        with sqlite3.connect('database.db') as connection:
            cursor = connection.cursor()

            if request.method == 'POST':
                # Handle admin reply
                complaint_id = request.form['complaint_id']
                reply = request.form['reply']
                cursor.execute(
                    'UPDATE complaints SET reply = ? WHERE id = ?', (reply, complaint_id)
                )
                connection.commit()
                flash('Reply submitted successfully!', 'success')

            # Fetch complaints
            cursor.execute('SELECT id, username, complaint, reply FROM complaints')
            complaints = cursor.fetchall()
        return render_template('view_complaints.html', complaints=complaints)
    except Exception as e:
        flash(f"An error occurred: {str(e)}", 'error')
        return redirect('/admindashboard')

@app.route('/view-feedback')
def view_feedback():
    try:
        with sqlite3.connect('database.db') as connection:
            cursor = connection.cursor()
            cursor.execute('SELECT username, feedback FROM feedback')
            feedbacks = cursor.fetchall()
        return render_template('view_feedback.html', feedbacks=feedbacks)
    except Exception as e:
        flash(f"An error occurred: {str(e)}", 'error')
        return redirect('/admindashboard')


    
@app.route('/complaints', methods=['GET', 'POST'])
def complaints():
    username = session.get('username')  # Assuming you're storing the username in the session

    if request.method == 'POST':
        complaint = request.form['complaint']
        
        # Store the complaint in the database
        try:
            with sqlite3.connect('database.db') as connection:
                cursor = connection.cursor()
                cursor.execute('''
                    INSERT INTO complaints (username, complaint) 
                    VALUES (?, ?)
                ''', (username, complaint))
                connection.commit()
                flash('Complaint submitted successfully!', 'success')
        except Exception as e:
            flash(f'An error occurred: {str(e)}', 'error')

    # Retrieve all previous complaints for the current user
    with sqlite3.connect('database.db') as connection:
        cursor = connection.cursor()
        cursor.execute('SELECT * FROM complaints WHERE username = ?', (username,))
        complaints = cursor.fetchall()

    return render_template('complaints.html', complaints=complaints)

@app.route('/feedbacks', methods=['GET', 'POST'])
def feedbacks():
    username = session.get('username')  # Assuming you're storing the username in the session

    if request.method == 'POST':
        feedback = request.form['feedback']
        
        # Store the feedback in the database
        try:
            with sqlite3.connect('database.db') as connection:
                cursor = connection.cursor()
                cursor.execute('''
                    INSERT INTO feedback (username, feedback) 
                    VALUES (?, ?)
                ''', (username, feedback))
                connection.commit()
                flash('Feedback submitted successfully!', 'success')
        except Exception as e:
            flash(f'An error occurred: {str(e)}', 'error')

    return render_template('feedbacks.html')



if __name__ == '__main__':
    app.run(debug=True)