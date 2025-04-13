from flask import Flask, request, jsonify, render_template, send_from_directory, url_for
from flask_jwt_extended import JWTManager, jwt_required, create_access_token
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from sqlalchemy import create_engine
import pandas as pd
from config import SQL_SERVER_CONFIG, MYSQL_CONFIG, JWT_SECRET_KEY, JWT_ACCESS_TOKEN_EXPIRES, API_PREFIX, SQL_SERVER_CONN, MYSQL_CONN
from datetime import datetime
import pyodbc
import mysql.connector
import os
import traceback

app = Flask(__name__, 
            static_folder='DASHBOAR',
            template_folder='templates')
app.config['JWT_SECRET_KEY'] = JWT_SECRET_KEY
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = JWT_ACCESS_TOKEN_EXPIRES
CORS(app)  # Enable CORS for all routes
jwt = JWTManager(app)

# Serve static files
@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory(app.static_folder, filename)

@app.route('/css/<path:filename>')
def serve_css(filename):
    return send_from_directory(os.path.join(app.static_folder, 'css'), filename)

@app.route('/js/<path:filename>')
def serve_js(filename):
    return send_from_directory(os.path.join(app.static_folder, 'js'), filename)

@app.route('/images/<path:filename>')
def serve_images(filename):
    return send_from_directory(os.path.join(app.static_folder, 'images'), filename)

@app.route('/icons/<path:filename>')
def serve_icons(filename):
    return send_from_directory(os.path.join(app.static_folder, 'icons'), filename)

@app.route('/vendor/<path:filename>')
def serve_vendor(filename):
    return send_from_directory(os.path.join(app.static_folder, 'vendor'), filename)

# Frontend Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/all-employees')
def all_employees():
    # Mock data for testing
    employees = [
        {
            'id': 1,
            'name': 'John Doe',
            'gender': 'Male',
            'position': 'Manager',
            'group': 'IT',
            'date': '2023-01-01',
            'image_url': url_for('serve_images', filename='profile/education/pic1.jpg')
        },
        {
            'id': 2,
            'name': 'Jane Smith',
            'gender': 'Female',
            'position': 'Developer',
            'group': 'IT',
            'date': '2023-02-01',
            'image_url': url_for('serve_images', filename='profile/education/pic2.jpg')
        }
    ]
    return render_template('all-employees.html', employees=employees)

@app.route('/add-employee')
def add_employee():
    # Mock data for testing
    departments = [
        {'id': 1, 'name': 'IT'},
        {'id': 2, 'name': 'HR'},
        {'id': 3, 'name': 'Finance'}
    ]
    
    positions = [
        {'id': 1, 'name': 'Manager'},
        {'id': 2, 'name': 'Developer'},
        {'id': 3, 'name': 'Designer'}
    ]
    
    return render_template('add-employee.html', departments=departments, positions=positions)

@app.route('/edit-employee')
def edit_employee():
    return render_template('edit-employee.html')

@app.route('/employee-profile')
def employee_profile():
    return render_template('employee-profile.html')

@app.route('/payroll-details')
@app.route('/payroll-details.html')
def payroll_details():
    return render_template('payroll-details.html')

@app.route('/salary-history')
@app.route('/salary-history.html')
def salary_history():
    return render_template('salary-history.html')

@app.route('/attendance-records')
@app.route('/attendance-records.html')
def attendance_records():
    # Mock data for testing
    attendance_records = [
        {
            'employee_id': '001',
            'name': 'John Doe',
            'date': '2024-04-06',
            'check_in': '09:00',
            'check_out': '17:00',
            'status': 'Present'
        },
        {
            'employee_id': '002',
            'name': 'Jane Smith',
            'date': '2024-04-06',
            'check_in': '08:45',
            'check_out': '16:30',
            'status': 'Present'
        }
    ]
    return render_template('attendance-records.html', attendance_records=attendance_records)

@app.route('/all-departments')
def all_departments():
    return render_template('all-departments.html')

@app.route('/all-job-titles')
def all_job_titles():
    return render_template('all-job-titles.html')

@app.route('/manage-departments')
def manage_departments():
    return render_template('manage-departments.html')

@app.route('/manage-job-titles')
def manage_job_titles():
    return render_template('manage-job-titles.html')

@app.route('/employee-summary')
def employee_summary():
    return render_template('employee-summary.html')

@app.route('/payroll-report')
def payroll_report():
    return render_template('payroll-report.html')

@app.route('/dividend-report')
def dividend_report():
    return render_template('dividend-report.html')

@app.route('/comparative-charts')
def comparative_charts():
    return render_template('comparative-charts.html')

@app.route('/work-anniversary')
@app.route('/work-anniversary.html')
def work_anniversary():
    # Mock data for testing
    anniversaries = [
        {
            'employee_id': '001',
            'name': 'John Doe',
            'position': 'Manager',
            'department': 'IT',
            'join_date': '2020-04-06',
            'years': 4,
            'image_url': url_for('serve_images', filename='profile/education/pic1.jpg')
        },
        {
            'employee_id': '002', 
            'name': 'Jane Smith',
            'position': 'Developer',
            'department': 'IT',
            'join_date': '2021-04-06',
            'years': 3,
            'image_url': url_for('serve_images', filename='profile/education/pic2.jpg')
        }
    ]
    return render_template('work-anniversary.html', anniversaries=anniversaries)

@app.route('/leave-alerts')
def leave_alerts():
    return render_template('leave-alerts.html')

@app.route('/payroll-alerts')
def payroll_alerts():
    return render_template('payroll-alerts.html')

@app.route('/salary-statements')
def salary_statements():
    return render_template('salary-statements.html')

@app.route('/user-roles')
def user_roles():
    return render_template('user-roles.html')

@app.route('/permissions')
def permissions():
    return render_template('permissions.html')

@app.route('/access-logs')
def access_logs():
    return render_template('access-logs.html')

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/login')
@app.route('/page-login.html')
def login():
    return render_template('login.html')

# Database connection functions
def get_sql_server_connection():
    return create_engine(SQL_SERVER_CONN)

def get_mysql_connection():
    return create_engine(MYSQL_CONN)

# Authentication endpoint
@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Missing username or password'}), 400

    try:
        engine = get_sql_server_connection()
        query = "SELECT PasswordHash FROM Users WHERE Username = ?"
        with engine.connect() as conn:
            result = conn.execute(query, (username,)).fetchone()
        
        if result and check_password_hash(result[0], password):
            access_token = create_access_token(identity=username)
            return jsonify({'access_token': access_token})
        else:
            return jsonify({'message': 'Invalid credentials'}), 401
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    localStorage.setItem('access_token', data.access_token);

# Employee endpoints
@app.route('/api/employees', methods=['GET'])
@jwt_required()
def get_employees():
    try:
        engine = get_sql_server_connection()
        query = "SELECT * FROM Employees"
        df = pd.read_sql(query, engine)
        return jsonify(df.to_dict(orient='records'))
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/payroll', methods=['GET'])
@jwt_required()
def get_payroll():
    try:
        engine = get_mysql_connection()
        query = "SELECT * FROM salaries"
        df = pd.read_sql(query, engine)
        return jsonify(df.to_dict(orient='records'))
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/add-employee', methods=['POST'])
@jwt_required()
def api_add_employee():
    try:
        data = request.get_json()
        print("🔎 Dữ liệu nhận được:", data)  # <--- THÊM DÒNG NÀY
        # Add to SQL Server
        engine_sql = get_sql_server_connection()
        query_sql = """
            INSERT INTO Employees (FullName, DateOfBirth, Gender, PhoneNumber, Email, 
                                 HireDate, DepartmentID, PositionID, Status, CreatedAt, UpdatedAt)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, GETDATE(), GETDATE())
        """
        with engine_sql.connect() as conn:
            result = conn.execute(query_sql, (
                data['FullName'], data['DateOfBirth'], data['Gender'], data['PhoneNumber'],
                data['Email'], data['HireDate'], data['DepartmentID'], data['PositionID'],
                data['Status']
            ))
            employee_id = conn.execute("SELECT SCOPE_IDENTITY()").scalar()
        
        # Add to MySQL payroll
        engine_mysql = get_mysql_connection()
        query_mysql = """
            INSERT INTO employees (EmployeeID, FullName, DepartmentID, PositionID, Status,Email,DateOfBirth,HireDate,Gender,PhoneNumber)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        with engine_mysql.connect() as conn:
            conn.execute(query_mysql, (
                employee_id, data['FullName'], data['DepartmentID'], 
                data['PositionID'], data['Status'], data['Email'],
                data['DateOfBirth'], data['HireDate'], data['Gender'],
                data['PhoneNumber']
            ))
        
        return jsonify({'message': 'Employee added successfully', 'employee_id': employee_id}), 201
        
    except Exception as e:
        traceback.print_exc()  # log lỗi đầy đủ ra console
        return jsonify({'error': str(e)}), 500

@app.route('/api/update-employee/<int:employee_id>', methods=['PUT'])
@jwt_required()
def update_employee(employee_id):
    try:
        data = request.get_json()
        
        # Update in SQL Server
        engine_sql = get_sql_server_connection()
        query_sql = """
            UPDATE Employees 
            SET FullName = ?, DateOfBirth = ?, Gender = ?, PhoneNumber = ?,
                Email = ?, DepartmentID = ?, PositionID = ?, Status  = ?,
                UpdatedAt = GETDATE()
            WHERE EmployeeID = ?
        """
        with engine_sql.connect() as conn:
            conn.execute(query_sql, (
                data['FullName'], data['DateOfBirth'], data['Gender'], data['PhoneNumber'],
                data['Email'], data['DepartmentID'], data['PositionID'], data['Status'],
                employee_id
            ))
        
        # Update in MySQL payroll
        engine_mysql = get_mysql_connection()
        query_mysql = """
            UPDATE employees 
            SET FullName = %s, DepartmentID = %s, PositionID = %s, Status = %s
            WHERE EmployeeID = %s
         """
        with engine_mysql.connect() as conn:
            conn.execute(query_mysql, (
                data['FullName'], data['DepartmentID'], data['PositionID'],
                data['Status'], employee_id
            ))
        
        return jsonify({'message': 'Employee updated successfully'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/delete-employee/<int:employee_id>', methods=['DELETE'])
@jwt_required()
def delete_employee(employee_id):
    try:
        # Delete from SQL Server
        engine_sql = get_sql_server_connection()
        with engine_sql.connect() as conn:
            conn.execute("DELETE FROM Employees WHERE EmployeeID = ?", (employee_id,))

        
        # Delete from MySQL payroll
        engine_mysql = get_mysql_connection()
        with engine_mysql.connect() as conn:
            conn.execute("DELETE FROM employees WHERE EmployeeID = %s", (employee_id,))
        
        return jsonify({'message': 'Employee deleted successfully'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Attendance endpoints
@app.route('/api/attendance', methods=['GET'])
@jwt_required()
def get_attendance():
    try:
        engine = get_sql_server_connection()
        query = """
            SELECT a.AttendanceID, e.EmployeeID, e.FullName, 
                   FORMAT(a.Date, 'yyyy-MM-dd') as Date,
                   FORMAT(a.CheckIn, 'HH:mm') as CheckIn,
                   FORMAT(a.CheckOut, 'HH:mm') as CheckOut,
                   a.Status
            FROM Attendance a
            JOIN Employees e ON a.EmployeeID = e.EmployeeID
            ORDER BY a.Date DESC, e.FullName
        """
        df = pd.read_sql(query, engine)
        return jsonify(df.to_dict(orient='records'))
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/attendance/check-in', methods=['POST'])
@jwt_required()
def check_in():
    try:
        data = request.get_json()
        employee_id = data.get('employee_id')
        
        engine = get_sql_server_connection()
        query = """
            INSERT INTO Attendance (EmployeeID, Date, CheckIn, Status)
            VALUES (?, GETDATE(), GETDATE(), 'Present')
        """
        with engine.connect() as conn:
            conn.execute(query, (employee_id,))

        
        return jsonify({'message': 'Check-in successful'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/attendance/check-out/<int:employee_id>', methods=['PUT'])
@jwt_required()
def check_out(employee_id):
    try:
        engine = get_sql_server_connection()
        query = """
            UPDATE Attendance 
            SET CheckOut = GETDATE()
            WHERE EmployeeID = ? AND Date = CAST(GETDATE() AS DATE)
            AND CheckOut IS NULL
        """
        with engine.connect() as conn:
            conn.execute(query, (employee_id,))

        
        return jsonify({'message': 'Check-out successful'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Missing username or password'}), 400

    try:
        engine = get_sql_server_connection()
        hashed_password = generate_password_hash(password)
        query = "INSERT INTO Users (Username, PasswordHash) VALUES (?, ?)"
        with engine.connect() as conn:
            conn.execute(query, (username, hashed_password))
        return jsonify({'message': 'User registered successfully'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500
@app.route('/api/user-info', methods=['GET'])
@jwt_required()
def user_info():
    current_user = get_jwt_identity()
    return jsonify({'logged_in_as': current_user})

@app.route('/check-attendance')
def check_attendance():
    return render_template('check-attendance.html')

if __name__ == '__main__':
    app.run(debug=True) 