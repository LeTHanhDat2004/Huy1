from flask import Flask, request, jsonify, render_template, send_from_directory, url_for, redirect
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token, 
    get_jwt_identity, verify_jwt_in_request, get_jwt
)
import logging
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from sqlalchemy import create_engine
import pymysql
import pandas as pd
from config import SQL_SERVER_CONFIG, MYSQL_CONFIG, JWT_SECRET_KEY, JWT_ACCESS_TOKEN_EXPIRES, API_PREFIX, SQL_SERVER_CONN, MYSQL_CONN
from datetime import datetime, timedelta
import pyodbc
import mysql.connector
import os
import traceback
from functools import wraps
from flask_wtf.csrf import CSRFProtect

def role_required(allowed_roles):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt()
            if claims.get('role') in allowed_roles:
                return fn(*args, **kwargs)
            return jsonify({'message': 'Permission denied'}), 403
        return wrapper
    return decorator

app = Flask(__name__, 
            static_folder='static',  # Thay đổi này
            template_folder='templates')
app.config['JWT_SECRET_KEY'] = JWT_SECRET_KEY
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = JWT_ACCESS_TOKEN_EXPIRES
app.secret_key = 'your-very-secret-key'
CORS(app)  # Enable CORS for all routes
jwt = JWTManager(app)
csrf = CSRFProtect(app)  # Thêm dòng này để khởi tạo CSRF protection

db = pymysql.connect(
    host='localhost',
    user='root',
    password="Tritran0932523321@",
    database="sqlnewbie",
    cursorclass=pymysql.cursors.DictCursor
)
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
    with db.cursor() as cursor:
        cursor.execute("SELECT EmployeeID, Fullname, DepartmentID, positionID, status FROM employees")
        employees = cursor.fetchall()
    return render_template('all-employees.html', employees=employees)

@app.route('/add-employee', methods=['GET', 'POST'])
def add_employee():
    # Xử lý dữ liệu từ form và thêm vào database nếu là POST request
    if request.method == 'POST':
        fullname = request.form.get('FullName')
        department_id = request.form.get('DepartmentID')
        position_id = request.form.get('PositionID')
        status = request.form.get('Status')
        with db.cursor() as cursor:
            cursor.execute("""
                INSERT INTO employees (FullName, DepartmentID, PositionID, Status)
                VALUES (%s, %s, %s, %s)
            """, (fullname, department_id, position_id, status))
            db.commit()
        return redirect(url_for('all_employees'))

    # GET: Lấy danh sách phòng ban và chức vụ cho form
    with db.cursor() as cursor:
        cursor.execute("SELECT DepartmentID, DepartmentName FROM departments")
        departments = cursor.fetchall()
        cursor.execute("SELECT PositionID, PositionName FROM positions")
        positions = cursor.fetchall()
    return render_template('add-employee.html', departments=departments, positions=positions)

@app.route('/edit-employee', defaults={'employee_id': None})
@app.route('/edit-employee/<int:employee_id>')
def edit_employee(employee_id):
    if employee_id is None:
        # Nếu không có ID, chuyển hướng đến trang danh sách nhân viên
        return redirect(url_for('all_employees'))
    try:
        with db.cursor() as cursor:
            # Lấy thông tin nhân viên theo ID
            cursor.execute("""
                SELECT e.*, d.DepartmentName, p.PositionName 
                FROM employees e
                LEFT JOIN departments d ON e.DepartmentID = d.DepartmentID
                LEFT JOIN positions p ON e.PositionID = p.PositionID
                WHERE e.EmployeeID = %s
            """, (employee_id,))
            emp = cursor.fetchone()

            # Lấy danh sách phòng ban
            cursor.execute("SELECT DepartmentID, DepartmentName FROM departments")
            departments = cursor.fetchall()

            # Lấy danh sách chức vụ
            cursor.execute("SELECT PositionID, PositionName FROM positions")
            positions = cursor.fetchall()

            if not emp:
                emp = {
                    'EmployeeID': 0,
                    'FullName': 'Không tìm thấy',
                    'DepartmentID': 0,
                    'PositionID': 0,
                    'Status': 'Không tìm thấy',
                    'DateOfBirth': '',
                    'Gender': '',
                    'HireDate': ''
                }

        return render_template('edit-employee.html', emp=emp, departments=departments, positions=positions)
    except Exception as e:
        print(f"Lỗi khi lấy thông tin nhân viên: {str(e)}")
        emp = {
            'EmployeeID': 0,
            'FullName': 'Lỗi khi tải dữ liệu',
            'DepartmentID': 0,
            'PositionID': 0,
            'Status': 'Lỗi khi tải dữ liệu',
            'DateOfBirth': '',
            'Gender': '',
            'HireDate': ''
        }
        return render_template('edit-employee.html', emp=emp, departments=[], positions=[])

@app.route('/employee-profile')
def employee_profile():
    try:
        with db.cursor() as cursor:
            # Lấy thông tin nhân viên đầu tiên để demo
            cursor.execute("""
                SELECT e.*, d.DepartmentName, p.PositionName 
                FROM employees e
                LEFT JOIN departments d ON e.DepartmentID = d.DepartmentID
                LEFT JOIN positions p ON e.PositionID = p.PositionID
                LIMIT 1
            """)
            emp = cursor.fetchone()
            
            if not emp:
                # Nếu không tìm thấy nhân viên nào, tạo dữ liệu mẫu
                emp = {
                    'EmployeeID': 0,
                    'FullName': 'Chưa có dữ liệu',
                    'DepartmentName': 'Chưa có dữ liệu',
                    'PositionName': 'Chưa có dữ liệu',
                    'Status': 'Chưa có dữ liệu',
                    'DateOfBirth': 'Chưa có dữ liệu',
                    'Gender': 'Chưa có dữ liệu'
                }
            
        return render_template('employee-profile.html', emp=emp)
    except Exception as e:
        print(f"Lỗi khi lấy thông tin nhân viên: {str(e)}")
        # Trả về template với dữ liệu mẫu nếu có lỗi
        emp = {
            'EmployeeID': 0,
            'FullName': 'Lỗi khi tải dữ liệu',
            'DepartmentName': 'Lỗi khi tải dữ liệu',
            'PositionName': 'Lỗi khi tải dữ liệu',
            'Status': 'Lỗi khi tải dữ liệu',
            'DateOfBirth': 'Lỗi khi tải dữ liệu',
            'Gender': 'Lỗi khi tải dữ liệu'
        }
        return render_template('employee-profile.html', emp=emp)

@app.route('/payroll-details')
@app.route('/payroll-details.html')
def payroll_details():
    with db.cursor() as cursor:
        cursor.execute("""
            SELECT EmployeeID as employee_id,
                   Fullname as employee_name,
                   0 as base_salary,
                   0 as bonus,
                   0 as deductions,
                   0 as net_salary,
                   'Bank Transfer' as payment_type,
                   'Pending' as status,
                   CURRENT_TIMESTAMP as payment_date
            FROM employees
        """)
        payrolls = cursor.fetchall()
    return render_template('payroll-details.html', payrolls=payrolls)

@app.route('/salary-history')
def salary_history():
    with db.cursor() as cursor:
        cursor.execute("SELECT * FROM salaries")
        salaries = cursor.fetchall()
    print(salaries)  # In ra dữ liệu để kiểm tra
    return render_template('salary-history.html', salaries=salaries)

@app.route('/attendance-records')
def attendance_records():
    with db.cursor() as cursor:
        cursor.execute("SELECT * FROM attendance")
        attendance_records = cursor.fetchall()
    print(attendance_records)  # Kiểm tra dữ liệu trả về
    return render_template('attendance-records.html', attendance_records=attendance_records)


@app.route('/all-departments')
def all_departments():
    with db.cursor() as cursor:
        cursor.execute("SELECT * FROM departments")
        departments = cursor.fetchall()
    print(departments)  # Kiểm tra dữ liệu trả về
    return render_template('all-departments.html', departments=departments)

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

@app.route('/page-register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            data = request.get_json()
            username = data.get('username')
            fullname = data.get('fullname')
            email = data.get('email')
            password = data.get('password')
            
            with db.cursor() as cursor:
                # Chỉ kiểm tra username trùng
                cursor.execute('SELECT * FROM user_employee WHERE username = %s', (username,))
                if cursor.fetchone():
                    return jsonify({'message': 'Tên đăng nhập đã tồn tại'}), 400
                
                # Thêm user mới
                hashed_password = generate_password_hash(password)
                cursor.execute(
                    'INSERT INTO user_employee (username, fullname, email, password, role) VALUES (%s, %s, %s, %s, %s)',
                    (username, fullname, email, hashed_password, 'employee')
                )
                db.commit()
                
                return jsonify({'message': 'Đăng ký thành công'}), 201
                
        except Exception as e:
            db.rollback()
            return jsonify({'message': 'Có lỗi xảy ra, vui lòng thử lại sau'}), 500
            
    return render_template('page-register.html')

@app.route('/page-login.html', methods=['GET', 'POST'])
# Xóa tất cả các route login cũ

# Thêm route mới này
@app.route('/page-login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        with db.cursor() as cursor:
            cursor.execute('SELECT * FROM user_employee WHERE username = %s', (username,))
            user = cursor.fetchone()
            
            if user and check_password_hash(user['password'], password):
                access_token = create_access_token(identity=username)
                return jsonify({
                    'access_token': access_token,
                    'role': user['role']
                }), 200
            return jsonify({'message': 'Sai tên đăng nhập hoặc mật khẩu'}), 401
    return render_template('page-login.html')

# Thêm route redirect cho page-login.html





@app.route('/edit-payroll/<int:employee_id>')
def edit_payroll(employee_id):
    with db.cursor() as cursor:
        cursor.execute("""
            SELECT EmployeeID as employee_id,
                   Fullname as employee_name,
                   0 as base_salary,
                   0 as bonus,
                   0 as deductions,
                   0 as net_salary,
                   'Bank Transfer' as payment_type,
                   'Pending' as status,
                   CURRENT_TIMESTAMP as payment_date
            FROM employees
            WHERE EmployeeID = %s
        """, (employee_id,))
        payroll = cursor.fetchone()
        
        if not payroll:
            payroll = {
                'employee_id': 0,
                'employee_name': 'Không tìm thấy',
                'base_salary': 0,
                'bonus': 0,
                'deductions': 0,
                'net_salary': 0,
                'payment_type': '',
                'status': 'Không tìm thấy',
                'payment_date': ''
            }
            
    return render_template('edit-payroll.html', payroll=payroll)

@app.route('/delete-payroll/<int:EmployeeID>')
def delete_payroll(EmployeeID):
    # Xử lý xóa payroll ở đây
    # ...
    return redirect(url_for('payroll_details'))  # hoặc trang phù hợp

# Database connection functions
def get_sql_server_connection():
    return create_engine(SQL_SERVER_CONN)

def get_mysql_connection():
    return create_engine(MYSQL_CONN)

# Authentication endpoint
@app.route('/api/page-login', methods=['POST'])
def api_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Thiếu username hoặc password'}), 400

    # Kiểm tra trong bảng admin
    with db.cursor() as cursor:
        cursor.execute("SELECT * FROM admin WHERE user=%s", (username,))
        admin = cursor.fetchone()
        if admin and check_password_hash(admin['pass'], password):
            token = create_access_token(identity=admin['id'], additional_claims={'role': ROLE_ADMIN})
            return jsonify({
                'access_token': token,
                'role': ROLE_ADMIN,
                'username': username
            })

    # Kiểm tra trong bảng user_employee
    with db.cursor() as cursor:
        cursor.execute("SELECT * FROM user_employee WHERE user=%s", (username,))
        user = cursor.fetchone()
        if user and check_password_hash(user['pass'], password):
            token = create_access_token(identity=user['id'], additional_claims={'role': ROLE_EMPLOYEE})
            return jsonify({
                'access_token': token,
                'role': ROLE_EMPLOYEE,
                'username': username
            })

    with db.cursor() as cursor:
        cursor.execute("""
            SELECT u.*, r.role_name 
            FROM users u
            JOIN roles r ON u.role_id = r.role_id
            WHERE u.username = %s
        """, (username,))
        user = cursor.fetchone()
        
        if user and check_password_hash(user['password_hash'], password):
            token = create_access_token(
                identity=user['user_id'],
                additional_claims={'role': user['role_name']}
            )
            return jsonify({
                'access_token': token,
                'role': user['role_name'],
                'username': username
            })

    return jsonify({'message': 'Thông tin đăng nhập không hợp lệ'}), 401

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

# API cho cả admin và employee truy cập
@app.route('/api/employee-profile/<int:id>', methods=['GET'])
@role_required(['admin', 'employee'])
def get_employee_profile(id):
    try:
        # Logic lấy thông tin profile
        return jsonify({'message': 'Success'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/add-employee', methods=['POST'])
@jwt_required()
@role_required(['admin', 'hr'])  # Chỉ admin và HR mới có quyền thêm nhân viên
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
            INSERT INTO employees (EmployeeID, FullName, DepartmentID, PositionID, Status)
            VALUES (%s, %s, %s, %s, %s)
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
@role_required(['admin', 'hr'])  # Chỉ admin và HR mới có quyền cập nhật nhân viên
def api_update_employee(employee_id):
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

@app.route('/check-attendance')
def check_attendance():
    return render_template('check-attendance.html')

@app.route('/update_employee', methods=['POST'])
def update_employee():
    try:
        employee_id = request.form.get('EmployeeID')
        fullname = request.form.get('FullName')
        department_id = request.form.get('DepartmentID')
        position_id = request.form.get('PositionID')
        status = request.form.get('Status')

        with db.cursor() as cursor:
            cursor.execute("""
                UPDATE employees
                SET FullName=%s, DepartmentID=%s, PositionID=%s, Status=%s
                WHERE EmployeeID=%s
            """, (fullname, department_id, position_id, status, employee_id))
            db.commit()
        # Sau khi cập nhật thành công, chuyển về trang danh sách nhân viên
        return redirect(url_for('all_employees'))
    except Exception as e:
        print("Lỗi khi cập nhật nhân viên:", e)
        return "Có lỗi xảy ra khi cập nhật nhân viên!"



# Thêm SECRET_KEY vào config
app.config['SECRET_KEY'] = 'Tritran'

def generate_token(user_id, role):
    token = jwt.encode({
        'user_id': user_id,
        'role': role,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }, app.config['SECRET_KEY'])
    return token
@app.route('/api/user-info', methods=['GET'])
@jwt_required()
def user_info():
    current_user = get_jwt_identity()
    return jsonify({'logged_in_as': current_user})





# Thêm các hằng số cho roles
ROLE_ADMIN = 'admin'
ROLE_HR = 'hr_manager'
ROLE_EMPLOYEE = 'employee'
ROLE_PAYROLL = 'payroll_manager'

# Cập nhật cấu hình JWT
app.config['JWT_SECRET_KEY'] = 'your-super-secret-key'  # Thay đổi key này
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)



# Áp dụng phân quyền cho các API
@app.route('/api/employees', methods=['GET'])
@jwt_required()
@role_required([ROLE_ADMIN, ROLE_HR])
def get_employees_v2():
    try:
        engine = get_sql_server_connection()
        query = "SELECT * FROM Employees"
        df = pd.read_sql(query, engine)
        return jsonify(df.to_dict(orient='records'))
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/payroll', methods=['GET'])
@jwt_required()
@role_required([ROLE_ADMIN, ROLE_PAYROLL])
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
@role_required(['admin', 'hr'])  # Chỉ admin và HR mới có quyền thêm nhân viên
def api_add_employee_v2():
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
            INSERT INTO employees (EmployeeID, FullName, DepartmentID, PositionID, Status)
            VALUES (%s, %s, %s, %s, %s)
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
def get_user_info():
    current_user = get_jwt_identity()
    return jsonify({'logged_in_as': current_user})



@app.route('/delete-employee/<int:employee_id>', methods=['POST'])
def delete_employee(employee_id):
    try:
        with db.cursor() as cursor:
            cursor.execute("DELETE FROM employees WHERE EmployeeID = %s", (employee_id,))
            db.commit()
        return redirect(url_for('all_employees'))
    except Exception as e:
        traceback.print_exc()
        return "Có lỗi xảy ra khi xóa nhân viên!"

if __name__ == '__main__':
    app.run(debug=True)
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect()
csrf.init_app(app)
@app.before_request
def before_request():
    if 'user' in session:
        session.permanent = True
        app.permanent_session_lifetime = timedelta(minutes=30)

csrf = CSRFProtect()
csrf.init_app(app)
csrf.init_app(app)

