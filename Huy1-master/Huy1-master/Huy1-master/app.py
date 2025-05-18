from flask import Flask, request, jsonify, render_template, send_from_directory, url_for, redirect,flash,session
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

# Thêm các hằng số cho roles
ROLE_ADMIN = 'admin'
ROLE_HR = 'hr_manager'
ROLE_EMPLOYEE = 'employee'
ROLE_PAYROLL = 'payroll_manager'

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
            static_folder='static',
            template_folder='templates')
app.config['JWT_SECRET_KEY'] = JWT_SECRET_KEY
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = JWT_ACCESS_TOKEN_EXPIRES
app.secret_key = 'app1'
app.config['JWT_SECRET_KEY'] = 'Tritran'
CORS(app, resources={
    r"/*": {
        "origins": ["http://localhost:5000", "http://127.0.0.1:5000"],  # Chỉ định rõ origins
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization", "X-CSRFToken"],
        "supports_credentials": True  # Quan trọng cho việc gửi cookies
    }
})  # Enable CORS for all routes
app.secret_key = 'your-very-secret-key'
# Thay đổi cấu hình CORS
CORS(app, resources={
    r"/*": {
        "origins": ["http://localhost:5000", "http://127.0.0.1:5000"],  # Chỉ định rõ origins
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization", "X-CSRFToken"],
        "supports_credentials": True  # Quan trọng cho việc gửi cookies
    }
})  # Enable CORS for all routes
jwt = JWTManager(app)
csrf = CSRFProtect(app)  # Thêm dòng này để khởi tạo CSRF protection
# Custom JWT error handlers
@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({
        'status': 401,
        'sub_status': 'token_expired',
        'msg': 'Token has expired'
    }), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({
        'status': 401,
        'sub_status': 'invalid_token',
        'msg': 'Invalid token: ' + str(error)
    }), 401

@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({
        'status': 401,
        'sub_status': 'missing_token',
        'msg': 'Missing token: ' + str(error)
    }), 401

# Middleware để xử lý token từ query params và form
@app.before_request
def handle_auth_token():
    # Nếu có token trong query params, thêm vào header
    auth_token = request.args.get('auth_token')
    if auth_token and 'Authorization' not in request.headers:
        # Flask không cho phép sửa request.headers trực tiếp
        # Nhưng chúng ta có thể sửa environ
        request.environ['HTTP_AUTHORIZATION'] = f'Bearer {auth_token}'
        
        # Đối với các request đến dashboard, sau khi xử lý token từ query params,
        # chuyển hướng đến URL không có query params để tránh double request
        if request.path == '/dashboard' and len(request.args) > 0:
            # Chỉ chuyển hướng nếu có query parameters
            app.logger.debug('Redirecting dashboard request to clean URL')
            return redirect('/dashboard')
    
    # Ghi log chi tiết request để debug
    app.logger.debug('Request URL: %s', request.url)
    app.logger.debug('Request method: %s', request.method)
    app.logger.debug('Authorization header: %s', request.headers.get('Authorization', 'None'))
    
    # Kiểm tra double request
    if request.path == '/dashboard':
        app.logger.debug('Dashboard request detected')

# Add token debug route
@app.route('/debug/token')
def debug_token():
    auth_header = request.headers.get('Authorization', '')
    token = None
    if auth_header.startswith('Bearer '):
        token = auth_header[7:]  # Remove 'Bearer ' prefix
    
    return jsonify({
        'has_auth_header': bool(auth_header),
        'auth_header': auth_header[:10] + '...' if auth_header else None,
        'token_extracted': bool(token),
        'token_preview': token[:10] + '...' if token else None,
        'query_params': dict(request.args),
        'form_data': dict(request.form),
        'request_path': request.path,
        'request_method': request.method
    })
db = pymysql.connect(
    host='localhost',
    user='root',
    password="Thach4102004!",
    database="payroll_baitap",
    cursorclass=pymysql.cursors.DictCursor,
    connect_timeout=60,
    read_timeout=30,
    write_timeout=30
)


def get_db_connection():
    try:
        connection = pymysql.connect(
            host='127.0.0.1',  # Thay localhost bằng IP cụ thể
            user='root',
            password="Tritran0932523321@",
            database="sqlnewbie",
            cursorclass=pymysql.cursors.DictCursor,
            connect_timeout=60,
            read_timeout=30,
            write_timeout=30
        )
        return connection
    except Exception as e:
        app.logger.error(f"Database connection error: {str(e)}")
        raise
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
@jwt_required()
def index():
    return render_template('index.html')
@app.route('/dashboard')
@jwt_required()
def dashboard():
    try:
        # Lấy thông tin role từ JWT token
        claims = get_jwt()
        current_role = claims.get('role', 'employee')  # Mặc định là employee nếu không có role
        
        # Lấy dữ liệu chung cho tất cả các role
        common_data = {
            'user_info': get_jwt_identity(),
            'current_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # Log thông tin token để debug
        app.logger.debug(f'Dashboard access - User: {get_jwt_identity()}, Role: {current_role}')
        
        if current_role == 'admin':
            # Admin sẽ thấy tất cả dữ liệu
            try:
                db = get_db_connection()
                with db.cursor() as cursor:
                    # Lấy danh sách nhân viên
                    cursor.execute("SELECT * FROM employees")
                    employees = cursor.fetchall()
                    
                    # Lấy thông tin phòng ban
                    cursor.execute("SELECT * FROM departments")
                    departments = cursor.fetchall()
                    
                    # Lấy thông tin lương
                    cursor.execute("SELECT * FROM salaries")
                    salaries = cursor.fetchall()
                    
                    return render_template('index.html',
                        role='admin',
                        employees=employees,
                        departments=departments,
                        salaries=salaries,
                        **common_data
                    )
            except Exception as db_error:
                app.logger.error(f'Database error in dashboard: {str(db_error)}')
                return jsonify({'message': 'Lỗi cơ sở dữ liệu'}), 500
            finally:
                if 'db' in locals():
                    db.close()
        else:
            # Employee chỉ thấy thông tin của mình
            try:
                db = get_db_connection()
                with db.cursor() as cursor:
                    # Lấy thông tin nhân viên hiện tại
                    username = get_jwt_identity()
                    cursor.execute("SELECT * FROM employees WHERE user = %s", (username,))
                    employee = cursor.fetchone()
                    
                    # Lấy thông tin phòng ban của nhân viên
                    if employee:
                        cursor.execute("SELECT * FROM departments WHERE DepartmentID = %s", 
                                     (employee['DepartmentID'],))
                        department = cursor.fetchone()
                    else:
                        department = None
                    
                    return render_template('index.html',
                        role='employee',
                        employee=employee,
                        department=department,
                        **common_data
                    )
            except Exception as db_error:
                app.logger.error(f'Database error in dashboard (employee): {str(db_error)}')
                return jsonify({'message': 'Lỗi cơ sở dữ liệu'}), 500
            finally:
                if 'db' in locals():
                    db.close()
    except Exception as e:
        app.logger.error(f'Error in dashboard route: {str(e)}')
        traceback_str = traceback.format_exc()
        app.logger.error(f'Traceback: {traceback_str}')
        
        # Kiểm tra nếu lỗi liên quan đến JWT
        if 'jwt' in str(e).lower() or 'token' in str(e).lower():
            return redirect(url_for('page_login'))
            
        return jsonify({'message': 'Có lỗi xảy ra', 'error': str(e)}), 500
    
    try:
        # Lấy thông tin role từ JWT token
        claims = get_jwt()
        current_role = claims.get('role', 'employee')  # Mặc định là employee nếu không có role
        
        # Lấy dữ liệu chung cho tất cả các role
        common_data = {
            'user_info': get_jwt_identity(),
            'current_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        if current_role == 'admin':
            # Admin sẽ thấy tất cả dữ liệu
            try:
                db = get_db_connection()
                with db.cursor() as cursor:
                    # Lấy danh sách nhân viên
                    cursor.execute("SELECT * FROM employees")
                    employees = cursor.fetchall()
                    
                    # Lấy thông tin phòng ban
                    cursor.execute("SELECT * FROM departments")
                    departments = cursor.fetchall()
                    
                    # Lấy thông tin lương
                    cursor.execute("SELECT * FROM salaries")
                    salaries = cursor.fetchall()
                    
                    return render_template('index.html',
                        role='admin',
                        employees=employees,
                        departments=departments,
                        salaries=salaries,
                        **common_data
                    )
            finally:
                if 'db' in locals():
                    db.close()
        else:
            # Employee chỉ thấy thông tin của mình
            try:
                db = get_db_connection()
                with db.cursor() as cursor:
                    # Lấy thông tin nhân viên hiện tại
                    username = get_jwt_identity()
                    cursor.execute("SELECT * FROM employees WHERE user = %s", (username,))
                    employee = cursor.fetchone()
                    
                    # Lấy thông tin phòng ban của nhân viên
                    if employee:
                        cursor.execute("SELECT * FROM departments WHERE DepartmentID = %s", 
                                     (employee['DepartmentID'],))
                        department = cursor.fetchone()
                    else:
                        department = None
                    
                    return render_template('index.html',
                        role='employee',
                        employee=employee,
                        department=department,
                        **common_data
                    )
            finally:
                if 'db' in locals():
                    db.close()
    except Exception as e:
        app.logger.error(f'Error in index route: {str(e)}')
        return jsonify({'message': 'Có lỗi xảy ra'}), 500

@app.route('/all-employees')
def all_employees():
    with db.cursor() as cursor:
        cursor.execute("SELECT EmployeeID, Fullname,DepartmentName, PositionName, Status FROM employees e LEFT JOIN departments d ON e.DepartmentID = d.DepartmentID LEFT JOIN positions p ON e.PositionID = p.PositionID")
        employees = cursor.fetchall()
        cursor.execute("SELECT DepartmentID, DepartmentName FROM departments")
        departments = cursor.fetchall()
        cursor.execute("SELECT PositionID, PositionName FROM positions")
        positions = cursor.fetchall()
    return render_template('all-employees.html', employees=employees, departments=departments, positions=positions)

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
         #Nếu không có ID, chuyển hướng đến trang danh sách nhân viên
        return redirect(url_for('all_employees'))
    try:
        with db.cursor() as cursor:
            # Lấy thông tin nhân viên theo ID
            cursor.execute("""
                SELECT e.EmployeeID, e.FullName, d.DepartmentName, p.PositionName 
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
            print(emp)

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
@app.route('/edit-department', defaults={'DepartmentID': None})
@app.route('/edit-department/<int:DepartmentID>')
def edit_department(DepartmentID):
    if DepartmentID is None:
        return redirect(url_for('all_departments'))
    try:

        with db.cursor() as cursor:

            cursor.execute("SELECT DepartmentID, DepartmentName FROM departments WHERE DepartmentID = %s ", (DepartmentID,))
            departments = cursor.fetchone()
            if not departments:
                departments = {
                    'DepartmentID': 0,
                    'DepartmentName': 'Không tìm thấy',
                }
                print(departments)
                return render_template('edit-department.html', error="Department not found")
            return render_template('edit-department.html', departments=departments,)
    except Exception as e:
        return render_template('edit-department.html', error=str(e))
    
    
    
@app.route('/add-payroll', methods=['GET', 'POST'])
def add_payroll():
    if request.method == 'POST':
        employee_id = request.form.get('EmployeeID')
        department_id = request.form.get('DepartmentID')
        fullname = request.form.get('Fullname')
        position_id = request.form.get('PositionID')
        total = request.form.get('Total')
        with db.cursor() as cursor:
            cursor.execute("INSERT INTO employee_payroll (EmployeeID, DepartmentID, Fullname, PositionID, Total) VALUES (%s, %s, %s, %s, %s)", (employee_id, department_id, fullname, position_id, total))
            db.commit()
        return redirect(url_for('payroll_details'))
    with db.cursor() as cursor:
        cursor.execute("SELECT * FROM employees")
        employees = cursor.fetchall()
        cursor.execute("SELECT * FROM departments")
        departments = cursor.fetchall()
        cursor.execute("SELECT * FROM positions")
        positions = cursor.fetchall()
        cursor.execute("SELECT * FROM employee_payroll")  
        payrolls = cursor.fetchall()
    return render_template('add-payroll.html', employees=employees, departments=departments, positions=positions, payrolls=payrolls)
@app.route('/add-department', methods=['GET', 'POST'])
def add_department():
    if request.method == 'POST':
        department_name = request.form.get('DepartmentName')
        with db.cursor() as cursor:
            cursor.execute("INSERT INTO departments (DepartmentName) VALUES (%s)", (department_name,))
            db.commit()
        return redirect(url_for('all_departments'))
    with db.cursor() as cursor:
        cursor.execute("SELECT * FROM departments")
        departments = cursor.fetchall()
        cursor.execute("SELECT * FROM employees")
        employees = cursor.fetchall()
    return render_template('add-department.html', departments=departments, employees=employees)
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
@app.route('/payroll-details.html ')
def payroll_details():
    with db.cursor() as cursor:
        cursor.execute("SELECT p.EmployeeID , p.Fullname , d.DepartmentName , p1.PositionName , p.Total   FROM employee_payroll p LEFT JOIN departments d ON p.DepartmentID = d.DepartmentID LEFT JOIN positions p1 ON p.PositionID = p1.PositionID LEFT JOIN employees e ON p.EmployeeID = e.EmployeeID ")
        payrolls = cursor.fetchall()
        cursor.execute("SELECT * FROM employees")
        employees = cursor.fetchall()
        cursor.execute("SELECT * FROM departments")
        departments = cursor.fetchall()
        cursor.execute("SELECT * FROM positions")
        positions = cursor.fetchall()
    return render_template('payroll-details.html', payrolls=payrolls , employees=employees , departments=departments , positions=positions )

@app.route('/salary-history')
def salary_history():
    with db.cursor() as cursor:
        cursor.execute("SELECT s.EmployeeID, e.FullName, s.SalaryID, s.SalaryMonth, s.BaseSalary, s.Bonus, s.Deductions, s.NetSalary FROM salaries s LEFT JOIN employees e ON s.EmployeeID = e.EmployeeID")
        salaries = cursor.fetchall()
        cursor.execute("SELECT * FROM employees")
        employees = cursor.fetchall()
        cursor.execute("SELECT * FROM departments") 
        departments = cursor.fetchall()
        cursor.execute("SELECT * FROM positions")
        positions = cursor.fetchall()
    return render_template('salary-history.html', salaries=salaries, employees=employees, departments=departments, positions=positions)

@app.route('/attendance-records')
def attendance_records():
    with db.cursor() as cursor:
        cursor.execute("SELECT a.EmployeeID, e.FullName, a.AttendanceID, a.WorkDays, a.AbsentDays, a.LeaveDays, a.AttendanceMonth FROM attendance a LEFT JOIN employees e ON a.EmployeeID = e.EmployeeID")
        attendance_records = cursor.fetchall()
        cursor.execute("SELECT * FROM employees")
        employees = cursor.fetchall()
        cursor.execute("SELECT * FROM departments")
        departments = cursor.fetchall()
        cursor.execute("SELECT * FROM positions")
        positions = cursor.fetchall()
    return render_template('attendance-records.html', attendance_records=attendance_records, employees=employees, departments=departments, positions=positions)


@app.route('/all-departments')
def all_departments():
    with db.cursor() as cursor:
        cursor.execute("SELECT d.DepartmentID, d.DepartmentName, e.Fullname  FROM departments d LEFT JOIN employees e ON d.DepartmentID = e.DepartmentID ")
        departments = cursor.fetchall()
        cursor.execute("SELECT * FROM employees")
        employees = cursor.fetchall()
    print(departments)  # Kiểm tra dữ liệu trả về
    return render_template('all-departments.html', departments=departments, employees=employees)

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
            app.logger.info('Register route POST request received')
            data = request.get_json()
            if not data:
                return jsonify({'message': 'Không có dữ liệu được gửi'}), 400
                
            username = data.get('username')
            fullname = data.get('fullname')
            email = data.get('email')
            password = data.get('password')
            
            if not all([username, fullname, email, password]):
                app.logger.warning('Missing required fields')
                return jsonify({'message': 'Thiếu thông tin bắt buộc'}), 400

            # Validate email format
            if '@' not in email:
                return jsonify({'message': 'Email không hợp lệ'}), 400

            # Validate password strength
            if len(password) < 6:
                return jsonify({'message': 'Mật khẩu phải có ít nhất 6 ký tự'}), 400

            db = get_db_connection()
            try:
                with db.cursor() as cursor:
                    # Kiểm tra username trùng
                    cursor.execute('SELECT * FROM user_employee WHERE username = %s', (username,))
                    if cursor.fetchone():
                        return jsonify({'message': 'Tên đăng nhập đã tồn tại'}), 400
                    
                    # Kiểm tra email trùng
                    cursor.execute('SELECT * FROM user_employee WHERE email = %s', (email,))
                    if cursor.fetchone():
                        return jsonify({'message': 'Email đã được sử dụng'}), 400
                    
                    # Thêm user mới
                    hashed_password = generate_password_hash(password)
                    cursor.execute(
                        'INSERT INTO user_employee (username, fullname, email, password, role) VALUES (%s, %s, %s, %s, %s)',
                        (username, fullname, email, hashed_password, 'employee')
                    )
                    db.commit()
                    app.logger.info(f'User {username} registered successfully')
                    return jsonify({'message': 'Đăng ký thành công'}), 201
            except Exception as e:
                db.rollback()
                app.logger.error(f'Database error: {str(e)}')
                return jsonify({'message': 'Lỗi khi thêm người dùng'}), 500
            finally:
                db.close()
        except Exception as e:
            app.logger.error(f'Unexpected error: {str(e)}')
            return jsonify({'message': 'Có lỗi xảy ra, vui lòng thử lại sau'}), 500
            
    return render_template('page-register.html')


@app.route('/page-login', methods=['GET', 'POST'])
def page_login():
    if request.method == 'GET':
        return render_template('page-login.html')
    
    try:
def login():
    if request.method == 'GET':
        return render_template('page-login.html')
    
    try:
        data = request.get_json()
        
        if not data:
            app.logger.error("No JSON data received")
            return jsonify({'message': 'No JSON data received'}), 400
            
        username = data.get('username')
        password = data.get('password')
        
        # Kiểm tra thông tin đăng nhập từ database
        connection = get_db_connection()
        try:
            with connection.cursor() as cursor:
                # Kiểm tra trong bảng admin trước
                cursor.execute('SELECT * FROM admin WHERE user = %s', (username,))
                user = cursor.fetchone()
                if user and check_password_hash(user['pass'], password):
                    access_token = create_access_token(
                        identity=username,
                        additional_claims={'role': 'admin'}
                    )
                    return jsonify({
                        'access_token': access_token,
                        'role': 'admin'
                    }), 200

                # Nếu không có trong admin, kiểm tra trong user_employee
                cursor.execute('SELECT * FROM user_employee WHERE username = %s', (username,))
                user = cursor.fetchone()
                if user and check_password_hash(user['password'], password):
                    access_token = create_access_token(
                        identity=username,
                        additional_claims={'role': 'employee'}
                    )
                    return jsonify({
                        'access_token': access_token,
                        'role': 'employee'
                    }), 200

            return jsonify({'message': 'Invalid credentials'}), 401
        finally:
            connection.close()
    except Exception as e:
        return jsonify({'message': str(e)}), 500

# Thêm route alias cho route page-login để tương thích với code cũ

@app.route('/login')
def login():
    # Chuyển tiếp bất kỳ query params nào tới page-login
    if request.args:
        return redirect(url_for('page_login', **request.args))
    return redirect(url_for('page_login'))

# Thêm decorator để kiểm tra quyền truy cập
def role_required(allowed_roles):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt()
            if claims.get('role') in allowed_roles:
                return fn(*args, **kwargs)
            return jsonify({'message': 'Không có quyền truy cập'}), 403
        return wrapper
    return decorator
# Ví dụ sử dụng decorator để bảo vệ route
@app.route('/admin-dashboard')
@jwt_required()
@role_required(['admin'])
def admin_dashboard():
    return render_template('admin-dashboard.html')

@app.route('/employee-dashboard')
@jwt_required()
@role_required(['employee'])
def employee_dashboard():
    return render_template('employee-dashboard.html')

# Route cho cả admin và employee
@app.route('/profile')
@jwt_required()
@role_required(['admin', 'employee'])
def profile():
    return render_template('profile.html')



@app.route('/update_payroll', methods=['POST'])
def update_payroll():
    if request.method == 'POST':
        employee_id = request.form.get('EmployeeID')
        fullname = request.form.get('FullName')
        position_id = request.form.get('PositionID')
        total = request.form.get('Total')
        department_id = request.form.get('DepartmentID')
        with db.cursor() as cursor:
            cursor.execute("""
                UPDATE employee_payroll
                SET FullName = %s, PositionID = %s, Total = %s, DepartmentID = %s
                WHERE EmployeeID = %s
                """, (fullname, position_id, total, department_id, employee_id))
            db.commit()     
        return redirect(url_for('payroll_details'))

@app.route('/edit-payroll', defaults={'EmployeeID': None})
@app.route('/edit-payroll/<int:EmployeeID> ')
def edit_payroll(EmployeeID):
    with db.cursor() as cursor:
        cursor.execute("SELECT * FROM employee_payroll WHERE EmployeeID = %s", (EmployeeID,))
        # Kiểm tra thông tin đăng nhập từ database
        connection = get_db_connection()
        try:
            with connection.cursor() as cursor:
                # Kiểm tra trong bảng admin trước
                cursor.execute('SELECT * FROM admin WHERE user = %s', (username,))
                user = cursor.fetchone()
                if user and check_password_hash(user['pass'], password):
                    access_token = create_access_token(
                        identity=username,
                        additional_claims={'role': 'admin'}
                    )
                    return jsonify({
                        'access_token': access_token,
                        'role': 'admin'
                    }), 200

                # Nếu không có trong admin, kiểm tra trong user_employee
                cursor.execute('SELECT * FROM user_employee WHERE username = %s', (username,))
                user = cursor.fetchone()
                if user and check_password_hash(user['password'], password):
                    access_token = create_access_token(
                        identity=username,
                        additional_claims={'role': 'employee'}
                    )
                    return jsonify({
                        'access_token': access_token,
                        'role': 'employee'
                    }), 200

            return jsonify({'message': 'Invalid credentials'}), 401
        finally:
            connection.close()
    except Exception as e:
        return jsonify({'message': str(e)}), 500

# Thêm decorator để kiểm tra quyền truy cập
def role_required(allowed_roles):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt()
            if claims.get('role') in allowed_roles:
                return fn(*args, **kwargs)
            return jsonify({'message': 'Không có quyền truy cập'}), 403
        return wrapper
    return decorator

# Ví dụ sử dụng decorator để bảo vệ route
@app.route('/admin-dashboard')
@jwt_required()
@role_required(['admin'])
def admin_dashboard():
    return render_template('admin-dashboard.html')

@app.route('/employee-dashboard')
@jwt_required()
@role_required(['employee'])
def employee_dashboard():
    return render_template('employee-dashboard.html')

# Route cho cả admin và employee
@app.route('/profile')
@jwt_required()
@role_required(['admin', 'employee'])
def profile():
    return render_template('profile.html')

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
        cursor.execute("SELECT * FROM employees")
        employees = cursor.fetchall()
        cursor.execute("SELECT * FROM departments")
        departments = cursor.fetchall()
        cursor.execute("SELECT * FROM positions")
        positions = cursor.fetchall()
        cursor.execute("SELECT * FROM employee_payroll")
        employee_payrolls = cursor.fetchall()
        print(employee_payrolls)
    return render_template('edit-payroll.html', payroll=payroll, employees=employees, departments=departments, positions=positions, employee_payrolls=employee_payrolls)
@app.route('/update_department', methods=['GET', 'POST'])
def update_department():
    if request.method == 'POST':
        department_id = request.form.get('DepartmentID')
        department_name = request.form.get('DepartmentName')
        with db.cursor() as cursor:
            cursor.execute("UPDATE departments SET DepartmentName = %s WHERE DepartmentID = %s", (department_name, department_id))
            db.commit()
        return redirect(url_for('all_departments'))
    with db.cursor() as cursor:
        cursor.execute("SELECT * FROM departments")
        cursor.execute("SELECT * FROM employees")
        cursor.execute("SELECT * FROM positions")
        departments = cursor.fetchall()
        employees = cursor.fetchall()
        positions = cursor.fetchall()
    return render_template('edit-department.html', departments=departments, employees=employees, positions=positions)

@app.route('/delete-department/<int:DepartmentID> ', methods=['POST'])
def delete_department(DepartmentID):
    with db.cursor() as cursor:
        cursor.execute("DELETE FROM departments WHERE DepartmentID = %s", (DepartmentID,))
        db.commit()
    return redirect(url_for('all_departments'))

@app.route('/delete-payroll/<int:EmployeeID> ', methods=['GET', 'POST'])
def delete_payroll(EmployeeID):
    try:
        with db.cursor() as cursor:
            cursor.execute("DELETE FROM employee_payroll WHERE EmployeeID = %s", (EmployeeID,))
            db.commit()
        flash('Payroll deleted successfully', 'success')
        return redirect(url_for('payroll_details'))
    except Exception as e:
        flash('Error deleting payroll', 'error')
        print(e)
        traceback.print_exc()
        return redirect(url_for('payroll_details'))

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

    # Khởi tạo kết nối database
    db = get_db_connection()
    try:
        # Kiểm tra trong bảng admin
        with db.cursor() as cursor:
            cursor.execute("SELECT * FROM admin WHERE user = %s AND pass = %s", (username, password))
            admin = cursor.fetchone()
            if admin:
                token = create_access_token(
                    identity=admin['idadmin'],
                    additional_claims={'role': 'admin'}
                )
                return jsonify({
                    'access_token': token,
                    'role': 'admin',
                    'username': username
                })

        # Kiểm tra trong bảng user_employee (giữ nguyên phần này vì password đã được hash)
        with db.cursor() as cursor:
            cursor.execute("SELECT * FROM user_employee WHERE username = %s", (username,))
            user = cursor.fetchone()
            if user and check_password_hash(user['password'], password):
                token = create_access_token(
                    identity=user['id'],
                    additional_claims={'role': 'employee'}
                )
                return jsonify({
                    'access_token': token,
                    'role': 'employee',
                    'username': username
                })

        return jsonify({'message': 'Invalid credentials'}), 401
    finally:
        db.close()

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
@role_required([ROLE_ADMIN, ROLE_PAYROLL])
def api_add_employee():
    try:
        engine = get_mysql_connection()
        query = "SELECT * FROM salaries"
        df = pd.read_sql(query, engine)
        return jsonify(df.to_dict(orient='records'))
    except Exception as e:
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



@app.route('/update_employee', methods=['GET', 'POST'])
def update_employee():
    if request.method == 'POST':
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
        print("Cập nhật thành công")
        print(fullname, department_id, position_id, status, employee_id)
        # Sau khi cập nhật thành công, chuyển về trang danh sách nhân viên
        return redirect(url_for('all_employees'))
    


# Thêm SECRET_KEY vào config
app.config['SECRET_KEY'] = 'Tritran'

def generate_token(user_id, role):
    token = jwt.encode({
        'user_id': user_id,
        'role': role,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }, app.config['SECRET_KEY'])
    return token



def generate_token(user_id, role):
    token = jwt.encode({
        'user_id': user_id,
        'role': role,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }, app.config['SECRET_KEY'])
    return token
@app.route('/api/user-info', methods=['GET'])
@jwt_required()
def get_user_info():
    current_user = get_jwt_identity()
    return jsonify({'logged_in_as': current_user})


# Cập nhật cấu hình JWT
  # Thay đổi key này
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

@app.route('/check-attendance', methods=['POST'])
def check_attendance():
    data = request.get_json()
    employee_id = data.get('EmployeeID')
    with db.cursor() as cursor:
        cursor.execute("SELECT * FROM employees WHERE EmployeeID = %s", (employee_id,))
        employee = cursor.fetchone()
        if employee:            
            return jsonify({'message': 'Employee found', 'employee': employee})
        else:
            return jsonify({'message': 'Employee not found'}), 404
    
@app.route('/api/check-Out', methods=['PUT'])
def check_out():
    data = request.get_json()
    employee_id = data.get('EmployeeID')
    with db.cursor() as cursor:
        cursor.execute("SELECT * FROM employees WHERE EmployeeID = %s", (employee_id,))
        employee = cursor.fetchone()
        if employee:
            return jsonify({'message': 'Employee found', 'employee': employee})
        else:
            return jsonify({'message': 'Employee not found'}), 404
    


@app.route('/api/check-In', methods=['POST'])
def check_in():
    data = request.get_json()
    employee_id = data.get('EmployeeID')
    with db.cursor() as cursor:
        cursor.execute("SELECT * FROM employees WHERE EmployeeID = %s", (employee_id,))
        employee = cursor.fetchone()
        if employee:
            return jsonify({'message': 'Employee found', 'employee': employee})
        else:
                  return jsonify({'message': 'Employee not found'}), 404
        
   
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


@app.before_request
def before_request():
    if 'user' in session:
        session.permanent = True
        app.permanent_session_lifetime = timedelta(minutes=30)


csrf.init_app(app)

