from flask import Flask, request, jsonify, render_template, send_from_directory, url_for, redirect, flash,flash,session
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
app.config['SECRET_KEY'] = 'Tritran'
app.secret_key = 'tritran0932523'
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
    # Nếu đây là request API, trả về JSON
    if request.path.startswith('/api/'):
        return jsonify({
            'status': 401,
            'sub_status': 'token_expired',
            'msg': 'Token has expired'
        }), 401
    # Nếu là request từ web browser, chuyển hướng về trang đăng nhập với tham số next
    return redirect(url_for('page_login', token_expired='true', next=request.path))

@jwt.invalid_token_loader
def invalid_token_callback(error):
    if request.path.startswith('/api/'):
        return jsonify({
            'status': 401,
            'sub_status': 'invalid_token',
            'msg': 'Invalid token: ' + str(error)
        }), 401
    return redirect(url_for('page_login', error='invalid_token', next=request.path))

@jwt.unauthorized_loader
def missing_token_callback(error):
    if request.path.startswith('/api/'):
        return jsonify({
            'status': 401,
            'sub_status': 'missing_token',
            'msg': 'Missing token: ' + str(error)
        }), 401
    return redirect(url_for('page_login', error='missing_token', next=request.path))

# Middleware để xử lý token từ query params và form
@app.before_request
def handle_auth_token():
    # Ghi log chi tiết request để debug
    app.logger.debug('Request URL: %s', request.url)
    app.logger.debug('Request method: %s', request.method)
    app.logger.debug('Authorization header: %s', request.headers.get('Authorization', 'None'))
    
    # Nếu có token trong query params, thêm vào header
    auth_token = request.args.get('auth_token')
    if auth_token and 'Authorization' not in request.headers:
        # Flask không cho phép sửa request.headers trực tiếp
        # Nhưng chúng ta có thể sửa environ
        app.logger.debug('Found auth_token in query params, adding to headers: %s', auth_token[:10] + '...')
        request.environ['HTTP_AUTHORIZATION'] = f'Bearer {auth_token}'
        
        # Đối với các request đến dashboard, sau khi xử lý token từ query params,
        # chuyển hướng đến URL không có query params để tránh double request
        if request.path == '/dashboard' and len(request.args) > 1:  # > 1 để giữ lại refresh param nếu có
            # Chỉ chuyển hướng nếu có query parameters
            app.logger.debug('Redirecting dashboard request to clean URL')
            return redirect('/dashboard')
    
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
def index():
    return redirect(url_for('page_login'))

@app.route('/dashboard')
@jwt_required()
def dashboard():
    try:
        # Lấy thông tin role từ JWT token
        claims = get_jwt()
        current_role = claims.get('role', 'employee')  # Mặc định là employee nếu không có role
        current_username = get_jwt_identity()  # Lấy username từ token
        
        # Lấy dữ liệu chung cho tất cả các role
        common_data = {
            'user_info': current_username,
            'current_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # Log thông tin token để debug
        app.logger.debug(f'Dashboard access - User: {current_username}, Role: {current_role}')
        
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
                    # Bỏ qua tìm kiếm trong bảng employees vì có thể không có hoặc cấu trúc khác
                    # Tìm kiếm trong bảng user_employee
                    cursor.execute("SELECT * FROM user_employee WHERE username = %s", (current_username,))
                    user = cursor.fetchone()
                    
                    if user:
                        # Tạo dữ liệu employee giả lập từ thông tin user_employee
                        employee = {
                            'EmployeeID': user.get('id', 0),
                            'FullName': user.get('fullname', 'Unknown'),
                            'Email': user.get('email', ''),
                            'Username': user.get('username', current_username),
                            'Role': user.get('role', 'employee'),
                            'DepartmentID': 0,  # Giá trị mặc định
                            'PositionID': 0,    # Giá trị mặc định
                            'Status': 'Active'
                        }
                    else:
                        # Nếu không tìm thấy, tạo dữ liệu trống
                        employee = {
                            'EmployeeID': 0,
                            'FullName': current_username,
                            'Email': '',
                            'Username': current_username,
                            'Role': current_role,
                            'DepartmentID': 0,
                            'PositionID': 0,
                            'Status': 'Unknown'
                        }
                    
                    # Lấy thông tin phòng ban của nhân viên nếu có
                    department = None
                    if employee and employee.get('DepartmentID'):
                        try:
                            cursor.execute("SELECT * FROM departments WHERE DepartmentID = %s", 
                                        (employee['DepartmentID'],))
                            department = cursor.fetchone()
                        except Exception as dept_error:
                            app.logger.warning(f"Could not fetch department: {str(dept_error)}")
                    
                    return render_template('index.html',
                        role='employee',
                        employee=employee,
                        department=department,
                        **common_data
                    )
            except Exception as db_error:
                app.logger.error(f'Database error in dashboard (employee): {str(db_error)}')
                traceback_str = traceback.format_exc()
                app.logger.error(f'Traceback: {traceback_str}')
                return jsonify({'message': 'Lỗi cơ sở dữ liệu', 'error': str(db_error)}), 500
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

@app.route('/all-employees')
@jwt_required()
def all_employees():
    try:
        # Lấy thông tin người dùng từ token
        current_username = get_jwt_identity()
        claims = get_jwt()
        current_role = claims.get('role', 'employee')
        
        db = get_db_connection()
        with db.cursor() as cursor:
            cursor.execute("SELECT e.EmployeeID, e.Fullname, d.DepartmentName, p.PositionName, e.Status FROM employees e LEFT JOIN departments d ON e.DepartmentID = d.DepartmentID LEFT JOIN positions p ON e.PositionID = p.PositionID")
            employees = cursor.fetchall()
            cursor.execute("SELECT DepartmentID, DepartmentName FROM departments")
            departments = cursor.fetchall()
            cursor.execute("SELECT PositionID, PositionName FROM positions")
            positions = cursor.fetchall()
        
        return render_template('all-employees.html', 
                              employees=employees, 
                              departments=departments, 
                              positions=positions,
                              current_role=current_role)
    except Exception as e:
        app.logger.error(f"Error in all_employees: {str(e)}")
        traceback_str = traceback.format_exc()
        app.logger.error(f'Traceback: {traceback_str}')
        
        # Nếu lỗi JWT thì chuyển về trang đăng nhập
        if 'jwt' in str(e).lower() or 'token' in str(e).lower():
            return redirect(url_for('page_login'))
            
        return jsonify({'message': 'Lỗi cơ sở dữ liệu', 'error': str(e)}), 500
    finally:
        if 'db' in locals():
            db.close()

@app.route('/add-employee', methods=['GET', 'POST'])
def add_employee():
    # Xử lý dữ liệu từ form và thêm vào database nếu là POST request
    if request.method == 'POST':
        try:
            fullname = request.form.get('FullName')
            department_id = request.form.get('DepartmentID')
            position_id = request.form.get('PositionID')
            status = request.form.get('Status')
            
            db = get_db_connection()
            with db.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO employees (FullName, DepartmentID, PositionID, Status)
                    VALUES (%s, %s, %s, %s)
                """, (fullname, department_id, position_id, status))
                db.commit()
            return redirect(url_for('all_employees'))
        except Exception as e:
            app.logger.error(f"Error adding employee: {str(e)}")
            return jsonify({'message': 'Lỗi khi thêm nhân viên'}), 500
        finally:
            if 'db' in locals():
                db.close()

    # GET: Lấy danh sách phòng ban và chức vụ cho form
    try:
        db = get_db_connection()
        with db.cursor() as cursor:
            cursor.execute("SELECT DepartmentID, DepartmentName FROM departments")
            departments = cursor.fetchall()
            cursor.execute("SELECT PositionID, PositionName FROM positions")
            positions = cursor.fetchall()
        return render_template('add-employee.html', departments=departments, positions=positions)
    except Exception as e:
        app.logger.error(f"Error fetching data for add_employee form: {str(e)}")
        return jsonify({'message': 'Lỗi cơ sở dữ liệu'}), 500
    finally:
        if 'db' in locals():
            db.close()

@app.route('/page-login', methods=['GET', 'POST'])
def page_login():
    if request.method == 'GET':
        return render_template('page-login.html')
    
    try:
        app.logger.debug("Received login request")
        data = request.get_json()
        
        if not data:
            app.logger.error("No JSON data received")
            return jsonify({'message': 'No JSON data received'}), 400
            
        username = data.get('username')
        password = data.get('password')

        app.logger.debug(f"Login attempt for user: {username}")

        if not username or not password:
            app.logger.warning("Missing username or password")
            return jsonify({'message': 'Thiếu username hoặc password'}), 400

        # Khởi tạo kết nối database
        db = get_db_connection()
        try:
            # Kiểm tra trong bảng admin
            with db.cursor() as cursor:
                cursor.execute("SELECT * FROM admin WHERE user = %s", (username,))
                admin = cursor.fetchone()
                if admin and admin['pass'] == password:  # Direct comparison for admin (warning: insecure)
                    token = create_access_token(
                        identity=username,
                        additional_claims={'role': 'admin'}
                    )
                    app.logger.info(f"Admin login successful: {username}")
                    return jsonify({
                        'access_token': token,
                        'role': 'admin',
                        'username': username
                    })

            # Kiểm tra trong bảng user_employee (password đã được hash)
            with db.cursor() as cursor:
                app.logger.debug(f"Checking user_employee table for {username}")
                cursor.execute("SELECT * FROM user_employee WHERE username = %s", (username,))
                user = cursor.fetchone()
                app.logger.debug(f"Found user: {user is not None}")
                
                if user:
                    # Debug password info
                    app.logger.debug(f"Stored password hash (first 20 chars): {user['password'][:20]}...")
                    
                    # Kiểm tra password với hash
                    if check_password_hash(user['password'], password):
                        app.logger.debug("Password check passed")
                        token = create_access_token(
                            identity=username,
                            additional_claims={'role': user.get('role', 'employee')}
                        )
                        app.logger.info(f"User login successful: {username}")
                        
                        # Debug thông tin token
                        app.logger.debug(f"Generated token (first 20 chars): {token[:20]}...")
                        
                        return jsonify({
                            'access_token': token,
                            'role': user.get('role', 'employee'),
                            'username': username
                        })
                    else:
                        app.logger.warning(f"Invalid password for user: {username}")
                
            app.logger.warning(f"Invalid credentials for: {username}")
            return jsonify({'message': 'Invalid credentials'}), 401
        except Exception as e:
            app.logger.error(f"Database error during login: {str(e)}")
            return jsonify({'message': f'Database error: {str(e)}'}), 500
        finally:
            db.close()
    except Exception as e:
        app.logger.error(f"Unexpected error in login: {str(e)}")
        return jsonify({'message': f'Server error: {str(e)}'}), 500

# Thêm alias cho login để tương thích với các template đang sử dụng
@app.route('/login-redirect')
def login_redirect():
    return redirect(url_for('page_login'))

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
        try:
            employee_id = request.form.get('EmployeeID')
            fullname = request.form.get('FullName')
            position_id = request.form.get('PositionID')
            total = request.form.get('Total')
            department_id = request.form.get('DepartmentID')
            
            db = get_db_connection()
            with db.cursor() as cursor:
                cursor.execute("""
                    UPDATE employee_payroll
                    SET FullName = %s, PositionID = %s, Total = %s, DepartmentID = %s
                    WHERE EmployeeID = %s
                    """, (fullname, position_id, total, department_id, employee_id))
                db.commit()
            return redirect(url_for('payroll_details'))
        except Exception as e:
            app.logger.error(f"Error updating payroll: {str(e)}")
            return jsonify({'message': 'Lỗi khi cập nhật bảng lương'}), 500
        finally:
            if 'db' in locals():
                db.close()

@app.route('/edit-payroll', defaults={'employee_id': None})
@app.route('/edit-payroll/<int:employee_id>')
def edit_payroll(employee_id):
    try:
        if employee_id is None:
            return redirect(url_for('payroll_details'))
            
        db = get_db_connection()
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
            
        return render_template('edit-payroll.html', 
                             payroll=payroll, 
                             employees=employees, 
                             departments=departments, 
                             positions=positions, 
                             employee_payrolls=employee_payrolls)
    except Exception as e:
        app.logger.error(f"Error in edit_payroll: {str(e)}")
        return jsonify({'message': 'Lỗi cơ sở dữ liệu'}), 500
    finally:
        if 'db' in locals():
            db.close()

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

# Database connection functions
def get_sql_server_connection():
    return create_engine(SQL_SERVER_CONN)

def get_mysql_connection():
    return create_engine(MYSQL_CONN)

# API endpoints
@app.route('/api/user-info', methods=['GET'])
@jwt_required()
def get_user_info():
    current_user = get_jwt_identity()
    return jsonify({'logged_in_as': current_user})

@app.route('/api/page-login', methods=['POST'])
def api_login():
    try:
        app.logger.debug("API login request received")
        data = request.get_json()
        
        if not data:
            app.logger.error("No JSON data received")
            return jsonify({'message': 'No JSON data received'}), 400
            
        username = data.get('username')
        password = data.get('password')

        app.logger.debug(f"API login attempt for user: {username}")

        if not username or not password:
            app.logger.warning("Missing username or password")
            return jsonify({'message': 'Thiếu username hoặc password'}), 400

        # Khởi tạo kết nối database
        db = get_db_connection()
        try:
            # Kiểm tra trong bảng admin
            with db.cursor() as cursor:
                cursor.execute("SELECT * FROM admin WHERE user = %s", (username,))
                admin = cursor.fetchone()
                if admin and admin['pass'] == password:  # Direct comparison for admin (warning: insecure)
                    token = create_access_token(
                        identity=username,
                        additional_claims={'role': 'admin'}
                    )
                    app.logger.info(f"Admin login successful: {username}")
                    return jsonify({
                        'access_token': token,
                        'role': 'admin',
                        'username': username
                    })

            # Kiểm tra trong bảng user_employee (password đã được hash)
            with db.cursor() as cursor:
                app.logger.debug(f"Checking user_employee table for {username}")
                cursor.execute("SELECT * FROM user_employee WHERE username = %s", (username,))
                user = cursor.fetchone()
                app.logger.debug(f"Found user: {user is not None}")
                
                if user:
                    # Debug password info
                    app.logger.debug(f"Stored password hash (first 20 chars): {user['password'][:20]}...")
                    
                    # Kiểm tra password với hash
                    if check_password_hash(user['password'], password):
                        app.logger.debug("Password check passed")
                        token = create_access_token(
                            identity=username,
                            additional_claims={'role': user.get('role', 'employee')}
                        )
                        app.logger.info(f"User login successful: {username}")
                        
                        # Debug thông tin token
                        app.logger.debug(f"Generated token (first 20 chars): {token[:20]}...")
                        
                        return jsonify({
                            'access_token': token,
                            'role': user.get('role', 'employee'),
                            'username': username
                        })
                    else:
                        app.logger.warning(f"Invalid password for user: {username}")
                
            app.logger.warning(f"Invalid credentials for: {username}")
            return jsonify({'message': 'Invalid credentials'}), 401
        except Exception as e:
            app.logger.error(f"Database error during login: {str(e)}")
            return jsonify({'message': f'Database error: {str(e)}'}), 500
        finally:
            db.close()
    except Exception as e:
        app.logger.error(f"Unexpected error in login: {str(e)}")
        return jsonify({'message': f'Server error: {str(e)}'}), 500

@app.route('/api/employees', methods=['GET'])
@jwt_required()
@role_required([ROLE_ADMIN, ROLE_HR])
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
@role_required([ROLE_ADMIN, ROLE_PAYROLL])
def get_payroll():
    try:
        engine = get_mysql_connection()
        query = "SELECT * FROM salaries"
        df = pd.read_sql(query, engine)
        return jsonify(df.to_dict(orient='records'))
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/employee-profile/<int:id>', methods=['GET'])
@jwt_required()
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
        try:
            employee_id = request.form.get('EmployeeID')
            fullname = request.form.get('FullName')
            department_id = request.form.get('DepartmentID')
            position_id = request.form.get('PositionID')
            status = request.form.get('Status')

            db = get_db_connection()
            with db.cursor() as cursor:
                cursor.execute("""
                    UPDATE employees
                    SET FullName=%s, DepartmentID=%s, PositionID=%s, Status=%s
                    WHERE EmployeeID=%s
                """, (fullname, department_id, position_id, status, employee_id))
                db.commit()
            return redirect(url_for('all_employees'))
        except Exception as e:
            app.logger.error(f"Error updating employee: {str(e)}")
            return jsonify({'message': 'Lỗi khi cập nhật nhân viên'}), 500
        finally:
            if 'db' in locals():
                db.close()

@app.route('/delete-employee/<int:employee_id>', methods=['POST'])
def delete_employee(employee_id):
    try:
        db = get_db_connection()
        with db.cursor() as cursor:
            # Xóa các bản ghi liên quan trong bảng employee_payroll trước
            cursor.execute("DELETE FROM employee_payroll WHERE EmployeeID = %s", (employee_id,))
            # Sau đó mới xóa nhân viên
            cursor.execute("DELETE FROM employees WHERE EmployeeID = %s", (employee_id,))
            db.commit()
        return redirect(url_for('all_employees'))
    except Exception as e:
        app.logger.error(f"Error deleting employee: {str(e)}")
        return jsonify({'message': 'Lỗi khi xóa nhân viên'}), 500
    finally:
        if 'db' in locals():
            db.close()

@app.before_request
def before_request():
    if 'user' in session:
        session.permanent = True
        app.permanent_session_lifetime = timedelta(minutes=30)

@app.route('/edit-employee', defaults={'employee_id': None})
@app.route('/edit-employee/<int:employee_id>')
@jwt_required()
@role_required(['admin'])
def edit_employee(employee_id):
    try:
        if employee_id is None:
            return redirect(url_for('all_employees'))
            
        db = get_db_connection()
        with db.cursor() as cursor:
            cursor.execute("SELECT * FROM employees WHERE EmployeeID = %s", (employee_id,))
            employee = cursor.fetchone()
            
            cursor.execute("SELECT DepartmentID, DepartmentName FROM departments")
            departments = cursor.fetchall()
            
            cursor.execute("SELECT PositionID, PositionName FROM positions")
            positions = cursor.fetchall()
            
        return render_template('edit-employee.html', 
                             employee=employee, 
                             departments=departments, 
                             positions=positions)
    except Exception as e:
        app.logger.error(f"Error in edit_employee: {str(e)}")
        return jsonify({'message': 'Lỗi cơ sở dữ liệu'}), 500
    finally:
        if 'db' in locals():
            db.close()

@app.route('/employee-profile')
@app.route('/employee-profile/<int:employee_id>')
def employee_profile(employee_id=None):
    try:
        # Verify JWT to ensure only authenticated users can access
        verify_jwt_in_request()
        current_username = get_jwt_identity()
        claims = get_jwt()
        current_role = claims.get('role', 'employee')
        
        db = get_db_connection()
        with db.cursor() as cursor:
            if employee_id:
                # Nếu có employee_id, lấy thông tin nhân viên cụ thể
                cursor.execute("SELECT * FROM employees WHERE EmployeeID = %s", (employee_id,))
            else:
                # Nếu không có employee_id, lấy thông tin của user hiện tại
                cursor.execute("SELECT * FROM user_employee WHERE username = %s", (current_username,))
                user = cursor.fetchone()
                # Nếu user có employee_id thì lấy thông tin từ bảng employees
                if user and 'employee_id' in user:
                    cursor.execute("SELECT * FROM employees WHERE EmployeeID = %s", (user['employee_id'],))
                    
            employee = cursor.fetchone()
            
            # Lấy thông tin phòng ban, chức vụ
            departments = []
            positions = []
            cursor.execute("SELECT * FROM departments")
            departments = cursor.fetchall()
            cursor.execute("SELECT * FROM positions")
            positions = cursor.fetchall()
            
        return render_template('employee-profile.html', 
                              employee=employee, 
                              departments=departments,
                              positions=positions,
                              current_role=current_role)
    except Exception as e:
        app.logger.error(f"Error in employee_profile: {str(e)}")
        traceback_str = traceback.format_exc()
        app.logger.error(f'Traceback: {traceback_str}')
        
        # Nếu lỗi JWT thì chuyển về trang đăng nhập
        if 'jwt' in str(e).lower() or 'token' in str(e).lower():
            return redirect(url_for('page_login'))
            
        return jsonify({'message': 'Lỗi cơ sở dữ liệu', 'error': str(e)}), 500
    finally:
        if 'db' in locals():
            db.close()

@app.route('/payroll_details')
@app.route('/payroll_details/<int:employee_id>')
def payroll_details(employee_id=None):
    try:
        # Verify JWT to ensure only authenticated users can access
        verify_jwt_in_request()
        current_username = get_jwt_identity()
        claims = get_jwt()
        current_role = claims.get('role', 'employee')
        
        db = get_db_connection()
        with db.cursor() as cursor:
            # Lấy danh sách nhân viên
            cursor.execute("SELECT * FROM employees")
            employees = cursor.fetchall()
            
            # Lấy danh sách phòng ban
            cursor.execute("SELECT * FROM departments")
            departments = cursor.fetchall()
            
            # Lấy danh sách vị trí
            cursor.execute("SELECT * FROM positions")
            positions = cursor.fetchall()
            
            # Lấy thông tin lương
            if employee_id and current_role in ['admin', 'payroll_manager']:
                cursor.execute("""
                    SELECT s.*, e.FullName, d.DepartmentName, p.PositionName
                    FROM salaries s
                    JOIN employees e ON s.EmployeeID = e.EmployeeID
                    LEFT JOIN departments d ON e.DepartmentID = d.DepartmentID
                    LEFT JOIN positions p ON e.PositionID = p.PositionID
                    WHERE s.EmployeeID = %s
                """, (employee_id,))
            elif current_role in ['admin', 'payroll_manager']:
                cursor.execute("""
                    SELECT s.*, e.FullName, d.DepartmentName, p.PositionName
                    FROM salaries s
                    JOIN employees e ON s.EmployeeID = e.EmployeeID
                    LEFT JOIN departments d ON e.DepartmentID = d.DepartmentID
                    LEFT JOIN positions p ON e.PositionID = p.PositionID
                """)
            else:
                # Nhân viên thường chỉ xem được thông tin lương của mình
                cursor.execute("""
                    SELECT s.*, e.FullName, d.DepartmentName, p.PositionName
                    FROM salaries s
                    JOIN employees e ON s.EmployeeID = e.EmployeeID
                    LEFT JOIN departments d ON e.DepartmentID = d.DepartmentID
                    LEFT JOIN positions p ON e.PositionID = p.PositionID
                    JOIN user_employee u ON u.username = %s
                    WHERE u.username = %s
                """, (current_username, current_username))
            
            payrolls = cursor.fetchall()
            
            # Cũng kiểm tra bảng employee_payroll nếu có
            try:
                cursor.execute("SELECT * FROM employee_payroll")
                employee_payrolls = cursor.fetchall()
            except:
                employee_payrolls = []
                
        return render_template('payroll-details.html', 
                              payrolls=payrolls,
                              employees=employees,
                              departments=departments,
                              positions=positions,
                              employee_payrolls=employee_payrolls,
                              current_role=current_role)
    except Exception as e:
        app.logger.error(f"Error in payroll_details: {str(e)}")
        traceback_str = traceback.format_exc()
        app.logger.error(f'Traceback: {traceback_str}')
        
        # Nếu lỗi JWT thì chuyển về trang đăng nhập
        if 'jwt' in str(e).lower() or 'token' in str(e).lower():
            return redirect(url_for('page_login'))
            
        return jsonify({'message': 'Lỗi cơ sở dữ liệu', 'error': str(e)}), 500
    finally:
        if 'db' in locals():
            db.close()

@app.route('/salary_history')
@app.route('/salary_history/<int:employee_id>')
def salary_history(employee_id=None):
    try:
        # Verify JWT to ensure only authenticated users can access
        verify_jwt_in_request()
        current_username = get_jwt_identity()
        claims = get_jwt()
        current_role = claims.get('role', 'employee')
        
        db = get_db_connection()
        with db.cursor() as cursor:
            # Lấy thông tin lương theo tháng
            if employee_id and current_role in ['admin', 'payroll_manager']:
                cursor.execute("""
                    SELECT s.*, e.FullName, d.DepartmentName, p.PositionName
                    FROM salaries s
                    JOIN employees e ON s.EmployeeID = e.EmployeeID
                    LEFT JOIN departments d ON e.DepartmentID = d.DepartmentID
                    LEFT JOIN positions p ON e.PositionID = p.PositionID
                    WHERE s.EmployeeID = %s
                    ORDER BY s.SalaryMonth DESC
                """, (employee_id,))
            elif current_role in ['admin', 'payroll_manager']:
                cursor.execute("""
                    SELECT s.*, e.FullName, d.DepartmentName, p.PositionName
                    FROM salaries s
                    JOIN employees e ON s.EmployeeID = e.EmployeeID
                    LEFT JOIN departments d ON e.DepartmentID = d.DepartmentID
                    LEFT JOIN positions p ON e.PositionID = p.PositionID
                    ORDER BY s.SalaryMonth DESC
                """)
            else:
                # Nhân viên thường chỉ xem được thông tin lương của mình
                cursor.execute("""
                    SELECT s.*, e.FullName, d.DepartmentName, p.PositionName
                    FROM salaries s
                    JOIN employees e ON s.EmployeeID = e.EmployeeID
                    LEFT JOIN departments d ON e.DepartmentID = d.DepartmentID
                    LEFT JOIN positions p ON e.PositionID = p.PositionID
                    JOIN user_employee u ON u.username = %s
                    WHERE u.username = %s
                    ORDER BY s.SalaryMonth DESC
                """, (current_username, current_username))
            
            salary_history = cursor.fetchall()
            
            # Lấy danh sách nhân viên và phòng ban (chỉ cho admin/payroll manager)
            employees = []
            departments = []
            if current_role in ['admin', 'payroll_manager']:
                cursor.execute("SELECT * FROM employees")
                employees = cursor.fetchall()
                cursor.execute("SELECT * FROM departments")
                departments = cursor.fetchall()
                
            # Lấy thông tin chức vụ
            cursor.execute("SELECT * FROM positions")
            positions = cursor.fetchall()
                
        return render_template('salary-history.html', 
                             salary_history=salary_history,
                             employees=employees,
                             departments=departments,
                             positions=positions,
                             current_role=current_role)
    except Exception as e:
        app.logger.error(f"Error in salary_history: {str(e)}")
        traceback_str = traceback.format_exc()
        app.logger.error(f'Traceback: {traceback_str}')
        
        # Nếu lỗi JWT thì chuyển về trang đăng nhập
        if 'jwt' in str(e).lower() or 'token' in str(e).lower():
            return redirect(url_for('page_login'))
            
        return jsonify({'message': 'Lỗi cơ sở dữ liệu', 'error': str(e)}), 500
    finally:
        if 'db' in locals():
            db.close()

@app.route('/attendance_records')
@app.route('/attendance_records/<int:employee_id>')
def attendance_records(employee_id=None):
    try:
        # Verify JWT to ensure only authenticated users can access
        verify_jwt_in_request()
        current_username = get_jwt_identity()
        claims = get_jwt()
        current_role = claims.get('role', 'employee')
        
        db = get_db_connection()
        with db.cursor() as cursor:
            # Lấy thông tin chấm công
            if employee_id and current_role in ['admin', 'hr_manager']:
                cursor.execute("""
                    SELECT a.*, e.FullName, d.DepartmentName, p.PositionName
                    FROM attendance a
                    JOIN employees e ON a.EmployeeID = e.EmployeeID
                    LEFT JOIN departments d ON e.DepartmentID = d.DepartmentID
                    LEFT JOIN positions p ON e.PositionID = p.PositionID
                    WHERE a.EmployeeID = %s
                    ORDER BY a.AttendanceMonth DESC
                """, (employee_id,))
            elif current_role in ['admin', 'hr_manager']:
                cursor.execute("""
                    SELECT a.*, e.FullName, d.DepartmentName, p.PositionName
                    FROM attendance a
                    JOIN employees e ON a.EmployeeID = e.EmployeeID
                    LEFT JOIN departments d ON e.DepartmentID = d.DepartmentID
                    LEFT JOIN positions p ON e.PositionID = p.PositionID
                    ORDER BY a.AttendanceMonth DESC
                """)
            else:
                # Nhân viên chỉ xem được chấm công của mình
                cursor.execute("""
                    SELECT a.*, e.FullName, d.DepartmentName, p.PositionName
                    FROM attendance a
                    JOIN employees e ON a.EmployeeID = e.EmployeeID
                    LEFT JOIN departments d ON e.DepartmentID = d.DepartmentID
                    LEFT JOIN positions p ON e.PositionID = p.PositionID
                    JOIN user_employee u ON u.username = %s
                    WHERE u.username = %s
                    ORDER BY a.AttendanceMonth DESC
                """, (current_username, current_username))
            
            attendance_data = cursor.fetchall()
            
            # Lấy thông tin nhân viên, phòng ban (chỉ cho admin/hr_manager)
            employees = []
            departments = []
            if current_role in ['admin', 'hr_manager']:
                cursor.execute("SELECT * FROM employees")
                employees = cursor.fetchall()
                cursor.execute("SELECT * FROM departments")
                departments = cursor.fetchall()
                
            # Lấy thông tin chức vụ
            cursor.execute("SELECT * FROM positions")
            positions = cursor.fetchall()
                
        return render_template('attendance-records.html', 
                             attendance_data=attendance_data,
                             employees=employees,
                             departments=departments,
                             positions=positions,
                             current_role=current_role)
    except Exception as e:
        app.logger.error(f"Error in attendance_records: {str(e)}")
        traceback_str = traceback.format_exc()
        app.logger.error(f'Traceback: {traceback_str}')
        
        # Nếu lỗi JWT thì chuyển về trang đăng nhập
        if 'jwt' in str(e).lower() or 'token' in str(e).lower():
            return redirect(url_for('page_login'))
            
        return jsonify({'message': 'Lỗi cơ sở dữ liệu', 'error': str(e)}), 500
    finally:
        if 'db' in locals():
            db.close()

@app.route('/all_departments')
def all_departments():
    try:
        # Verify JWT to ensure only authenticated users can access
        verify_jwt_in_request()
        current_username = get_jwt_identity()
        claims = get_jwt()
        current_role = claims.get('role', 'employee')
        
        if current_role not in ['admin', 'hr_manager']:
            return jsonify({'message': 'Không có quyền truy cập'}), 403
            
        db = get_db_connection()
        with db.cursor() as cursor:
            cursor.execute("SELECT * FROM departments")
            departments = cursor.fetchall()
                
        return render_template('all-departments.html', 
                             departments=departments,
                             current_role=current_role)
    except Exception as e:
        app.logger.error(f"Error in all_departments: {str(e)}")
        traceback_str = traceback.format_exc()
        app.logger.error(f'Traceback: {traceback_str}')
        
        # Nếu lỗi JWT thì chuyển về trang đăng nhập
        if 'jwt' in str(e).lower() or 'token' in str(e).lower():
            return redirect(url_for('page_login'))
            
        return jsonify({'message': 'Lỗi cơ sở dữ liệu', 'error': str(e)}), 500
    finally:
        if 'db' in locals():
            db.close()

@app.route('/add_department', methods=['GET', 'POST'])
def add_department():
    try:
        # Verify JWT to ensure only authenticated users can access
        verify_jwt_in_request()
        current_username = get_jwt_identity()
        claims = get_jwt()
        current_role = claims.get('role', 'employee')
        
        if current_role not in ['admin', 'hr_manager']:
            return jsonify({'message': 'Không có quyền truy cập'}), 403
            
        if request.method == 'POST':
            department_name = request.form.get('DepartmentName')
            
            db = get_db_connection()
            with db.cursor() as cursor:
                # Tìm ID lớn nhất để tạo ID mới
                cursor.execute("SELECT MAX(DepartmentID) AS max_id FROM departments")
                result = cursor.fetchone()
                new_id = 1
                if result and result['max_id']:
                    new_id = result['max_id'] + 1
                    
                cursor.execute("""
                    INSERT INTO departments (DepartmentID, DepartmentName)
                    VALUES (%s, %s)
                """, (new_id, department_name))
                db.commit()
                
            return redirect(url_for('all_departments'))
            
        return render_template('add-department.html', 
                             current_role=current_role)
    except Exception as e:
        app.logger.error(f"Error in add_department: {str(e)}")
        traceback_str = traceback.format_exc()
        app.logger.error(f'Traceback: {traceback_str}')
        
        # Nếu lỗi JWT thì chuyển về trang đăng nhập
        if 'jwt' in str(e).lower() or 'token' in str(e).lower():
            return redirect(url_for('page_login'))
            
        return jsonify({'message': 'Lỗi cơ sở dữ liệu', 'error': str(e)}), 500
    finally:
        if 'db' in locals():
            db.close()

@app.route('/edit_department', defaults={'department_id': None})
@app.route('/edit_department/<int:department_id>', methods=['GET', 'POST'])
def edit_department(department_id=None):
    try:
        # Verify JWT to ensure only authenticated users can access
        verify_jwt_in_request()
        current_username = get_jwt_identity()
        claims = get_jwt()
        current_role = claims.get('role', 'employee')
        
        if current_role not in ['admin', 'hr_manager']:
            return jsonify({'message': 'Không có quyền truy cập'}), 403
            
        if department_id is None:
            return redirect(url_for('all_departments'))
            
        db = get_db_connection()
        
        if request.method == 'POST':
            department_name = request.form.get('DepartmentName')
            
            with db.cursor() as cursor:
                cursor.execute("""
                    UPDATE departments
                    SET DepartmentName = %s
                    WHERE DepartmentID = %s
                """, (department_name, department_id))
                db.commit()
                
            return redirect(url_for('all_departments'))
            
        # GET: Lấy thông tin phòng ban để hiển thị form edit
        with db.cursor() as cursor:
            cursor.execute("SELECT * FROM departments WHERE DepartmentID = %s", (department_id,))
            department = cursor.fetchone()
            
            if not department:
                return redirect(url_for('all_departments'))
                
        return render_template('edit-department.html', 
                             department=department,
                             current_role=current_role)
    except Exception as e:
        app.logger.error(f"Error in edit_department: {str(e)}")
        traceback_str = traceback.format_exc()
        app.logger.error(f'Traceback: {traceback_str}')
        
        # Nếu lỗi JWT thì chuyển về trang đăng nhập
        if 'jwt' in str(e).lower() or 'token' in str(e).lower():
            return redirect(url_for('page_login'))
            
        return jsonify({'message': 'Lỗi cơ sở dữ liệu', 'error': str(e)}), 500
    finally:
        if 'db' in locals():
            db.close()

@app.route('/user_roles')
def user_roles():
    try:
        # Verify JWT to ensure only authenticated users can access
        verify_jwt_in_request()
        current_username = get_jwt_identity()
        claims = get_jwt()
        current_role = claims.get('role', 'employee')
        
        if current_role != 'admin':
            return jsonify({'message': 'Chỉ admin mới có quyền truy cập'}), 403
            
        db = get_db_connection()
        with db.cursor() as cursor:
            # Lấy thông tin từ bảng roles
            cursor.execute("SELECT * FROM roles")
            roles = cursor.fetchall()
            
            # Lấy danh sách người dùng và quyền tương ứng
            cursor.execute("""
                SELECT u.*, r.role_name, r.description 
                FROM user_employee u
                LEFT JOIN roles r ON u.role = r.role_name
            """)
            users = cursor.fetchall()
                
        return render_template('user-roles.html', 
                             roles=roles,
                             users=users,
                             current_role=current_role)
    except Exception as e:
        app.logger.error(f"Error in user_roles: {str(e)}")
        traceback_str = traceback.format_exc()
        app.logger.error(f'Traceback: {traceback_str}')
        
        # Nếu lỗi JWT thì chuyển về trang đăng nhập
        if 'jwt' in str(e).lower() or 'token' in str(e).lower():
            return redirect(url_for('page_login'))
            
        return jsonify({'message': 'Lỗi cơ sở dữ liệu', 'error': str(e)}), 500
    finally:
        if 'db' in locals():
            db.close()

@app.route('/permissions')
def permissions():
    try:
        # Verify JWT to ensure only authenticated users can access
        verify_jwt_in_request()
        current_username = get_jwt_identity()
        claims = get_jwt()
        current_role = claims.get('role', 'employee')
        
        if current_role != 'admin':
            return jsonify({'message': 'Chỉ admin mới có quyền truy cập'}), 403
            
        # Tạo danh sách quyền theo vai trò (hard-coded vì chưa có bảng tương ứng)
        permissions_data = {
            'admin': ['dashboard', 'employee_management', 'payroll_management', 'attendance_management', 'department_management', 'job_title_management', 'user_role_management', 'permission_management', 'access_log_management'],
            'hr_manager': ['dashboard', 'employee_management', 'attendance_management', 'department_management'],
            'payroll_manager': ['dashboard', 'payroll_management'],
            'employee': ['dashboard', 'profile', 'attendance_view', 'payroll_view']
        }
                
        return render_template('permissions.html', 
                             permissions=permissions_data,
                             current_role=current_role)
    except Exception as e:
        app.logger.error(f"Error in permissions: {str(e)}")
        traceback_str = traceback.format_exc()
        app.logger.error(f'Traceback: {traceback_str}')
        
        # Nếu lỗi JWT thì chuyển về trang đăng nhập
        if 'jwt' in str(e).lower() or 'token' in str(e).lower():
            return redirect(url_for('page_login'))
            
        return jsonify({'message': 'Lỗi cơ sở dữ liệu', 'error': str(e)}), 500

@app.route('/access_logs')
def access_logs():
    try:
        # Verify JWT to ensure only authenticated users can access
        verify_jwt_in_request()
        current_username = get_jwt_identity()
        claims = get_jwt()
        current_role = claims.get('role', 'employee')
        
        if current_role != 'admin':
            return jsonify({'message': 'Chỉ admin mới có quyền truy cập'}), 403
            
        # Vì chưa có bảng log, tạo dữ liệu mẫu
        access_logs_data = [
            {
                'id': 1,
                'username': 'thach',
                'access_time': datetime.now() - timedelta(hours=1),
                'ip_address': '127.0.0.1',
                'action': 'Login',
                'status': 'Success'
            },
            {
                'id': 2,
                'username': 'admin',
                'access_time': datetime.now() - timedelta(hours=2),
                'ip_address': '127.0.0.1',
                'action': 'View employee list',
                'status': 'Success'
            },
            {
                'id': 3,
                'username': 'employee1',
                'access_time': datetime.now() - timedelta(hours=3),
                'ip_address': '127.0.0.1',
                'action': 'Login',
                'status': 'Failed'
            },
        ]
                
        return render_template('access-logs.html', 
                             access_logs=access_logs_data,
                             current_role=current_role)
    except Exception as e:
        app.logger.error(f"Error in access_logs: {str(e)}")
        traceback_str = traceback.format_exc()
        app.logger.error(f'Traceback: {traceback_str}')
        
        # Nếu lỗi JWT thì chuyển về trang đăng nhập
        if 'jwt' in str(e).lower() or 'token' in str(e).lower():
            return redirect(url_for('page_login'))
            
        return jsonify({'message': 'Lỗi cơ sở dữ liệu', 'error': str(e)}), 500

@app.route('/all_job_titles')
def all_job_titles():
    try:
        # Verify JWT to ensure only authenticated users can access
        verify_jwt_in_request()
        current_username = get_jwt_identity()
        claims = get_jwt()
        current_role = claims.get('role', 'employee')
        
        if current_role not in ['admin', 'hr_manager']:
            return jsonify({'message': 'Không có quyền truy cập'}), 403
            
        db = get_db_connection()
        with db.cursor() as cursor:
            cursor.execute("SELECT * FROM positions")
            positions = cursor.fetchall()
                
        return render_template('job-titles.html', 
                             positions=positions,
                             current_role=current_role)
    except Exception as e:
        app.logger.error(f"Error in all_job_titles: {str(e)}")
        traceback_str = traceback.format_exc()
        app.logger.error(f'Traceback: {traceback_str}')
        
        # Nếu lỗi JWT thì chuyển về trang đăng nhập
        if 'jwt' in str(e).lower() or 'token' in str(e).lower():
            return redirect(url_for('page_login'))
            
        return jsonify({'message': 'Lỗi cơ sở dữ liệu', 'error': str(e)}), 500
    finally:
        if 'db' in locals():
            db.close()

@app.route('/manage_departments')
def manage_departments():
    try:
        # Verify JWT to ensure only authenticated users can access
        verify_jwt_in_request()
        current_username = get_jwt_identity()
        claims = get_jwt()
        current_role = claims.get('role', 'employee')
        
        if current_role not in ['admin', 'hr_manager']:
            return jsonify({'message': 'Không có quyền truy cập'}), 403
            
        db = get_db_connection()
        with db.cursor() as cursor:
            cursor.execute("SELECT * FROM departments")
            departments = cursor.fetchall()
                
        return render_template('manage-departments.html', 
                             departments=departments,
                             current_role=current_role)
    except Exception as e:
        app.logger.error(f"Error in manage_departments: {str(e)}")
        traceback_str = traceback.format_exc()
        app.logger.error(f'Traceback: {traceback_str}')
        
        # Nếu lỗi JWT thì chuyển về trang đăng nhập
        if 'jwt' in str(e).lower() or 'token' in str(e).lower():
            return redirect(url_for('page_login'))
            
        return jsonify({'message': 'Lỗi cơ sở dữ liệu', 'error': str(e)}), 500
    finally:
        if 'db' in locals():
            db.close()

@app.route('/manage_job_titles')
def manage_job_titles():
    try:
        # Verify JWT to ensure only authenticated users can access
        verify_jwt_in_request()
        current_username = get_jwt_identity()
        claims = get_jwt()
        current_role = claims.get('role', 'employee')
        
        if current_role not in ['admin', 'hr_manager']:
            return jsonify({'message': 'Không có quyền truy cập'}), 403
            
        db = get_db_connection()
        with db.cursor() as cursor:
            cursor.execute("SELECT * FROM positions")
            positions = cursor.fetchall()
                
        return render_template('manage-job-titles.html', 
                             positions=positions,
                             current_role=current_role)
    except Exception as e:
        app.logger.error(f"Error in manage_job_titles: {str(e)}")
        traceback_str = traceback.format_exc()
        app.logger.error(f'Traceback: {traceback_str}')
        
        # Nếu lỗi JWT thì chuyển về trang đăng nhập
        if 'jwt' in str(e).lower() or 'token' in str(e).lower():
            return redirect(url_for('page_login'))
            
        return jsonify({'message': 'Lỗi cơ sở dữ liệu', 'error': str(e)}), 500
    finally:
        if 'db' in locals():
            db.close()

# Thêm các route cho các báo cáo
@app.route('/employee_summary')
def employee_summary():
    try:
        verify_jwt_in_request()
        return render_template('employee-summary.html')
    except:
        return redirect(url_for('page_login'))

@app.route('/payroll_report')
def payroll_report():
    try:
        verify_jwt_in_request()
        return render_template('payroll-report.html')
    except:
        return redirect(url_for('page_login'))

@app.route('/dividend_report')
def dividend_report():
    try:
        verify_jwt_in_request()
        return render_template('dividend-report.html')
    except:
        return redirect(url_for('page_login'))

@app.route('/comparative_charts')
def comparative_charts():
    try:
        verify_jwt_in_request()
        return render_template('comparative-charts.html')
    except:
        return redirect(url_for('page_login'))

# Thêm các route cho thông báo
@app.route('/work_anniversary')
def work_anniversary():
    try:
        verify_jwt_in_request()
        return render_template('work-anniversary.html')
    except:
        return redirect(url_for('page_login'))

@app.route('/leave_alerts')
def leave_alerts():
    try:
        verify_jwt_in_request()
        return render_template('leave-alerts.html')
    except:
        return redirect(url_for('page_login'))

@app.route('/payroll_alerts')
def payroll_alerts():
    try:
        verify_jwt_in_request()
        return render_template('payroll-alerts.html')
    except:
        return redirect(url_for('page_login'))

@app.route('/salary_statements')
def salary_statements():
    try:
        verify_jwt_in_request()
        return render_template('salary-statements.html')
    except:
        return redirect(url_for('page_login'))

# Thêm route index để tương thích với các template sử dụng url_for('index')
@app.route('/index')
def index_redirect():
    return redirect(url_for('dashboard'))

# Thêm lại route login để tương thích với các template đang sử dụng url_for('login')
@app.route('/login')
def login_page():
    # Chuyển tiếp bất kỳ query params nào tới page-login
    if request.args:
        return redirect(url_for('page_login', **request.args))
    return redirect(url_for('page_login'))

# Tạo thêm một alias cho url_for('login')
@app.route('/login-alias')
def login():
    # Chuyển tiếp bất kỳ query params nào tới page-login
    if request.args:
        return redirect(url_for('page_login', **request.args))
    return redirect(url_for('page_login'))

if __name__ == '__main__':
    app.run(debug=True)

