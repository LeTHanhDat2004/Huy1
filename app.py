from flask import Flask, request, jsonify, render_template, send_from_directory
from flask_jwt_extended import JWTManager, jwt_required, create_access_token
from sqlalchemy import create_engine
import pandas as pd
from config import SQL_SERVER_CONFIG, MYSQL_CONFIG, JWT_SECRET_KEY, JWT_ACCESS_TOKEN_EXPIRES, API_PREFIX, SQL_SERVER_CONN, MYSQL_CONN
from datetime import datetime
import pyodbc
import mysql.connector
import os

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = JWT_SECRET_KEY
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = JWT_ACCESS_TOKEN_EXPIRES
jwt = JWTManager(app)

# Serve static files
@app.route('/css/<path:filename>')
def serve_css(filename):
    return send_from_directory('css', filename)

@app.route('/js/<path:filename>')
def serve_js(filename):
    return send_from_directory('js', filename)

@app.route('/images/<path:filename>')
def serve_images(filename):
    return send_from_directory('images', filename)

@app.route('/icons/<path:filename>')
def serve_icons(filename):
    return send_from_directory('icons', filename)

@app.route('/vendor/<path:filename>')
def serve_vendor(filename):
    return send_from_directory('vendor', filename)

# Index route
@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

# Database connection functions
def get_sql_server_connection():
    return create_engine(SQL_SERVER_CONN)

def get_mysql_connection():
    return create_engine(MYSQL_CONN)

# Authentication endpoint
@app.route('/login', methods=['POST'])
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return jsonify({'message': 'Could not verify'}), 401
    
    # Add your authentication logic here
    access_token = create_access_token(identity=auth.username)
    return jsonify({'access_token': access_token})

# Employee endpoints
@app.route('/employees', methods=['GET'])
@jwt_required()
def get_employees():
    try:
        engine = get_sql_server_connection()
        query = "SELECT * FROM Employees"
        df = pd.read_sql(query, engine)
        return jsonify(df.to_dict(orient='records'))
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/payroll', methods=['GET'])
@jwt_required()
def get_payroll():
    try:
        engine = get_mysql_connection()
        query = "SELECT * FROM salaries"
        df = pd.read_sql(query, engine)
        return jsonify(df.to_dict(orient='records'))
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/add-employee', methods=['POST'])
@jwt_required()
def add_employee():
    try:
        data = request.get_json()
        
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
                data['PositionID'], data['Status']
            ))
        
        return jsonify({'message': 'Employee added successfully', 'employee_id': employee_id}), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/update-employee/<int:employee_id>', methods=['PUT'])
@jwt_required()
def update_employee(employee_id):
    try:
        data = request.get_json()
        
        # Update in SQL Server
        engine_sql = get_sql_server_connection()
        query_sql = """
            UPDATE Employees 
            SET FullName = ?, DateOfBirth = ?, Gender = ?, PhoneNumber = ?,
                Email = ?, DepartmentID = ?, PositionID = ?, Status = ?,
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

@app.route('/delete-employee/<int:employee_id>', methods=['DELETE'])
@jwt_required()
def delete_employee(employee_id):
    try:
        # Delete from SQL Server
        engine_sql = get_sql_server_connection()
        with engine_sql.connect() as conn:
            conn.execute("DELETE FROM Employees WHERE EmployeeID = ?", employee_id)
        
        # Delete from MySQL payroll
        engine_mysql = get_mysql_connection()
        with engine_mysql.connect() as conn:
            conn.execute("DELETE FROM employees WHERE EmployeeID = %s", employee_id)
        
        return jsonify({'message': 'Employee deleted successfully'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True) 