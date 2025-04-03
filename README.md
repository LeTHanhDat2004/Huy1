# Employee Management System

A Flask-based web application for managing employees and payroll data across SQL Server and MySQL databases.

## Features

- Employee management (CRUD operations)
- Payroll management
- JWT authentication
- Integration with SQL Server and MySQL databases
- Responsive web interface

## Setup

1. Install dependencies:
```bash
pip install flask flask-jwt-extended sqlalchemy pandas pyodbc mysql-connector-python
```

2. Configure database connections in `config.py`:
```python
SQL_SERVER_CONN = "mssql+pyodbc://@THUTHANHLICH/HUMAN_BAITAP?driver=ODBC+Driver+17+for+SQL+Server"
MYSQL_CONN = "mysql+mysqlconnector://root:Phuoc123@localhost:3306/Payroll_baitap"
```

3. Run the application:
```bash
python app.py
```

## API Endpoints

- `GET /employees` - Get all employees
- `GET /payroll` - Get payroll data
- `POST /add-employee` - Add new employee
- `PUT /update-employee/<id>` - Update employee
- `DELETE /delete-employee/<id>` - Delete employee

## Technologies Used

- Flask
- SQLAlchemy
- JWT Authentication
- SQL Server
- MySQL
- Bootstrap
- JavaScript
