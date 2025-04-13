import os
from datetime import timedelta

# Database Configurations
SQL_SERVER_CONFIG = {
    'server': 'KALI0CHUA',
    'database': 'HUMAN',
    'username': '',  # Windows Authentication
    'password': '',  # Windows Authentication
    'driver': 'ODBC Driver 17 for SQL Server'
}

MYSQL_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': 'Thach4102004!',
    'database': 'Prayroll_baitap',
    'port': 3306
}

# Connection Strings
SQL_SERVER_CONN = "mssql+pyodbc://@KALI0CHUA/HUMAN?driver=ODBC+Driver+17+for+SQL+Server&trusted_connection=yes"

MYSQL_CONN = "mysql+mysqlconnector://root:Thach4102004!@localhost:3306/Payroll_baitap"

# JWT Configuration
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'your-secret-key-here')
JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)

# API Configuration
API_PREFIX = '/api/v1' 