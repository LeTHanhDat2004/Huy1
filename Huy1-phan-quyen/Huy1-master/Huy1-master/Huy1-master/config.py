import os
from datetime import timedelta

# Database Configurations
SQL_SERVER_CONFIG = {
    'server': 'THUTHANHLICH',
    'database': 'HUMAN_BAITAP',
    'username': '',  # Windows Authentication
    'password': '',  # Windows Authentication
    'driver': 'ODBC Driver 17 for SQL Server'
}

MYSQL_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': 'Phuoc123',
    'database': 'payroll1',
    'port': 3306
}

# Connection Strings
SQL_SERVER_CONN = "mssql+pyodbc://@THUTHANHLICH/HUMAN_BAITAP?driver=ODBC+Driver+17+for+SQL+Server"
MYSQL_CONN = "mysql+mysqlconnector://root:Phuoc123@localhost:3306/Payrolls"

# JWT Configuration
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'your-secret-key-here')
JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)

# API Configuration
API_PREFIX = '/api/v1' 