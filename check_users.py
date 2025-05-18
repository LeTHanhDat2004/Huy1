import pymysql

try:
    # Kết nối đến MySQL
    conn = pymysql.connect(
        host='127.0.0.1',
        user='root',
        password='Thach4102004!',
        database='payroll_baitap',
        cursorclass=pymysql.cursors.DictCursor
    )
    
    # Xem cấu trúc bảng
    with conn.cursor() as cursor:
        cursor.execute('DESCRIBE user_employee')
        columns = cursor.fetchall()
        
        print("=== Cấu trúc bảng user_employee ===")
        for col in columns:
            print(f"Tên cột: {col['Field']}, Kiểu: {col['Type']}, Null: {col['Null']}, Key: {col['Key']}, Default: {col['Default']}")
        
        print("\n")
    
    # Kiểm tra bảng user_employee
    with conn.cursor() as cursor:
        cursor.execute('SELECT * FROM user_employee')
        users = cursor.fetchall()
        
        print("=== Danh sách người dùng trong bảng user_employee ===")
        for user in users:
            print(f"ID: {user['id']}")
            print(f"Username: {user['username']}")
            print(f"Fullname: {user['fullname']}")
            print(f"Email: {user['email']}")
            print(f"Password: {user['password'][:30]}...")
            print("-" * 50)
            
    # Tạo tài khoản test với mật khẩu rõ ràng nếu chưa có
    with conn.cursor() as cursor:
        # Kiểm tra xem tài khoản test có tồn tại không
        cursor.execute("SELECT * FROM user_employee WHERE username = 'test'")
        if not cursor.fetchone():
            # Tạo tài khoản test với mật khẩu rõ ràng
            from werkzeug.security import generate_password_hash
            test_password = '12345'
            password_hash = generate_password_hash(test_password)
            
            cursor.execute(
                'INSERT INTO user_employee (username, fullname, email, password, role) VALUES (%s, %s, %s, %s, %s)',
                ('test', 'Test Account', 'test@example.com', password_hash, 'employee')
            )
            conn.commit()
            print(f"\nĐã tạo tài khoản test với mật khẩu là '{test_password}'")
        else:
            print("\nTài khoản test đã tồn tại")
            
except Exception as e:
    print(f"Lỗi: {str(e)}")
finally:
    if 'conn' in locals():
        conn.close() 