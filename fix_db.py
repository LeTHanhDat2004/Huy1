import pymysql
from werkzeug.security import generate_password_hash

try:
    # Kết nối đến MySQL
    conn = pymysql.connect(
        host='127.0.0.1',
        user='root',
        password='Thach4102004!',
        database='payroll_baitap',
        cursorclass=pymysql.cursors.DictCursor
    )
    
    print("Đang cập nhật cấu trúc bảng user_employee...")
    
    # Đổi tên cột từ 'user' thành 'username' 
    with conn.cursor() as cursor:
        try:
            cursor.execute("ALTER TABLE user_employee CHANGE COLUMN `user` `username` VARCHAR(45) NOT NULL")
            conn.commit()
            print("- Đã đổi tên cột 'user' thành 'username'")
        except Exception as e:
            print(f"- Lỗi khi đổi tên cột 'user': {str(e)}")
            conn.rollback()
            
    # Đổi tên cột từ 'iduser_employee' thành 'id'
    with conn.cursor() as cursor:
        try:
            cursor.execute("ALTER TABLE user_employee CHANGE COLUMN `iduser_employee` `id` INT NOT NULL AUTO_INCREMENT")
            conn.commit()
            print("- Đã đổi tên cột 'iduser_employee' thành 'id'")
        except Exception as e:
            print(f"- Lỗi khi đổi tên cột 'iduser_employee': {str(e)}")
            conn.rollback()
    
    # Hash mật khẩu của tài khoản thach
    with conn.cursor() as cursor:
        try:
            # Tạo hash cho mật khẩu '12345'
            hashed_password = generate_password_hash('12345')
            
            # Cập nhật mật khẩu trong database
            cursor.execute("UPDATE user_employee SET password = %s WHERE username = 'thach'", (hashed_password,))
            conn.commit()
            print("- Đã cập nhật mật khẩu hash cho tài khoản 'thach'")
        except Exception as e:
            print(f"- Lỗi khi cập nhật mật khẩu: {str(e)}")
            conn.rollback()
    
    # Tạo thêm tài khoản 'teach' với mật khẩu là '12345'
    with conn.cursor() as cursor:
        try:
            # Kiểm tra xem tài khoản teach đã tồn tại chưa
            cursor.execute("SELECT * FROM user_employee WHERE username = 'teach'")
            if not cursor.fetchone():
                hashed_password = generate_password_hash('12345')
                cursor.execute(
                    "INSERT INTO user_employee (username, fullname, email, password) VALUES (%s, %s, %s, %s)",
                    ('teach', 'Teacher User', 'teacher@example.com', hashed_password)
                )
                conn.commit()
                print("- Đã tạo tài khoản 'teach' với mật khẩu '12345'")
            else:
                print("- Tài khoản 'teach' đã tồn tại")
        except Exception as e:
            print(f"- Lỗi khi tạo tài khoản 'teach': {str(e)}")
            conn.rollback()
            
    print("\nHoàn tất cập nhật database!")
            
except Exception as e:
    print(f"Lỗi chung: {str(e)}")
finally:
    if 'conn' in locals():
        conn.close()
        print("Đã đóng kết nối database") 