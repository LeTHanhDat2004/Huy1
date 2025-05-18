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
    
    # Thêm cột role
    with conn.cursor() as cursor:
        try:
            # Kiểm tra xem cột role đã tồn tại hay chưa
            cursor.execute("SHOW COLUMNS FROM user_employee LIKE 'role'")
            if not cursor.fetchone():
                cursor.execute("ALTER TABLE user_employee ADD COLUMN role VARCHAR(20) DEFAULT 'employee'")
                conn.commit()
                print("- Đã thêm cột 'role' vào bảng user_employee")
            else:
                print("- Cột 'role' đã tồn tại")
                
            # Cập nhật role cho user thach
            cursor.execute("UPDATE user_employee SET role = 'employee' WHERE username = 'thach'")
            conn.commit()
            print("- Đã cập nhật role cho user 'thach'")
            
            # Cập nhật role cho user teach
            cursor.execute("UPDATE user_employee SET role = 'employee' WHERE username = 'teach'")
            conn.commit()
            print("- Đã cập nhật role cho user 'teach'")
            
        except Exception as e:
            print(f"- Lỗi: {str(e)}")
            conn.rollback()
    
    # Kiểm tra lại cấu trúc bảng
    with conn.cursor() as cursor:
        cursor.execute("DESCRIBE user_employee")
        columns = cursor.fetchall()
        print("\n=== Cấu trúc bảng user_employee sau khi cập nhật ===")
        for col in columns:
            print(f"- {col['Field']} ({col['Type']})")
            
    print("\nCập nhật hoàn tất!")
            
except Exception as e:
    print(f"Lỗi chung: {str(e)}")
finally:
    if 'conn' in locals():
        conn.close()
        print("Đã đóng kết nối database") 