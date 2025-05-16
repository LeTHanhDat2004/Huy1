-- Bảng notifications
CREATE TABLE IF NOT EXISTS notifications (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT,
    type VARCHAR(50) NOT NULL,
    message TEXT NOT NULL,
    is_read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES user_employee(id)
);

-- Bảng salary_history
CREATE TABLE IF NOT EXISTS salary_history (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT,
    salary DECIMAL(10,2) NOT NULL,
    month INT NOT NULL,
    year INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES user_employee(id)
);

-- Bảng leave_records
CREATE TABLE IF NOT EXISTS leave_records (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT,
    start_date DATE NOT NULL,
    end_date DATE NOT NULL,
    type VARCHAR(50) NOT NULL,
    reason TEXT,
    status VARCHAR(20) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES user_employee(id)
); 