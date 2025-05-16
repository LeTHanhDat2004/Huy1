<?php
require_once 'config.php';
require_once 'functions.php';

class NotificationSystem {
    private $conn;
    
    public function __construct($conn) {
        $this->conn = $conn;
    }
    
    // Kiểm tra kỷ niệm ngày làm việc
    public function checkWorkAnniversary() {
        $sql = "SELECT id, name, email, join_date FROM user_employee 
                WHERE MONTH(join_date) = MONTH(CURRENT_DATE()) 
                AND DAY(join_date) = DAY(CURRENT_DATE())";
        
        $result = $this->conn->query($sql);
        
        while($row = $result->fetch_assoc()) {
            $years = date('Y') - date('Y', strtotime($row['join_date']));
            $message = "Chúc mừng kỷ niệm {$years} năm làm việc tại công ty!";
            $this->createNotification($row['id'], 'anniversary', $message);
            $this->sendEmail($row['email'], 'Kỷ niệm ngày làm việc', $message);
        }
    }
    
    // Kiểm tra ngày nghỉ phép
    public function checkLeaveDays() {
        $sql = "SELECT u.id, u.name, u.email, 
                COUNT(l.id) as leave_count 
                FROM user_employee u 
                LEFT JOIN leave_records l ON u.id = l.user_id 
                WHERE l.status = 'approved' 
                AND YEAR(l.start_date) = YEAR(CURRENT_DATE())
                GROUP BY u.id 
                HAVING leave_count > 20";
        
        $result = $this->conn->query($sql);
        
        while($row = $result->fetch_assoc()) {
            $message = "Cảnh báo: Bạn đã sử dụng {$row['leave_count']} ngày nghỉ phép trong năm nay.";
            $this->createNotification($row['id'], 'leave_warning', $message);
            $this->sendEmail($row['email'], 'Cảnh báo ngày nghỉ phép', $message);
        }
    }
    
    // Kiểm tra chênh lệch lương
    public function checkSalaryDifference() {
        $sql = "SELECT u.id, u.name, u.email, 
                sh.salary, sh.month, sh.year 
                FROM user_employee u 
                JOIN salary_history sh ON u.id = sh.user_id 
                WHERE sh.year = YEAR(CURRENT_DATE()) 
                ORDER BY u.id, sh.month DESC";
        
        $result = $this->conn->query($sql);
        $current_user = null;
        $last_salary = null;
        
        while($row = $result->fetch_assoc()) {
            if($current_user != $row['id']) {
                $current_user = $row['id'];
                $last_salary = $row['salary'];
            } else {
                $difference = abs($row['salary'] - $last_salary);
                $percentage = ($difference / $last_salary) * 100;
                
                if($percentage > 20) {
                    $message = "Cảnh báo: Có sự chênh lệch lớn ({$percentage}%) trong lương của bạn giữa tháng {$row['month']} và tháng trước.";
                    $this->createNotification($row['id'], 'salary_warning', $message);
                    $this->sendEmail($row['email'], 'Cảnh báo chênh lệch lương', $message);
                }
                $last_salary = $row['salary'];
            }
        }
    }
    
    // Gửi bảng lương hàng tháng
    public function sendMonthlySalary() {
        $current_month = date('m');
        $current_year = date('Y');
        
        $sql = "SELECT u.id, u.name, u.email, sh.salary 
                FROM user_employee u 
                JOIN salary_history sh ON u.id = sh.user_id 
                WHERE sh.month = ? AND sh.year = ?";
        
        $stmt = $this->conn->prepare($sql);
        $stmt->bind_param("ii", $current_month, $current_year);
        $stmt->execute();
        $result = $stmt->get_result();
        
        while($row = $result->fetch_assoc()) {
            $message = "Bảng lương tháng {$current_month}/{$current_year} của bạn là: " . number_format($row['salary']) . " VND";
            $this->createNotification($row['id'], 'salary', $message);
            $this->sendEmail($row['email'], 'Bảng lương tháng', $message);
        }
    }
    
    // Tạo thông báo mới
    private function createNotification($user_id, $type, $message) {
        $sql = "INSERT INTO notifications (user_id, type, message) VALUES (?, ?, ?)";
        $stmt = $this->conn->prepare($sql);
        $stmt->bind_param("iss", $user_id, $type, $message);
        $stmt->execute();
    }
    
    // Gửi email
    private function sendEmail($to, $subject, $message) {
        // Cấu hình email
        $headers = "From: hr@company.com\r\n";
        $headers .= "Content-Type: text/html; charset=UTF-8\r\n";
        
        // Gửi email
        mail($to, $subject, $message, $headers);
    }
    
    // Lấy thông báo chưa đọc
    public function getUnreadNotifications($user_id) {
        $sql = "SELECT * FROM notifications 
                WHERE user_id = ? AND is_read = FALSE 
                ORDER BY created_at DESC";
        
        $stmt = $this->conn->prepare($sql);
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        return $stmt->get_result();
    }
    
    // Đánh dấu thông báo đã đọc
    public function markAsRead($notification_id) {
        $sql = "UPDATE notifications SET is_read = TRUE WHERE id = ?";
        $stmt = $this->conn->prepare($sql);
        $stmt->bind_param("i", $notification_id);
        $stmt->execute();
    }
}

// Khởi tạo hệ thống thông báo
$notificationSystem = new NotificationSystem($conn);

// Chạy các kiểm tra định kỳ
$notificationSystem->checkWorkAnniversary();
$notificationSystem->checkLeaveDays();
$notificationSystem->checkSalaryDifference();
$notificationSystem->sendMonthlySalary();
?> 