<?php
require_once 'config.php';
require_once 'functions.php';
require_once 'notifications.php';

// Khởi tạo hệ thống thông báo
$notificationSystem = new NotificationSystem($conn);

// Chạy các kiểm tra
$notificationSystem->checkWorkAnniversary();
$notificationSystem->checkLeaveDays();
$notificationSystem->checkSalaryDifference();

// Gửi bảng lương vào ngày cuối tháng
if (date('d') == date('t')) {
    $notificationSystem->sendMonthlySalary();
}

echo "Đã chạy xong các kiểm tra thông báo.\n";
?> 