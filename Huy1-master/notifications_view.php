<?php
require_once 'config.php';
require_once 'functions.php';
require_once 'notifications.php';

// Kiểm tra đăng nhập
session_start();
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

$user_id = $_SESSION['user_id'];
$notificationSystem = new NotificationSystem($conn);

// Xử lý đánh dấu thông báo đã đọc
if (isset($_POST['mark_read']) && isset($_POST['notification_id'])) {
    $notificationSystem->markAsRead($_POST['notification_id']);
}

// Lấy danh sách thông báo
$notifications = $notificationSystem->getUnreadNotifications($user_id);
?>

<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Thông báo</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .notification-item {
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 5px;
            background-color: #f8f9fa;
            border-left: 4px solid #007bff;
        }
        .notification-item:hover {
            background-color: #e9ecef;
        }
        .notification-item.unread {
            background-color: #e3f2fd;
        }
        .notification-icon {
            margin-right: 10px;
            font-size: 1.2em;
        }
        .notification-time {
            font-size: 0.8em;
            color: #6c757d;
        }
    </style>
</head>
<body>
    <div class="container mt-4">
        <h2 class="mb-4">Thông báo</h2>
        
        <?php if ($notifications->num_rows > 0): ?>
            <?php while($notification = $notifications->fetch_assoc()): ?>
                <div class="notification-item <?php echo $notification['is_read'] ? '' : 'unread'; ?>">
                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <?php
                            $icon = 'fa-bell';
                            switch($notification['type']) {
                                case 'anniversary':
                                    $icon = 'fa-calendar-check';
                                    break;
                                case 'leave_warning':
                                    $icon = 'fa-exclamation-triangle';
                                    break;
                                case 'salary_warning':
                                    $icon = 'fa-money-bill-wave';
                                    break;
                                case 'salary':
                                    $icon = 'fa-file-invoice-dollar';
                                    break;
                            }
                            ?>
                            <i class="fas <?php echo $icon; ?> notification-icon"></i>
                            <?php echo htmlspecialchars($notification['message']); ?>
                        </div>
                        <div class="d-flex align-items-center">
                            <span class="notification-time me-3">
                                <?php echo date('d/m/Y H:i', strtotime($notification['created_at'])); ?>
                            </span>
                            <?php if (!$notification['is_read']): ?>
                                <form method="POST" class="d-inline">
                                    <input type="hidden" name="notification_id" value="<?php echo $notification['id']; ?>">
                                    <button type="submit" name="mark_read" class="btn btn-sm btn-outline-primary">
                                        <i class="fas fa-check"></i> Đánh dấu đã đọc
                                    </button>
                                </form>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            <?php endwhile; ?>
        <?php else: ?>
            <div class="alert alert-info">
                Không có thông báo mới.
            </div>
        <?php endif; ?>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html> 