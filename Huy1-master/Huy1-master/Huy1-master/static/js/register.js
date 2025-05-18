async function handleRegister(event) {
    event.preventDefault();
    console.log('handleRegister called');

    // Reset thông báo lỗi
    showMessage('', 'none');
    
    // Hiển thị trạng thái loading
    const submitBtn = document.querySelector('button[type="submit"]');
    const originalText = submitBtn.textContent;
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Đang xử lý...';

    // Thu thập dữ liệu từ form
    const formData = {
        username: document.querySelector('input[name="username"]').value.trim(),
        fullname: document.querySelector('input[name="fullname"]').value.trim(),
        email: document.querySelector('input[name="email"]').value.trim(),
        password: document.getElementById('password').value
    };

    // Kiểm tra dữ liệu đầu vào
    if (!validateData(formData)) {
        submitBtn.disabled = false;
        submitBtn.textContent = originalText;
        return;
    }

    try {
        const response = await fetch('/page-register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': document.querySelector('input[name="csrf_token"]').value
            },
            body: JSON.stringify(formData)
        });

        const data = await response.json();
        
        if (response.status === 201) {
            showMessage('Đăng ký thành công! Đang chuyển hướng đến trang đăng nhập...', 'success');
            // Chuyển hướng đến trang đăng nhập sau 2 giây
            setTimeout(() => {
                window.location.href = "/page-login";
            }, 2000);
        } else {
            showMessage(data.message || 'Đăng ký thất bại', 'danger');
            submitBtn.disabled = false;
            submitBtn.textContent = originalText;
        }
    } catch (error) {
        console.error('Error:', error);
        showMessage('Có lỗi xảy ra khi kết nối đến máy chủ, vui lòng thử lại sau', 'danger');
        submitBtn.disabled = false;
        submitBtn.textContent = originalText;
    }
}

function validateData(data) {
    // Kiểm tra username
    if (!data.username || data.username.length < 3) {
        showMessage('Tên đăng nhập phải có ít nhất 3 ký tự', 'danger');
        return false;
    }

    // Kiểm tra fullname
    if (!data.fullname || data.fullname.length < 2) {
        showMessage('Họ và tên không được để trống', 'danger');
        return false;
    }

    // Kiểm tra email
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(data.email)) {
        showMessage('Email không hợp lệ', 'danger');
        return false;
    }

    // Kiểm tra mật khẩu
    if (!data.password || data.password.length < 6) {
        showMessage('Mật khẩu phải có ít nhất 6 ký tự', 'danger');
        return false;
    }

    return true;
}

function showMessage(message, type = 'danger') {
    const messageDiv = document.getElementById('message');
    if (!message) {
        messageDiv.className = 'alert';
        messageDiv.textContent = '';
        return;
    }
    
    messageDiv.textContent = message;
    messageDiv.className = `alert alert-${type} show`;
    
    // Tự động ẩn thông báo lỗi sau 5 giây
    if (type === 'danger') {
        setTimeout(() => {
            messageDiv.className = messageDiv.className.replace('show', '');
        }, 5000);
    }
}

// Thêm sự kiện kiểm tra độ mạnh của mật khẩu
document.addEventListener('DOMContentLoaded', function() {
    const passwordInput = document.getElementById('password');
    if (passwordInput) {
        passwordInput.addEventListener('input', function() {
            const strength = checkPasswordStrength(this.value);
            updatePasswordStrengthIndicator(strength);
        });
    }
});

function checkPasswordStrength(password) {
    if (!password) return 0;
    
    let strength = 0;
    if (password.length >= 6) strength += 1;
    if (password.length >= 8) strength += 1;
    if (/[A-Z]/.test(password)) strength += 1;
    if (/[0-9]/.test(password)) strength += 1;
    if (/[^A-Za-z0-9]/.test(password)) strength += 1;
    
    return Math.min(strength, 5);
}

function updatePasswordStrengthIndicator(strength) {
    const passwordInput = document.getElementById('password');
    
    // Tạo hoặc lấy indicator
    let indicator = document.querySelector('.password-strength');
    if (!indicator) {
        indicator = document.createElement('div');
        indicator.className = 'password-strength';
        passwordInput.parentNode.appendChild(indicator);
    }
    
    // Cập nhật indicator
    const strengthLabels = ['Rất yếu', 'Yếu', 'Trung bình', 'Mạnh', 'Rất mạnh'];
    const strengthColors = ['#dc3545', '#ffc107', '#fd7e14', '#20c997', '#28a745'];
    
    if (strength === 0) {
        indicator.style.display = 'none';
        return;
    }
    
    indicator.style.display = 'block';
    indicator.textContent = strengthLabels[strength - 1];
    indicator.style.color = strengthColors[strength - 1];
}
