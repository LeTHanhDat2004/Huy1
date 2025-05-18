
async function handleRegister(event) {
    event.preventDefault();
    console.log('handleRegister called');

    const formData = {
        username: document.querySelector('input[name="username"]').value.trim(),
        fullname: document.querySelector('input[name="fullname"]').value.trim(),
        email: document.querySelector('input[name="email"]').value.trim(),
        password: document.getElementById('password').value
    };

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
            showMessage('Đăng ký thành công', 'success');
            setTimeout(() => {
                window.location.href = "/page-login";
            }, 1000);
        } else {
            showMessage(data.message || 'Đăng ký thất bại', 'danger');
        }
    } catch (error) {
        console.error('Error:', error);
        showMessage('Có lỗi xảy ra, vui lòng thử lại sau', 'danger');
    }
}

function showMessage(message, type = 'danger') {
    const messageDiv = document.getElementById('message');
    messageDiv.textContent = message;
    messageDiv.className = `alert alert-${type} show`;
    
    // Tự động ẩn thông báo sau 3 giây nếu là thông báo lỗi
    if (type === 'danger') {
        setTimeout(() => {
            messageDiv.className = messageDiv.className.replace('show', '');
        }, 3000);
    }
}
