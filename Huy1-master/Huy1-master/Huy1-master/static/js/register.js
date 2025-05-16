// Xóa đoạn code này
// window.PerfectScrollbar = function() {
//     return {
//         destroy: function() {},
//         update: function() {}
//     };
// };

// Giữ lại phần code xử lý form
// Xóa event listener cũ
// document.querySelector('form').addEventListener('submit', async function(e) {...

// Di chuyển hàm handleRegister ra ngoài
// Đăng ký sự kiện khi trang đã load xong
// Xóa phần event listener cũ
/*
document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('registerForm');
    if (form) {
        form.addEventListener('submit', handleRegister);
    }
});
*/

// Sửa lại hàm handleRegister
async function handleRegister(event) {
    event.preventDefault();
    console.log('handleRegister called'); // Thêm log này

    const formData = {
        username: document.querySelector('input[name="username"]').value.trim(),
        fullname: document.querySelector('input[name="fullname"]').value.trim(),
        email: document.querySelector('input[name="email"]').value.trim(),
        password: document.getElementById('password').value
    };
    console.log('Form data:', formData); // Thêm log này

    try {
        const response = await fetch('/page-register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': document.querySelector('input[name="csrf_token"]').value
            },
            body: JSON.stringify(formData)
        });
        console.log('Response status:', response.status); // Thêm log này

        const data = await response.json();
        console.log('Response data:', data); // Thêm log này

        if (response.ok) {
            window.location.href = "/page-login";
        } else {
            throw new Error(data.message || 'Đăng ký thất bại');
        }
    } catch (error) {
        console.error('Error:', error); // Thêm log này
        const messageDiv = document.getElementById('message');
        messageDiv.textContent = error.message || 'Có lỗi xảy ra';
        messageDiv.className = 'alert alert-danger show';
    }
}

function showMessage(message, type = 'error') {
    const messageDiv = document.getElementById('message');
    messageDiv.textContent = message;
    messageDiv.className = `alert alert-${type} show`;
    
    // Tự động ẩn thông báo sau 3 giây
    setTimeout(() => {
        messageDiv.className = messageDiv.className.replace('show', '');
    }, 3000);
}
