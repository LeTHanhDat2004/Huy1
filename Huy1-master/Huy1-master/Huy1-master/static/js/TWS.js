// Đăng nhập và lưu token
async function login(username, password) {
    const response = await fetch('/api/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            username: username,
            password: password
        })
    });
    const data = await response.json();
    if (response.ok) {
        // Lưu token vào localStorage
        localStorage.setItem('access_token', data.access_token);
    }
}

// Gọi API được bảo vệ
async function callProtectedAPI() {
    const token = localStorage.getItem('access_token');
    const response = await fetch('/api/protected', {
        headers: {
            'Authorization': `Bearer ${token}`
        }
    });
    const data = await response.json();
}

// Kiểm tra trạng thái đăng nhập
function isLoggedIn() {
    return localStorage.getItem('access_token') !== null;
}

// Đăng xuất
function logout() {
    localStorage.removeItem('access_token');
    window.location.href = '/login';
}

// Lấy token
function getToken() {
    return localStorage.getItem('access_token');
}

// Thêm token vào header cho mọi request
async function fetchWithAuth(url, options = {}) {
    const token = getToken();
    if (!token) {
        window.location.href = '/login';
        return;
    }

    const headers = {
        ...options.headers,
        'Authorization': `Bearer ${token}`
    };

    try {
        const response = await fetch(url, { ...options, headers });
        if (response.status === 401) {
            // Token hết hạn hoặc không hợp lệ
            logout();
            return;
        }
        return response;
    } catch (error) {
        console.error('Request failed:', error);
        throw error;
    }
}

// Middleware kiểm tra đăng nhập
// Thêm hàm kiểm tra role
function hasRole(role) {
    const userRole = localStorage.getItem('user_role');
    return userRole === role;
}

// Thêm hàm cập nhật UI theo role
function updateUIByRole() {
    const userRole = localStorage.getItem('user_role');
    
    // Ẩn tất cả các section trước
    document.querySelectorAll('.admin-section, .hr-section, .employee-section, .payroll-section')
        .forEach(section => section.style.display = 'none');
    
    // Hiển thị section theo role
    switch(userRole) {
        case 'admin':
            document.querySelectorAll('.admin-section').forEach(section => section.style.display = 'block');
            break;
        case 'hr_manager':
            document.querySelectorAll('.hr-section').forEach(section => section.style.display = 'block');
            break;
        case 'employee':
            document.querySelectorAll('.employee-section').forEach(section => section.style.display = 'block');
            break;
        case 'payroll_manager':
            document.querySelectorAll('.payroll-section').forEach(section => section.style.display = 'block');
            break;
    }
}

// Cập nhật checkAuth để gọi updateUIByRole
function checkAuth() {
    if (!isLoggedIn()) {
        window.location.href = '/login';
        return false;
    }
    if (isLoggedIn()) {
        updateUIByRole();
        return true;
    }
    return false;
}

// Thêm vào các trang cần bảo vệ
document.addEventListener('DOMContentLoaded', function() {
    if (!checkAuth()) return;
    updateUIByRole();
    // Code của trang
});

async function register(username, email, password) {
    const response = await fetch('/api/register', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            username: username,
            email: email,
            password: password
        })
    });
    const data = await response.json();
    return data;
}
