// Đăng nhập và lưu token
async function login(username, password) {
    try {
        const csrfToken = document.querySelector('input[name="csrf_token"]').value;
        
        const response = await fetch('/page-login', {  // Đảm bảo endpoint này khớp với route
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
            },
            body: JSON.stringify({
                username: username,
                password: password
            }),
            credentials: 'same-origin'
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.message || 'Đăng nhập thất bại');
        }

        const data = await response.json();
        localStorage.setItem('access_token', data.access_token);
        localStorage.setItem('user_role', data.role);
        window.location.href = '/';
    } catch (error) {
        console.error('Login error:', error);
        const errorDiv = document.createElement('div');
        errorDiv.className = 'alert alert-danger';
        errorDiv.textContent = error.message || 'Đăng nhập thất bại. Vui lòng thử lại.';
        document.querySelector('.auth-form').insertBefore(errorDiv, document.querySelector('form'));
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
    window.location.href = '/page-login';
}

// Lấy token
function getToken() {
    return localStorage.getItem('access_token');
}

// Thêm token vào header cho mọi request
async function fetchWithAuth(url, options = {}) {
    const token = getToken();
    if (!token) {
        // Chỉ throw error, không tự động logout
        throw new Error('No auth token');
    }

    const headers = {
        ...options.headers,
        'Authorization': `Bearer ${token}`
    };

    try {
        const response = await fetch(url, { ...options, headers });
        if (response.status === 401) {
            // Chỉ throw error, không tự động logout
            throw new Error('Unauthorized');
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

// Cập nhật checkAuth để tránh vòng lặp
function checkAuth() {
    // Không kiểm tra trên trang login
    if (window.location.pathname === '/page-login' || window.location.pathname === '/login') {
        return true;
    }
    
    if (!isLoggedIn()) {
        window.location.href = '/page-login';
        return false;
    }
    
    updateUIByRole();
    return true;
}


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
