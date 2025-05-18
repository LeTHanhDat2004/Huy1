// Đơn giản hóa namespace
window.TWS = {
    TOKEN_KEY: 'access_token',
    ROLE_KEY: 'user_role',
    
    showError: function(message) {
        alert(message);
    },
    
    getToken: function() {
        return localStorage.getItem(this.TOKEN_KEY);
    },

    setToken: function(token) {
        if (token) {
            localStorage.setItem(this.TOKEN_KEY, token);
            console.log("Token saved:", token.substring(0, 10) + '...');
            return true;
        }
        return false;
    },

    getRole: function() {
        return localStorage.getItem(this.ROLE_KEY);
    },

    setRole: function(role) {
        if (role) {
            localStorage.setItem(this.ROLE_KEY, role);
            return true;
        }
        return false;
    },
    
    // Thêm hàm fetch có xử lý token
    fetch: function(url, options = {}) {
        const token = this.getToken();
        options.headers = options.headers || {};
        
        if (token) {
            options.headers['Authorization'] = `Bearer ${token}`;
        }
        
        options.headers['Content-Type'] = 'application/json';
        
        return fetch(url, options);
    },
    
    login: function(params) {
        const { username, password, rememberMe, csrfToken } = params;
        
        return fetch('/api/page-login', {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
            },
            body: JSON.stringify({ 
                username, 
                password, 
                remember_me: rememberMe 
            }),
            credentials: 'include'
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Login failed');
            }
            return response.json();
        })
        .then(data => {
            if (data.access_token && data.role) {
                // Log thông tin token trước khi lưu
                console.log("Received token:", data.access_token.substring(0, 10) + '...');
                
                // Lưu token và role
                this.setToken(data.access_token);
                this.setRole(data.role);
                
                // Kiểm tra token đã lưu đúng chưa
                const savedToken = this.getToken();
                console.log("Token was saved:", !!savedToken);
                console.log("Saved token:", savedToken ? savedToken.substring(0, 10) + '...' : 'None');
                
                // Sử dụng goToDashboard để chuyển hướng
                this.goToDashboard();
                
                return data;
            }
            throw new Error(data.message || 'Đăng nhập thất bại');
        })
        .catch(error => {
            console.error('Login error:', error);
            this.showError(error.message);
            throw error; // Re-throw to allow caller to catch it
        });
    },
    
    // Check if user is authenticated
    isAuthenticated: function() {
        return !!this.getToken();
    },
    
    // Logout function
    logout: function() {
        localStorage.removeItem(this.TOKEN_KEY);
        localStorage.removeItem(this.ROLE_KEY);
        window.location.href = '/page-login';
    },
    
    // Truy cập dashboard an toàn - Sửa đổi để sử dụng query parameter
    goToDashboard: function() {
        const token = this.getToken();
        if (!token) {
            console.error("No token found, redirecting to login");
            window.location.href = '/page-login';
            return;
        }
        
        console.log("Redirecting to dashboard with token...");
        
        // Chuyển hướng với token trong query parameter
        try {
            // Thêm timeout để đảm bảo localStorage đã được cập nhật
            setTimeout(() => {
                // Double-check token is still in localStorage
                const finalToken = this.getToken();
                console.log("Final token check before redirect:", finalToken ? finalToken.substring(0, 10) + '...' : 'None');
                
                if (finalToken) {
                    window.location.href = `/dashboard?auth_token=${encodeURIComponent(finalToken)}`;
                } else {
                    console.error("Token missing right before redirect");
                    window.location.href = '/page-login?error=missing_token';
                }
            }, 100);
        } catch (e) {
            console.error("Error in goToDashboard:", e);
            window.location.href = '/page-login?error=redirect_error';
        }
    }
};

// Thêm xử lý toàn cục cho lỗi 401
(function() {
    // Lưu lại hàm fetch gốc
    const originalFetch = window.fetch;
    
    // Ghi đè hàm fetch để bắt lỗi 401
    window.fetch = function(url, options = {}) {
        // Thêm token vào header nếu có
        const token = TWS.getToken();
        if (token) {
            options.headers = options.headers || {};
            options.headers['Authorization'] = `Bearer ${token}`;
            
            // Debug để kiểm tra token
            console.log(`Adding token to request: ${url}`);
        }
        
        return originalFetch(url, options).then(response => {
            if (response.status === 401) {
                console.log('Phát hiện lỗi 401, đang đăng xuất...');
                TWS.logout();
            }
            return response;
        });
    };
    
    // Chặn tất cả các click vào link đến dashboard
    document.addEventListener('DOMContentLoaded', function() {
        document.body.addEventListener('click', function(e) {
            if (e.target.tagName === 'A' && e.target.getAttribute('href') === '/dashboard') {
                e.preventDefault();
                TWS.goToDashboard();
            }
        });
    });
})();

// Thêm xử lý chuyển hướng sau đăng nhập
document.addEventListener('DOMContentLoaded', () => {
    // Fix cho trang chủ
    if (window.location.pathname === '/') {
        const token = TWS.getToken();
        if (!token) {
            window.location.href = '/page-login';
            return;
        }
        
        // Log token presence for debugging
        console.log('Token exists:', !!token);
        console.log('Token first 10 chars:', token ? token.substring(0, 10) + '...' : 'none');
        
        // Sử dụng goToDashboard
        TWS.goToDashboard();
    }
    
    // Nếu đang ở trang dashboard, kiểm tra xác thực
    if (window.location.pathname === '/dashboard') {
        console.log('Đang ở trang dashboard, kiểm tra token...');
        const token = TWS.getToken();
        if (!token) {
            console.log('Không có token, chuyển hướng về trang đăng nhập');
            window.location.href = '/page-login';
        } else {
            console.log('Có token:', token.substring(0, 10) + '...');
        }
    }
});

