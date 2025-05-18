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
            // Thêm log để debug
            console.log('Debug - Request:', {
                url: url,
                token: token,
                headers: options.headers
            });
        }
        
        options.credentials = 'include';
        options.headers['Content-Type'] = 'application/json';
        
        return fetch(url, options)
            .then(response => {
                // Thêm log để debug
                console.log('Debug - Response:', {
                    status: response.status,
                    statusText: response.statusText,
                    url: response.url
                });
                
                if (response.status === 401) {
                    console.error('Auth error details:', {
                        status: response.status,
                        statusText: response.statusText,
                        headers: response.headers,
                        url: response.url
                    });
                    this.setToken(null);
                    this.setRole(null);
                    window.location.href = '/page-login';
                    throw new Error('Unauthorized');
                }
                return response;
            });
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
                this.setToken(data.access_token);
                this.setRole(data.role);
                return true;
            }
            throw new Error(data.message || 'Đăng nhập thất bại');
        })
        .catch(error => {
            console.error('Login error:', error);
            this.showError(error.message);
            return false;
        });
    }
};

// Thêm xử lý chuyển hướng sau đăng nhập
document.addEventListener('DOMContentLoaded', () => {
    if (window.location.pathname === '/') {
        const token = TWS.getToken();
        if (!token) {
            window.location.href = '/page-login';
            return;
        }
        
        TWS.fetch('/')
            .then(response => {
                if (!response.ok) {
                    throw new Error('Unauthorized');
                }
            })
            .catch(() => {
                TWS.setToken(null);
                TWS.setRole(null);
                window.location.href = '/page-login';
            });
    }
});

