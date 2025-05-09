// Role-Based Access Control Utility
class AccessControl {
    constructor() {
        this.currentUser = null;
        this.currentRoles = [];
    }

    // Initialize access control
    async initialize() {
        try {
            this.currentUser = localStorage.getItem('current_user');
            if (this.currentUser) {
                this.currentRoles = await roleManager.getUserRoles(this.currentUser);
            }
        } catch (error) {
            console.error('Error initializing access control:', error);
        }
    }

    // Check if current user has a specific role
    hasRole(role) {
        return this.currentRoles.includes(role);
    }

    // Check if current user has any of the specified roles
    hasAnyRole(roles) {
        return roles.some(role => this.hasRole(role));
    }

    // Check if current user has all of the specified roles
    hasAllRoles(roles) {
        return roles.every(role => this.hasRole(role));
    }

    // Check if current user has a specific permission
    async hasPermission(permission) {
        try {
            return await roleManager.checkUserPermission(this.currentUser, permission);
        } catch (error) {
            console.error('Error checking permission:', error);
            return false;
        }
    }

    // Check if current user has any of the specified permissions
    async hasAnyPermission(permissions) {
        for (const permission of permissions) {
            if (await this.hasPermission(permission)) {
                return true;
            }
        }
        return false;
    }

    // Check if current user has all of the specified permissions
    async hasAllPermissions(permissions) {
        for (const permission of permissions) {
            if (!(await this.hasPermission(permission))) {
                return false;
            }
        }
        return true;
    }

    // Protect a route based on role requirements
    async protectRoute(requiredRole, redirectPath = '/login') {
        if (!this.hasRole(requiredRole)) {
            window.location.href = redirectPath;
            return false;
        }
        return true;
    }

    // Protect a route based on permission requirements
    async protectRouteByPermission(requiredPermission, redirectPath = '/login') {
        if (!(await this.hasPermission(requiredPermission))) {
            window.location.href = redirectPath;
            return false;
        }
        return true;
    }

    // Show/hide elements based on role
    updateElementsByRole() {
        // Admin elements
        const adminElements = document.querySelectorAll('[data-role="admin"]');
        adminElements.forEach(element => {
            element.style.display = this.hasRole('admin') ? 'block' : 'none';
        });

        // HR Manager elements
        const hrElements = document.querySelectorAll('[data-role="hr_manager"]');
        hrElements.forEach(element => {
            element.style.display = this.hasRole('hr_manager') ? 'block' : 'none';
        });

        // Payroll Manager elements
        const payrollElements = document.querySelectorAll('[data-role="payroll_manager"]');
        payrollElements.forEach(element => {
            element.style.display = this.hasRole('payroll_manager') ? 'block' : 'none';
        });

        // Employee elements
        const employeeElements = document.querySelectorAll('[data-role="employee"]');
        employeeElements.forEach(element => {
            element.style.display = this.hasRole('employee') ? 'block' : 'none';
        });
    }

    // Show/hide elements based on permission
    async updateElementsByPermission() {
        // System permissions
        const systemElements = document.querySelectorAll('[data-permission^="system."]');
        for (const element of systemElements) {
            const permission = element.dataset.permission;
            element.style.display = await this.hasPermission(permission) ? 'block' : 'none';
        }

        // HR permissions
        const hrElements = document.querySelectorAll('[data-permission^="hr."]');
        for (const element of hrElements) {
            const permission = element.dataset.permission;
            element.style.display = await this.hasPermission(permission) ? 'block' : 'none';
        }

        // Payroll permissions
        const payrollElements = document.querySelectorAll('[data-permission^="payroll."]');
        for (const element of payrollElements) {
            const permission = element.dataset.permission;
            element.style.display = await this.hasPermission(permission) ? 'block' : 'none';
        }

        // Employee permissions
        const employeeElements = document.querySelectorAll('[data-permission^="employee."]');
        for (const element of employeeElements) {
            const permission = element.dataset.permission;
            element.style.display = await this.hasPermission(permission) ? 'block' : 'none';
        }
    }

    // Update UI based on current user's roles and permissions
    async updateUI() {
        this.updateElementsByRole();
        await this.updateElementsByPermission();
    }

    // Listen for role changes
    setupRoleChangeListener() {
        document.addEventListener('roleChanged', () => {
            this.updateUI();
        });
    }

    // Check if user can access HR data
    async canAccessHRData() {
        return this.hasRole('admin') || this.hasRole('hr_manager');
    }

    // Check if user can access Payroll data
    async canAccessPayrollData() {
        return this.hasRole('admin') || this.hasRole('payroll_manager');
    }

    // Check if user can access Employee data
    async canAccessEmployeeData(employeeId) {
        // Admin can access all employee data
        if (this.hasRole('admin')) return true;
        
        // HR Manager can access all employee data
        if (this.hasRole('hr_manager')) return true;
        
        // Payroll Manager can access all employee data
        if (this.hasRole('payroll_manager')) return true;
        
        // Employee can only access their own data
        return this.currentUser === employeeId;
    }
}

// Initialize access control
const accessControl = new AccessControl();

// Export for use in other modules
window.accessControl = accessControl;

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', async () => {
    await accessControl.initialize();
    await accessControl.updateUI();
    accessControl.setupRoleChangeListener();
}); 