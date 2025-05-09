// Role Management Script
class RoleManager {
    constructor() {
        this.roles = {
            'admin': 'Admin',
            'hr_manager': 'HR Manager',
            'payroll_manager': 'Payroll Manager',
            'employee': 'Employee'
        };
        
        this.permissions = {
            'admin': [
                // System-wide permissions
                'system.manage_users',
                'system.manage_roles',
                'system.manage_permissions',
                'system.view_audit_logs',
                'system.manage_settings',
                // HR permissions
                'hr.view_employees',
                'hr.add_employee',
                'hr.edit_employee',
                'hr.delete_employee',
                'hr.view_attendance',
                'hr.manage_departments',
                'hr.manage_positions',
                // Payroll permissions
                'payroll.view_payroll',
                'payroll.manage_payroll',
                'payroll.generate_reports',
                'payroll.view_salary_history',
                // Employee permissions
                'employee.view_own_profile',
                'employee.view_own_salary',
                'employee.view_own_attendance'
            ],
            'hr_manager': [
                // HR permissions
                'hr.view_employees',
                'hr.add_employee',
                'hr.edit_employee',
                'hr.delete_employee',
                'hr.view_attendance',
                'hr.manage_departments',
                'hr.manage_positions',
                // Employee permissions
                'employee.view_own_profile',
                'employee.view_own_salary',
                'employee.view_own_attendance'
            ],
            'payroll_manager': [
                // Payroll permissions
                'payroll.view_payroll',
                'payroll.manage_payroll',
                'payroll.generate_reports',
                'payroll.view_salary_history',
                // Employee permissions
                'employee.view_own_profile',
                'employee.view_own_salary',
                'employee.view_own_attendance'
            ],
            'employee': [
                // Employee permissions
                'employee.view_own_profile',
                'employee.view_own_salary',
                'employee.view_own_attendance'
            ]
        };
    }

    // Get all available roles
    getRoles() {
        return this.roles;
    }

    // Get permissions for a specific role
    getRolePermissions(role) {
        return this.permissions[role] || [];
    }

    // Check if a role has a specific permission
    hasPermission(role, permission) {
        const rolePermissions = this.getRolePermissions(role);
        return rolePermissions.includes('*') || rolePermissions.includes(permission);
    }

    // Assign role to user
    async assignRole(userId, role) {
        try {
            const response = await fetch('/api/assign-role', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${localStorage.getItem('access_token')}`
                },
                body: JSON.stringify({ userId, role })
            });
            
            if (!response.ok) {
                throw new Error('Failed to assign role');
            }
            
            return await response.json();
        } catch (error) {
            console.error('Error assigning role:', error);
            throw error;
        }
    }

    // Remove role from user
    async removeRole(userId, role) {
        try {
            const response = await fetch('/api/remove-role', {
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${localStorage.getItem('access_token')}`
                },
                body: JSON.stringify({ userId, role })
            });
            
            if (!response.ok) {
                throw new Error('Failed to remove role');
            }
            
            return await response.json();
        } catch (error) {
            console.error('Error removing role:', error);
            throw error;
        }
    }

    // Get user's roles
    async getUserRoles(userId) {
        try {
            const response = await fetch(`/api/user-roles/${userId}`, {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('access_token')}`
                }
            });
            
            if (!response.ok) {
                throw new Error('Failed to get user roles');
            }
            
            return await response.json();
        } catch (error) {
            console.error('Error getting user roles:', error);
            throw error;
        }
    }

    // Check if user has specific permission
    async checkUserPermission(userId, permission) {
        try {
            const userRoles = await this.getUserRoles(userId);
            return userRoles.some(role => this.hasPermission(role, permission));
        } catch (error) {
            console.error('Error checking user permission:', error);
            throw error;
        }
    }
}

// Initialize role manager
const roleManager = new RoleManager();

// Export for use in other modules
window.roleManager = roleManager; 