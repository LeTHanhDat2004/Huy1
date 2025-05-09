// Permission Management Script
class PermissionManager {
    constructor() {
        this.permissions = {
            // System-wide permissions
            'system': {
                'manage_users': 'Manage Users',
                'manage_roles': 'Manage Roles',
                'manage_permissions': 'Manage Permissions',
                'view_audit_logs': 'View Audit Logs'
            },
            // HR-related permissions
            'hr': {
                'view_employees': 'View Employees',
                'add_employee': 'Add Employee',
                'edit_employee': 'Edit Employee',
                'delete_employee': 'Delete Employee',
                'view_attendance': 'View Attendance',
                'manage_departments': 'Manage Departments',
                'manage_positions': 'Manage Positions'
            },
            // Payroll-related permissions
            'payroll': {
                'view_payroll': 'View Payroll',
                'manage_payroll': 'Manage Payroll',
                'generate_reports': 'Generate Reports',
                'view_salary_history': 'View Salary History'
            },
            // Employee self-service permissions
            'employee': {
                'view_own_profile': 'View Own Profile',
                'view_own_salary': 'View Own Salary',
                'view_own_attendance': 'View Own Attendance'
            }
        };
    }

    // Get all available permissions
    getAllPermissions() {
        return this.permissions;
    }

    // Get permissions by category
    getPermissionsByCategory(category) {
        return this.permissions[category] || {};
    }

    // Add new permission
    async addPermission(category, permissionKey, permissionName) {
        try {
            const response = await fetch('/api/permissions', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${localStorage.getItem('access_token')}`
                },
                body: JSON.stringify({
                    category,
                    permissionKey,
                    permissionName
                })
            });
            
            if (!response.ok) {
                throw new Error('Failed to add permission');
            }
            
            return await response.json();
        } catch (error) {
            console.error('Error adding permission:', error);
            throw error;
        }
    }

    // Remove permission
    async removePermission(category, permissionKey) {
        try {
            const response = await fetch(`/api/permissions/${category}/${permissionKey}`, {
                method: 'DELETE',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('access_token')}`
                }
            });
            
            if (!response.ok) {
                throw new Error('Failed to remove permission');
            }
            
            return await response.json();
        } catch (error) {
            console.error('Error removing permission:', error);
            throw error;
        }
    }

    // Assign permission to role
    async assignPermissionToRole(role, permission) {
        try {
            const response = await fetch('/api/role-permissions', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${localStorage.getItem('access_token')}`
                },
                body: JSON.stringify({ role, permission })
            });
            
            if (!response.ok) {
                throw new Error('Failed to assign permission to role');
            }
            
            return await response.json();
        } catch (error) {
            console.error('Error assigning permission to role:', error);
            throw error;
        }
    }

    // Remove permission from role
    async removePermissionFromRole(role, permission) {
        try {
            const response = await fetch(`/api/role-permissions/${role}/${permission}`, {
                method: 'DELETE',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('access_token')}`
                }
            });
            
            if (!response.ok) {
                throw new Error('Failed to remove permission from role');
            }
            
            return await response.json();
        } catch (error) {
            console.error('Error removing permission from role:', error);
            throw error;
        }
    }

    // Get role's permissions
    async getRolePermissions(role) {
        try {
            const response = await fetch(`/api/role-permissions/${role}`, {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('access_token')}`
                }
            });
            
            if (!response.ok) {
                throw new Error('Failed to get role permissions');
            }
            
            return await response.json();
        } catch (error) {
            console.error('Error getting role permissions:', error);
            throw error;
        }
    }
}

// Initialize permission manager
const permissionManager = new PermissionManager();

// Export for use in other modules
window.permissionManager = permissionManager; 