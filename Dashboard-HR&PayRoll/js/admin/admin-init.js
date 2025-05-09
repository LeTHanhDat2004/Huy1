// Admin UI Initialization Script
document.addEventListener('DOMContentLoaded', function() {
    // Initialize role management UI
    initializeRoleManagement();
    
    // Initialize permission management UI
    initializePermissionManagement();
    
    // Initialize role-based UI elements
    initializeRoleBasedUI();
});

// Initialize role management UI
function initializeRoleManagement() {
    // Load roles into the role management table
    loadRolesTable();
    
    // Set up role assignment form
    setupRoleAssignmentForm();
    
    // Set up role removal functionality
    setupRoleRemoval();
}

// Initialize permission management UI
function initializePermissionManagement() {
    // Load permissions into the permission management table
    loadPermissionsTable();
    
    // Set up permission assignment form
    setupPermissionAssignmentForm();
    
    // Set up permission removal functionality
    setupPermissionRemoval();
}

// Initialize role-based UI elements
function initializeRoleBasedUI() {
    // Hide/show UI elements based on user's role
    updateUIForUserRole();
    
    // Set up event listeners for role changes
    setupRoleChangeListeners();
}

// Load roles into the role management table
async function loadRolesTable() {
    try {
        const roles = roleManager.getRoles();
        const tableBody = document.getElementById('rolesTableBody');
        
        if (tableBody) {
            tableBody.innerHTML = '';
            
            for (const [roleKey, roleName] of Object.entries(roles)) {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${roleName}</td>
                    <td>${roleKey}</td>
                    <td>
                        <button class="btn btn-sm btn-primary edit-role" data-role="${roleKey}">
                            <i class="fas fa-edit"></i> Edit
                        </button>
                        <button class="btn btn-sm btn-danger delete-role" data-role="${roleKey}">
                            <i class="fas fa-trash"></i> Delete
                        </button>
                    </td>
                `;
                tableBody.appendChild(row);
            }
        }
    } catch (error) {
        console.error('Error loading roles table:', error);
        showError('Failed to load roles');
    }
}

// Set up role assignment form
function setupRoleAssignmentForm() {
    const form = document.getElementById('assignRoleForm');
    if (form) {
        form.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const userId = form.querySelector('[name="userId"]').value;
            const role = form.querySelector('[name="role"]').value;
            
            try {
                await roleManager.assignRole(userId, role);
                showSuccess('Role assigned successfully');
                loadRolesTable();
            } catch (error) {
                console.error('Error assigning role:', error);
                showError('Failed to assign role');
            }
        });
    }
}

// Set up role removal functionality
function setupRoleRemoval() {
    const table = document.getElementById('rolesTable');
    if (table) {
        table.addEventListener('click', async function(e) {
            if (e.target.closest('.delete-role')) {
                const roleKey = e.target.closest('.delete-role').dataset.role;
                
                if (confirm(`Are you sure you want to delete the role "${roleKey}"?`)) {
                    try {
                        await roleManager.removeRole(userId, roleKey);
                        showSuccess('Role removed successfully');
                        loadRolesTable();
                    } catch (error) {
                        console.error('Error removing role:', error);
                        showError('Failed to remove role');
                    }
                }
            }
        });
    }
}

// Load permissions into the permission management table
async function loadPermissionsTable() {
    try {
        const permissions = permissionManager.getAllPermissions();
        const tableBody = document.getElementById('permissionsTableBody');
        
        if (tableBody) {
            tableBody.innerHTML = '';
            
            for (const [category, categoryPermissions] of Object.entries(permissions)) {
                for (const [permissionKey, permissionName] of Object.entries(categoryPermissions)) {
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${category}</td>
                        <td>${permissionName}</td>
                        <td>${permissionKey}</td>
                        <td>
                            <button class="btn btn-sm btn-primary edit-permission" 
                                    data-category="${category}" 
                                    data-permission="${permissionKey}">
                                <i class="fas fa-edit"></i> Edit
                            </button>
                            <button class="btn btn-sm btn-danger delete-permission" 
                                    data-category="${category}" 
                                    data-permission="${permissionKey}">
                                <i class="fas fa-trash"></i> Delete
                            </button>
                        </td>
                    `;
                    tableBody.appendChild(row);
                }
            }
        }
    } catch (error) {
        console.error('Error loading permissions table:', error);
        showError('Failed to load permissions');
    }
}

// Set up permission assignment form
function setupPermissionAssignmentForm() {
    const form = document.getElementById('assignPermissionForm');
    if (form) {
        form.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const role = form.querySelector('[name="role"]').value;
            const permission = form.querySelector('[name="permission"]').value;
            
            try {
                await permissionManager.assignPermissionToRole(role, permission);
                showSuccess('Permission assigned successfully');
                loadPermissionsTable();
            } catch (error) {
                console.error('Error assigning permission:', error);
                showError('Failed to assign permission');
            }
        });
    }
}

// Set up permission removal functionality
function setupPermissionRemoval() {
    const table = document.getElementById('permissionsTable');
    if (table) {
        table.addEventListener('click', async function(e) {
            if (e.target.closest('.delete-permission')) {
                const button = e.target.closest('.delete-permission');
                const category = button.dataset.category;
                const permissionKey = button.dataset.permission;
                
                if (confirm(`Are you sure you want to delete the permission "${permissionKey}"?`)) {
                    try {
                        await permissionManager.removePermission(category, permissionKey);
                        showSuccess('Permission removed successfully');
                        loadPermissionsTable();
                    } catch (error) {
                        console.error('Error removing permission:', error);
                        showError('Failed to remove permission');
                    }
                }
            }
        });
    }
}

// Update UI based on user's role
async function updateUIForUserRole() {
    try {
        const currentUser = localStorage.getItem('current_user');
        if (!currentUser) return;
        
        const userRoles = await roleManager.getUserRoles(currentUser);
        
        // Hide/show admin sections
        const adminSections = document.querySelectorAll('.admin-section');
        adminSections.forEach(section => {
            section.style.display = userRoles.includes('admin') ? 'block' : 'none';
        });
        
        // Hide/show HR sections
        const hrSections = document.querySelectorAll('.hr-section');
        hrSections.forEach(section => {
            section.style.display = userRoles.includes('hr_manager') ? 'block' : 'none';
        });
        
        // Hide/show payroll sections
        const payrollSections = document.querySelectorAll('.payroll-section');
        payrollSections.forEach(section => {
            section.style.display = userRoles.includes('payroll_manager') ? 'block' : 'none';
        });
        
        // Hide/show employee sections
        const employeeSections = document.querySelectorAll('.employee-section');
        employeeSections.forEach(section => {
            section.style.display = userRoles.includes('employee') ? 'block' : 'none';
        });
    } catch (error) {
        console.error('Error updating UI for user role:', error);
    }
}

// Set up event listeners for role changes
function setupRoleChangeListeners() {
    // Listen for role changes in the system
    document.addEventListener('roleChanged', function() {
        updateUIForUserRole();
    });
}

// Helper function to show success messages
function showSuccess(message) {
    // Implement your success message display logic here
    console.log('Success:', message);
}

// Helper function to show error messages
function showError(message) {
    // Implement your error message display logic here
    console.error('Error:', message);
} 