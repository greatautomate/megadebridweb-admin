class AdminDashboard {
    constructor() {
        this.currentUsers = [];
        this.currentHistory = [];
        this.initializeElements();
        this.bindEvents();
        this.checkAdminAuth();
    }

    initializeElements() {
        this.tabBtns = document.querySelectorAll('.tab-btn');
        this.tabContents = document.querySelectorAll('.tab-content');
        this.addUserBtn = document.getElementById('addUserBtn');
        this.backToMain = document.getElementById('backToMain');
        this.adminLogout = document.getElementById('adminLogout');
        this.refreshHistory = document.getElementById('refreshHistory');

        // Tables
        this.usersTable = document.getElementById('usersTable').getElementsByTagName('tbody')[0];
        this.historyTable = document.getElementById('historyTable').getElementsByTagName('tbody')[0];

        // Modal
        this.userModal = document.getElementById('userModal');
        this.userForm = document.getElementById('userForm');
        this.closeUserModal = document.getElementById('closeUserModal');
        this.cancelUser = document.getElementById('cancelUser');

        // Stats
        this.totalUsers = document.getElementById('totalUsers');
        this.activeUsers = document.getElementById('activeUsers');
        this.totalGenerations = document.getElementById('totalGenerations');
        this.todayUsage = document.getElementById('todayUsage');
    }

    bindEvents() {
        // Tab switching
        this.tabBtns.forEach(btn => {
            btn.addEventListener('click', () => this.switchTab(btn.dataset.tab));
        });

        // Actions
        this.addUserBtn.addEventListener('click', () => this.showAddUserModal());
        this.backToMain.addEventListener('click', () => window.location.href = '/');
        this.adminLogout.addEventListener('click', () => this.logout());
        this.refreshHistory.addEventListener('click', () => this.loadHistory());

        // Modal
        this.closeUserModal.addEventListener('click', () => this.hideUserModal());
        this.cancelUser.addEventListener('click', () => this.hideUserModal());
        this.userForm.addEventListener('submit', (e) => this.handleUserSubmit(e));

        // Close modal when clicking outside
        this.userModal.addEventListener('click', (e) => {
            if (e.target === this.userModal) {
                this.hideUserModal();
            }
        });
    }

    async checkAdminAuth() {
        try {
            const response = await fetch('/api/user/status');
            if (response.ok) {
                const data = await response.json();
                if (data.user.role === 'admin') {
                    this.loadInitialData();
                } else {
                    window.location.href = '/';
                }
            } else {
                window.location.href = '/';
            }
        } catch (error) {
            window.location.href = '/';
        }
    }

    async loadInitialData() {
        await this.loadUsers();
        await this.loadHistory();
        this.updateStats();
    }

    switchTab(tabName) {
        // Update tab buttons
        this.tabBtns.forEach(btn => {
            btn.classList.toggle('active', btn.dataset.tab === tabName);
        });

        // Update tab content
        this.tabContents.forEach(content => {
            content.classList.toggle('active', content.id === tabName + 'Tab');
        });
    }

    async loadUsers() {
        try {
            const response = await fetch('/api/admin/users');
            if (response.ok) {
                this.currentUsers = await response.json();
                this.displayUsers();
            } else {
                this.showError('Failed to load users');
            }
        } catch (error) {
            this.showError('Connection error while loading users');
        }
    }

    displayUsers() {
        this.usersTable.innerHTML = '';

        this.currentUsers.forEach(user => {
            const row = this.usersTable.insertRow();
            row.innerHTML = `
                <td>${user.username}</td>
                <td>${user.email || '-'}</td>
                <td><span class="status-badge ${user.role === 'admin' ? 'status-active' : ''}">${user.role}</span></td>
                <td>${user.daily_limit}</td>
                <td>${user.today_usage || 0}</td>
                <td>${user.total_generations || 0}</td>
                <td><span class="status-badge ${user.is_active ? 'status-active' : 'status-inactive'}">${user.is_active ? 'Active' : 'Disabled'}</span></td>
                <td>
                    <button class="action-btn edit-btn" onclick="adminDashboard.editUser(${user.id})">Edit</button>
                    ${user.role !== 'admin' ? `<button class="action-btn delete-btn" onclick="adminDashboard.deleteUser(${user.id})">Delete</button>` : ''}
                </td>
            `;
        });
    }

    async loadHistory() {
        try {
            const response = await fetch('/api/admin/history');
            if (response.ok) {
                this.currentHistory = await response.json();
                this.displayHistory();
            } else {
                this.showError('Failed to load history');
            }
        } catch (error) {
            this.showError('Connection error while loading history');
        }
    }

    displayHistory() {
        this.historyTable.innerHTML = '';

        this.currentHistory.forEach(item => {
            const row = this.historyTable.insertRow();
            const date = new Date(item.created_at).toLocaleString();
            const sourceDomain = this.extractDomain(item.source_link);

            row.innerHTML = `
                <td>${date}</td>
                <td>${item.username}</td>
                <td>${sourceDomain}</td>
                <td>${item.filename || 'Unknown'}</td>
                <td>${item.user_ip}</td>
            `;
        });
    }

    updateStats() {
        if (this.currentUsers.length === 0) return;

        const activeUsers = this.currentUsers.filter(u => u.is_active).length;
        const totalGens = this.currentUsers.reduce((sum, u) => sum + (u.total_generations || 0), 0);
        const todayGens = this.currentUsers.reduce((sum, u) => sum + (u.today_usage || 0), 0);

        this.totalUsers.textContent = this.currentUsers.length;
        this.activeUsers.textContent = activeUsers;
        this.totalGenerations.textContent = totalGens;
        this.todayUsage.textContent = todayGens;
    }

    showAddUserModal() {
        document.getElementById('modalTitle').textContent = 'Add New User';
        document.getElementById('userId').value = '';
        document.getElementById('modalUsername').value = '';
        document.getElementById('modalPassword').value = '';
        document.getElementById('modalEmail').value = '';
        document.getElementById('modalRole').value = 'user';
        document.getElementById('modalDailyLimit').value = '10';
        document.getElementById('modalStatus').value = '1';
        document.getElementById('modalPassword').required = true;

        this.userModal.style.display = 'flex';
        document.getElementById('modalUsername').focus();
    }

    editUser(userId) {
        const user = this.currentUsers.find(u => u.id === userId);
        if (!user) return;

        document.getElementById('modalTitle').textContent = 'Edit User';
        document.getElementById('userId').value = user.id;
        document.getElementById('modalUsername').value = user.username;
        document.getElementById('modalPassword').value = '';
        document.getElementById('modalEmail').value = user.email || '';
        document.getElementById('modalRole').value = user.role;
        document.getElementById('modalDailyLimit').value = user.daily_limit;
        document.getElementById('modalStatus').value = user.is_active ? '1' : '0';
        document.getElementById('modalPassword').required = false;

        this.userModal.style.display = 'flex';
    }

    async deleteUser(userId) {
        if (!confirm('Are you sure you want to delete this user?')) return;

        try {
            const response = await fetch(`/api/admin/users/${userId}`, {
                method: 'DELETE'
            });

            if (response.ok) {
                await this.loadUsers();
                this.updateStats();
            } else {
                const data = await response.json();
                alert('Error: ' + data.error);
            }
        } catch (error) {
            alert('Connection error while deleting user');
        }
    }

    async handleUserSubmit(e) {
        e.preventDefault();

        const userId = document.getElementById('userId').value;
        const userData = {
            username: document.getElementById('modalUsername').value,
            email: document.getElementById('modalEmail').value,
            role: document.getElementById('modalRole').value,
            daily_limit: parseInt(document.getElementById('modalDailyLimit').value),
            is_active: parseInt(document.getElementById('modalStatus').value)
        };

        const password = document.getElementById('modalPassword').value;
        if (password) {
            userData.password = password;
        }

        try {
            let response;
            if (userId) {
                // Update existing user
                response = await fetch(`/api/admin/users/${userId}`, {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(userData)
                });
            } else {
                // Create new user
                response = await fetch('/api/admin/users', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(userData)
                });
            }

            if (response.ok) {
                this.hideUserModal();
                await this.loadUsers();
                this.updateStats();
            } else {
                const data = await response.json();
                alert('Error: ' + data.error);
            }
        } catch (error) {
            alert('Connection error while saving user');
        }
    }

    hideUserModal() {
        this.userModal.style.display = 'none';
    }

    async logout() {
        try {
            await fetch('/api/logout', { method: 'POST' });
            window.location.href = '/';
        } catch (error) {
            console.error('Logout error:', error);
        }
    }

    extractDomain(url) {
        try {
            return new URL(url).hostname.replace('www.', '');
        } catch {
            return 'Unknown';
        }
    }

    showError(message) {
        alert(message);
    }
}

// Initialize admin dashboard
let adminDashboard;
document.addEventListener('DOMContentLoaded', () => {
    adminDashboard = new AdminDashboard();
});
