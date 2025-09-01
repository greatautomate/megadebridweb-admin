class MedusaXDDebrid {
    constructor() {
        this.currentUser = null;
        this.initializeElements();
        this.bindEvents();
        this.checkAuthStatus();
    }

    initializeElements() {
        // Screens
        this.loginScreen = document.getElementById('loginScreen');
        this.mainScreen = document.getElementById('mainScreen');

        // Forms
        this.loginForm = document.getElementById('loginForm');
        this.debridForm = document.getElementById('debridForm');

        // Inputs
        this.usernameInput = document.getElementById('username');
        this.passwordInput = document.getElementById('password');
        this.linkInput = document.getElementById('linkInput');

        // Buttons
        this.generateBtn = document.getElementById('generateBtn');
        this.logoutBtn = document.getElementById('logoutBtn');
        this.copyBtn = document.getElementById('copyBtn');
        this.historyBtn = document.getElementById('historyBtn');
        this.adminBtn = document.getElementById('adminBtn');

        // Display elements
        this.loading = document.getElementById('loading');
        this.result = document.getElementById('result');
        this.error = document.getElementById('error');
        this.loginError = document.getElementById('loginError');
        this.filename = document.getElementById('filename');
        this.downloadLink = document.getElementById('downloadLink');
        this.welcomeUser = document.getElementById('welcomeUser');
        this.userLimits = document.getElementById('userLimits');

        // Modal elements
        this.historyModal = document.getElementById('historyModal');
        this.closeHistory = document.getElementById('closeHistory');
        this.historyList = document.getElementById('historyList');
    }

    bindEvents() {
        this.loginForm.addEventListener('submit', (e) => this.handleLogin(e));
        this.debridForm.addEventListener('submit', (e) => this.handleDebrid(e));
        this.logoutBtn.addEventListener('click', () => this.handleLogout());
        this.copyBtn.addEventListener('click', () => this.copyToClipboard());
        this.historyBtn.addEventListener('click', () => this.showHistory());
        this.adminBtn.addEventListener('click', () => this.goToAdmin());
        this.closeHistory.addEventListener('click', () => this.closeHistoryModal());

        // Close modal when clicking outside
        this.historyModal.addEventListener('click', (e) => {
            if (e.target === this.historyModal) {
                this.closeHistoryModal();
            }
        });
    }

    async checkAuthStatus() {
        try {
            const response = await fetch('/api/user/status');
            if (response.ok) {
                const data = await response.json();
                this.currentUser = data.user;
                this.showMainScreen();
                this.updateUserInfo();
            } else {
                this.showLoginScreen();
            }
        } catch (error) {
            this.showLoginScreen();
        }
    }

    async handleLogin(e) {
        e.preventDefault();

        const username = this.usernameInput.value.trim();
        const password = this.passwordInput.value;
        this.loginError.style.display = 'none';

        try {
            const response = await fetch('/api/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ username, password })
            });

            const data = await response.json();

            if (response.ok) {
                this.currentUser = data.user;
                this.showMainScreen();
                this.updateUserInfo();
            } else {
                this.showError(data.error, this.loginError);
            }
        } catch (error) {
            this.showError('Connection error. Please try again.', this.loginError);
        }
    }

    async handleDebrid(e) {
        e.preventDefault();

        const link = this.linkInput.value.trim();
        this.hideMessages();
        this.showLoading();

        try {
            const response = await fetch('/api/debrid', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ link })
            });

            const data = await response.json();

            if (response.ok) {
                this.showSuccess(data);
                // Update user limits
                this.currentUser.daily_usage++;
                this.currentUser.remaining--;
                this.updateUserInfo();
            } else {
                this.showError(data.error);
            }
        } catch (error) {
            this.showError('Connection error. Please try again.');
        } finally {
            this.hideLoading();
        }
    }

    async handleLogout() {
        try {
            await fetch('/api/logout', { method: 'POST' });
            this.showLoginScreen();
            this.usernameInput.value = '';
            this.passwordInput.value = '';
            this.currentUser = null;
        } catch (error) {
            console.error('Logout error:', error);
        }
    }

    async showHistory() {
        try {
            const response = await fetch('/api/user/history');
            if (response.ok) {
                const history = await response.json();
                this.displayHistory(history);
                this.historyModal.style.display = 'flex';
            } else {
                this.showError('Failed to load history');
            }
        } catch (error) {
            this.showError('Connection error while loading history');
        }
    }

    displayHistory(history) {
        if (history.length === 0) {
            this.historyList.innerHTML = '<p style="text-align: center; color: #666;">No generation history found.</p>';
            return;
        }

        this.historyList.innerHTML = history.map(item => `
            <div class="history-item">
                <div class="history-details">
                    <h4>${item.filename || 'Unknown file'}</h4>
                    <p><strong>Generated:</strong> ${new Date(item.created_at).toLocaleString()}</p>
                    <p><strong>Source:</strong> ${this.truncateUrl(item.source_link)}</p>
                    <p><strong>IP:</strong> ${item.user_ip}</p>
                </div>
                <a href="${item.generated_link}" target="_blank" class="history-link">Download</a>
            </div>
        `).join('');
    }

    closeHistoryModal() {
        this.historyModal.style.display = 'none';
    }

    goToAdmin() {
        window.location.href = '/admin';
    }

    async copyToClipboard() {
        try {
            const link = this.downloadLink.href;
            await navigator.clipboard.writeText(link);

            const originalText = this.copyBtn.textContent;
            this.copyBtn.textContent = '✅ Copied!';
            this.copyBtn.style.background = 'linear-gradient(135deg, #28a745 0%, #20c997 100%)';

            setTimeout(() => {
                this.copyBtn.textContent = originalText;
                this.copyBtn.style.background = 'linear-gradient(135deg, #17a2b8 0%, #6f42c1 100%)';
            }, 2000);
        } catch (error) {
            console.error('Copy failed:', error);
        }
    }

    showLoginScreen() {
        this.loginScreen.style.display = 'block';
        this.mainScreen.style.display = 'none';
        this.usernameInput.focus();
    }

    showMainScreen() {
        this.loginScreen.style.display = 'none';
        this.mainScreen.style.display = 'block';
        this.linkInput.focus();
    }

    updateUserInfo() {
        if (this.currentUser) {
            this.welcomeUser.textContent = `Welcome, ${this.currentUser.username}!`;
            this.userLimits.textContent = `Daily Usage: ${this.currentUser.daily_usage || 0}/${this.currentUser.daily_limit} (${this.currentUser.remaining || this.currentUser.daily_limit} remaining)`;

            // Show admin button if user is admin
            if (this.currentUser.role === 'admin') {
                this.adminBtn.style.display = 'inline-block';
            } else {
                this.adminBtn.style.display = 'none';
            }
        }
    }

    showLoading() {
        this.loading.style.display = 'block';
        this.generateBtn.disabled = true;
        this.generateBtn.textContent = 'Processing...';
    }

    hideLoading() {
        this.loading.style.display = 'none';
        this.generateBtn.disabled = false;
        this.generateBtn.textContent = 'Generate Premium Link';
    }

    showSuccess(data) {
        this.result.style.display = 'block';
        this.filename.textContent = data.filename;
        this.downloadLink.href = data.downloadLink;
        this.downloadLink.textContent = '📥 Download Now';
    }

    showError(message, element = this.error) {
        element.textContent = message;
        element.style.display = 'block';
    }

    hideMessages() {
        this.result.style.display = 'none';
        this.error.style.display = 'none';
    }

    truncateUrl(url, maxLength = 50) {
        if (url.length <= maxLength) return url;
        return url.substring(0, maxLength) + '...';
    }
}

// Initialize the application
document.addEventListener('DOMContentLoaded', () => {
    new MedusaXDDebrid();
});
