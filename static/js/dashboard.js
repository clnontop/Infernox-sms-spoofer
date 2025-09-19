// Dashboard JavaScript
class Dashboard {
    constructor() {
        this.token = localStorage.getItem('auth_token');
        this.currentUser = null;
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.setupNavigation();
        this.checkAuth();
        this.loadDashboardData();
    }

    setupEventListeners() {
        // SMS Form
        const smsForm = document.getElementById('sms-form');
        if (smsForm) {
            smsForm.addEventListener('submit', (e) => this.handleSMSSubmit(e));
        }

        // Message character counter
        const messageTextarea = document.getElementById('message');
        if (messageTextarea) {
            messageTextarea.addEventListener('input', (e) => this.updateCharCount(e));
        }

        // Refresh buttons
        document.addEventListener('click', (e) => {
            if (e.target.closest('[onclick*="refresh"]')) {
                const action = e.target.closest('button').getAttribute('onclick');
                if (action.includes('refreshProviders')) {
                    this.loadProviders();
                } else if (action.includes('refreshAuditLog')) {
                    this.loadAuditLog();
                }
            }
        });
    }

    setupNavigation() {
        const menuItems = document.querySelectorAll('.menu-item a');
        menuItems.forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                const section = item.getAttribute('data-section');
                this.showSection(section);
                
                // Update active menu item
                document.querySelectorAll('.menu-item').forEach(mi => mi.classList.remove('active'));
                item.parentElement.classList.add('active');
                
                // Update page title
                const title = item.querySelector('span').textContent;
                document.getElementById('page-title').textContent = title;
            });
        });
    }

    showSection(sectionName) {
        // Hide all sections
        document.querySelectorAll('.content-section').forEach(section => {
            section.classList.remove('active');
        });
        
        // Show target section
        const targetSection = document.getElementById(`${sectionName}-section`);
        if (targetSection) {
            targetSection.classList.add('active');
            
            // Load section-specific data
            switch(sectionName) {
                case 'providers':
                    this.loadProviders();
                    break;
                case 'audit':
                    this.loadAuditLog();
                    break;
            }
        }
    }

    async checkAuth() {
        if (!this.token) {
            this.redirectToLogin();
            return;
        }

        // For Netlify deployment, we'll skip the auth check
        // In production, you'd validate the JWT token
        try {
            // Simple token validation
            const tokenParts = this.token.split('.');
            if (tokenParts.length !== 3) {
                throw new Error('Invalid token format');
            }
            // Auth is valid, continue
        } catch (error) {
            console.error('Auth check failed:', error);
            this.redirectToLogin();
        }
    }

    redirectToLogin() {
        window.location.href = '/login';
    }

    async loadDashboardData() {
        try {
            await Promise.all([
                this.loadStats(),
                this.loadProviders(),
                this.loadRecentActivity()
            ]);
        } catch (error) {
            console.error('Failed to load dashboard data:', error);
            this.showToast('Failed to load dashboard data', 'error');
        }
    }

    async loadStats() {
        try {
            // For now, we'll use mock data since we don't have specific stats endpoints
            document.getElementById('total-sms').textContent = '0';
            document.getElementById('success-rate').textContent = '0%';
            document.getElementById('active-providers').textContent = '0';
            document.getElementById('security-events').textContent = '0';
        } catch (error) {
            console.error('Failed to load stats:', error);
        }
    }

    async loadProviders() {
        const providersContainer = document.getElementById('providers-list');
        const providerStatus = document.getElementById('provider-status');
        
        try {
            const response = await this.apiCall('/api/sms/providers', 'GET');
            const data = await response.json();
            
            if (response.ok) {
                this.renderProviders(data, providersContainer);
                this.renderProviderStatus(data, providerStatus);
                
                // Update active providers count
                const activeCount = Object.keys(data.gateways || {}).length;
                document.getElementById('active-providers').textContent = activeCount;
            } else {
                throw new Error(data.error || 'Failed to load providers');
            }
        } catch (error) {
            console.error('Failed to load providers:', error);
            providersContainer.innerHTML = '<p class="no-data">Failed to load providers</p>';
            providerStatus.innerHTML = '<p class="no-data">Failed to load provider status</p>';
        }
    }

    renderProviders(data, container) {
        const providers = data.gateways || {};
        
        if (Object.keys(providers).length === 0) {
            container.innerHTML = '<p class="no-data">No providers configured</p>';
            return;
        }

        const providersHTML = Object.entries(providers).map(([name, info]) => `
            <div class="provider-card">
                <div class="provider-header">
                    <div class="provider-name">${name}</div>
                    <div class="provider-status ${info.configured ? 'status-active' : 'status-inactive'}">
                        ${info.configured ? 'Active' : 'Inactive'}
                    </div>
                </div>
                <div class="provider-features">
                    ${info.supports_spoofing ? '<span class="feature-badge spoofing">Spoofing</span>' : ''}
                    <span class="feature-badge">SMS</span>
                </div>
            </div>
        `).join('');

        container.innerHTML = providersHTML;
    }

    renderProviderStatus(data, container) {
        const providers = data.gateways || {};
        
        if (Object.keys(providers).length === 0) {
            container.innerHTML = '<p class="no-data">No providers configured</p>';
            return;
        }

        const statusHTML = Object.entries(providers).map(([name, info]) => `
            <div class="provider-status-item">
                <span class="provider-name">${name}</span>
                <span class="status-dot ${info.configured ? 'online' : 'offline'}"></span>
            </div>
        `).join('');

        container.innerHTML = statusHTML;
    }

    async loadRecentActivity() {
        const activityContainer = document.getElementById('recent-activity');
        
        try {
            const response = await this.apiCall('/api/audit/records?limit=5', 'GET');
            const data = await response.json();
            
            if (response.ok && data.records && data.records.length > 0) {
                const activityHTML = data.records.map(record => `
                    <div class="activity-item">
                        <div class="activity-content">
                            <div class="activity-title">SMS to ${record.recipient_number}</div>
                            <div class="activity-meta">${new Date(record.timestamp).toLocaleString()}</div>
                        </div>
                        <div class="activity-status ${record.success ? 'success' : 'error'}">
                            ${record.success ? 'Success' : 'Failed'}
                        </div>
                    </div>
                `).join('');
                
                activityContainer.innerHTML = activityHTML;
            } else {
                activityContainer.innerHTML = '<p class="no-data">No recent activity</p>';
            }
        } catch (error) {
            console.error('Failed to load recent activity:', error);
            activityContainer.innerHTML = '<p class="no-data">Failed to load recent activity</p>';
        }
    }

    async loadAuditLog() {
        const auditContainer = document.getElementById('audit-log');
        
        try {
            const response = await this.apiCall('/api/audit/records?limit=50', 'GET');
            const data = await response.json();
            
            if (response.ok && data.records && data.records.length > 0) {
                const tableHTML = `
                    <table class="audit-table">
                        <thead>
                            <tr>
                                <th>Timestamp</th>
                                <th>User</th>
                                <th>Recipient</th>
                                <th>Provider</th>
                                <th>Status</th>
                                <th>Purpose</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${data.records.map(record => `
                                <tr>
                                    <td>${new Date(record.timestamp).toLocaleString()}</td>
                                    <td>${record.user_id}</td>
                                    <td>${record.recipient_number}</td>
                                    <td>${record.provider}</td>
                                    <td>
                                        <span class="badge ${record.success ? 'badge-success' : 'badge-error'}">
                                            ${record.success ? 'Success' : 'Failed'}
                                        </span>
                                    </td>
                                    <td>${record.purpose || 'N/A'}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                `;
                
                auditContainer.innerHTML = tableHTML;
            } else {
                auditContainer.innerHTML = '<p class="no-data">No audit records found</p>';
            }
        } catch (error) {
            console.error('Failed to load audit log:', error);
            auditContainer.innerHTML = '<p class="no-data">Failed to load audit log</p>';
        }
    }

    async handleSMSSubmit(e) {
        e.preventDefault();
        
        const formData = new FormData(e.target);
        const smsData = {
            to: formData.get('recipient'),
            message: formData.get('message'),
            sender_id: formData.get('sender-id') || undefined,
            provider: formData.get('provider') || 'TextBee',
            purpose: formData.get('purpose')
        };

        // Validate consent
        if (!formData.get('consent')) {
            this.showToast('Please confirm consent for authorized testing', 'error');
            return;
        }

        // Real SMS sending via Netlify function
        this.showLoading(true);
        
        try {
            const response = await this.apiCall('/api/sms/send', 'POST', smsData);
            const result = await response.json();
            
            if (response.ok && result.success) {
                this.showSMSResult(result, true);
                this.showToast('SMS sent successfully!', 'success');
                e.target.reset();
                this.updateCharCount({ target: { value: '' } });
                this.loadRecentActivity(); // Refresh activity
            } else {
                this.showSMSResult(result, false);
                this.showToast(result.error || 'Failed to send SMS', 'error');
            }
        } catch (error) {
            console.error('SMS send failed:', error);
            const errorResult = { error: error.message || 'Network error' };
            this.showSMSResult(errorResult, false);
            this.showToast('Failed to send SMS', 'error');
        } finally {
            this.showLoading(false);
        }
    }

    showSMSResult(result, success) {
        const resultContainer = document.getElementById('sms-result');
        
        if (success) {
            resultContainer.innerHTML = `
                <div class="result-success">
                    <h4><i class="fas fa-check-circle"></i> SMS Sent Successfully</h4>
                    <p><strong>Message ID:</strong> ${result.message_id}</p>
                    <p><strong>Provider:</strong> ${result.provider}</p>
                    <p><strong>Timestamp:</strong> ${new Date(result.timestamp).toLocaleString()}</p>
                    <p><strong>Status:</strong> Delivered via TextBee</p>
                    ${result.cost ? `<p><strong>Cost:</strong> $${result.cost}</p>` : ''}
                </div>
            `;
        } else {
            resultContainer.innerHTML = `
                <div class="result-error">
                    <h4><i class="fas fa-exclamation-circle"></i> SMS Failed</h4>
                    <p><strong>Error:</strong> ${result.error}</p>
                    ${result.provider ? `<p><strong>Provider:</strong> ${result.provider}</p>` : ''}
                </div>
            `;
        }
    }

    updateCharCount(e) {
        const charCount = e.target.value.length;
        const counter = document.getElementById('char-count');
        if (counter) {
            counter.textContent = charCount;
            
            // Change color based on limit
            if (charCount > 160) {
                counter.style.color = 'var(--danger-color)';
            } else if (charCount > 140) {
                counter.style.color = 'var(--warning-color)';
            } else {
                counter.style.color = 'var(--text-muted)';
            }
        }
    }

    async apiCall(endpoint, method = 'GET', data = null) {
        const options = {
            method,
            headers: {
                'Content-Type': 'application/json',
            }
        };

        if (this.token) {
            options.headers['Authorization'] = `Bearer ${this.token}`;
        }

        if (data) {
            options.body = JSON.stringify(data);
        }

        return fetch(endpoint, options);
    }

    showLoading(show) {
        const overlay = document.getElementById('loading-overlay');
        if (show) {
            overlay.classList.add('active');
        } else {
            overlay.classList.remove('active');
        }
    }

    showToast(message, type = 'info') {
        const container = document.getElementById('toast-container');
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        
        const icon = {
            success: 'fas fa-check-circle',
            error: 'fas fa-exclamation-circle',
            warning: 'fas fa-exclamation-triangle',
            info: 'fas fa-info-circle'
        }[type];

        toast.innerHTML = `
            <i class="${icon}"></i>
            <span>${message}</span>
        `;

        container.appendChild(toast);

        // Auto remove after 5 seconds
        setTimeout(() => {
            toast.remove();
        }, 5000);
    }

    clearForm() {
        const form = document.getElementById('sms-form');
        if (form) {
            form.reset();
            this.updateCharCount({ target: { value: '' } });
            document.getElementById('sms-result').innerHTML = '<p class="no-data">No SMS sent yet</p>';
        }
    }

    async logout() {
        try {
            await this.apiCall('/api/auth/logout', 'POST');
        } catch (error) {
            console.error('Logout failed:', error);
        } finally {
            localStorage.removeItem('auth_token');
            window.location.href = '/login';
        }
    }
}

// Global functions for onclick handlers
function clearForm() {
    dashboard.clearForm();
}

function refreshProviders() {
    dashboard.loadProviders();
}

function refreshAuditLog() {
    dashboard.loadAuditLog();
}

function logout() {
    dashboard.logout();
}

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.dashboard = new Dashboard();
});

// Auto-login for demo purposes (remove in production)
document.addEventListener('DOMContentLoaded', () => {
    // If no token exists, create a demo token for testing
    if (!localStorage.getItem('auth_token')) {
        // This is just for demo - in production, users must login properly
        localStorage.setItem('auth_token', 'demo-token-for-testing');
    }
});
