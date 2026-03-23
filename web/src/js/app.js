/**
 * Main Application — SPA router and lifecycle management.
 */

const App = {
    currentPage: 'dashboard',
    statusRefreshInterval: null,
    daemonState: 'idle',

    async init() {
        this.navigate('dashboard');
        this.startStatusPolling();
    },

    async navigate(page) {
        this.currentPage = page;

        // Update navbar
        const navbar = document.getElementById('navbar');
        navbar.innerHTML = Navbar.render(page, this.daemonState);

        // Render page content
        const main = document.getElementById('main-content');
        main.innerHTML = `<div class="loading-spinner">
            <i class="fas fa-spinner fa-spin fa-2x"></i><p>Loading...</p>
        </div>`;

        try {
            let html = '';
            switch (page) {
                case 'dashboard':
                    html = await Dashboard.render();
                    break;
                case 'settings':
                    html = await Settings.render();
                    break;
                case 'history':
                    html = await History.render();
                    break;
                default:
                    html = await Dashboard.render();
            }
            main.innerHTML = html;

            // Post-render hooks
            if (page === 'settings' && Settings.afterRender) {
                Settings.afterRender();
            }
        } catch (err) {
            main.innerHTML = `
                <div class="settings-section" style="border-color:var(--danger)">
                    <h2><i class="fas fa-exclamation-triangle" style="color:var(--danger)"></i> Error</h2>
                    <p>Failed to load page: ${err.message}</p>
                    <button class="btn btn-primary btn-sm" onclick="App.navigate('${page}')" style="margin-top:1rem">
                        <i class="fas fa-redo"></i> Retry
                    </button>
                </div>`;
        }
    },

    startStatusPolling() {
        // Poll daemon status every 10 seconds to update navbar badge
        this.statusRefreshInterval = setInterval(async () => {
            try {
                const status = await api.getStatus();
                const newState = status.state || 'idle';

                if (newState !== this.daemonState) {
                    this.daemonState = newState;
                    const navbar = document.getElementById('navbar');
                    navbar.innerHTML = Navbar.render(this.currentPage, this.daemonState);

                    // Auto-refresh dashboard if state changed
                    if (this.currentPage === 'dashboard') {
                        this.navigate('dashboard');
                    }
                }
            } catch (err) {
                this.daemonState = 'error';
                const navbar = document.getElementById('navbar');
                navbar.innerHTML = Navbar.render(this.currentPage, 'error');
            }
        }, 10000);
    },

    stopStatusPolling() {
        if (this.statusRefreshInterval) {
            clearInterval(this.statusRefreshInterval);
        }
    }
};

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', () => App.init());
