/**
 * Navigation bar component.
 */

const Navbar = {
    render(activePage = 'dashboard', daemonState = 'idle') {
        return `
        <a href="#" class="nav-brand" onclick="App.navigate('dashboard')">
            <i class="fas fa-shield-alt"></i>
            ISE ACME Manager
        </a>
        <ul class="nav-links">
            <li><a href="#" class="${activePage === 'dashboard' ? 'active' : ''}"
                onclick="App.navigate('dashboard')">
                <i class="fas fa-tachometer-alt"></i> Dashboard
            </a></li>
            <li><a href="#" class="${activePage === 'settings' ? 'active' : ''}"
                onclick="App.navigate('settings')">
                <i class="fas fa-cog"></i> Settings
            </a></li>
            <li><a href="#" class="${activePage === 'history' ? 'active' : ''}"
                onclick="App.navigate('history')">
                <i class="fas fa-history"></i> History
            </a></li>
        </ul>
        <div class="nav-status">
            <span class="status-badge ${daemonState}">
                <span class="status-dot ${daemonState}"></span>
                ${daemonState.toUpperCase()}
            </span>
        </div>`;
    }
};
