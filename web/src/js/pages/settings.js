/**
 * Settings page — sidebar-navigated layout with 7 sections.
 */

const Settings = {
    currentSettings: {},
    _activeSection: 'ise',
    _discoveredNodes: [],

    _sections: [
        { id: 'ise',           icon: 'fa-server',    label: 'ISE Connector'    },
        { id: 'acme',          icon: 'fa-certificate', label: 'ACME Providers'  },
        { id: 'certificates',  icon: 'fa-lock',      label: 'Certificates'     },
        { id: 'dns',           icon: 'fa-globe',     label: 'DNS Providers'    },
        { id: 'notifications', icon: 'fa-envelope',  label: 'Notifications'    },
        { id: 'scheduler',     icon: 'fa-clock',     label: 'Scheduler'        },
        { id: 'system',        icon: 'fa-sliders-h', label: 'System Settings'  },
    ],

    async render() {
        try {
            this.currentSettings = await api.getSettings();
            const s = this.currentSettings;

            const sidebarItems = this._sections.map(sec => `
                <li class="settings-nav__item">
                    <a href="#" data-section="${sec.id}" onclick="Settings.showSection('${sec.id}'); return false;">
                        <i class="fas ${sec.icon}"></i> ${sec.label}
                    </a>
                </li>`).join('');

            return `
            <div class="page-header">
                <h1><i class="fas fa-cog"></i> Settings</h1>
            </div>
            <div class="settings-layout">
                <aside class="settings-sidebar" id="settings-sidebar">
                    <div class="settings-sidebar__title">Configuration</div>
                    <button class="settings-sidebar__toggle" onclick="Settings.toggleMobileMenu()">
                        <i class="fas fa-bars"></i> Menu
                    </button>
                    <ul class="settings-nav" id="settings-nav">${sidebarItems}</ul>
                </aside>
                <div class="settings-content">
                    ${this.renderISESection(s)}
                    ${this.renderACMESection(s)}
                    ${this.renderCertificatesSection(s)}
                    ${this.renderDNSSection(s)}
                    ${this.renderNotificationsSection(s)}
                    ${this.renderSchedulerSection(s)}
                    ${this.renderSystemSection(s)}
                </div>
            </div>`;
        } catch (err) {
            return `<div class="settings-section" style="border-color:var(--danger)">
                <h2><i class="fas fa-exclamation-triangle" style="color:var(--danger)"></i> Error</h2>
                <p>Failed to load settings: ${err.message}</p>
            </div>`;
        }
    },

    afterRender() {
        this.showSection(this._activeSection || 'ise');
        this.toggleACMEFields();
        this.toggleDNSFields();
        this.loadNodes();
        this.loadManagedCerts();
    },

    showSection(id) {
        this._activeSection = id;
        document.querySelectorAll('.settings-panel').forEach(p => p.classList.remove('active'));
        document.querySelectorAll('.settings-nav__item a').forEach(a => a.classList.remove('active'));
        const panel = document.getElementById(`panel-${id}`);
        if (panel) panel.classList.add('active');
        const link = document.querySelector(`.settings-nav__item a[data-section="${id}"]`);
        if (link) link.classList.add('active');
        // Close mobile menu on selection
        const sidebar = document.getElementById('settings-sidebar');
        if (sidebar) sidebar.classList.remove('open');
    },

    toggleMobileMenu() {
        const sidebar = document.getElementById('settings-sidebar');
        if (sidebar) sidebar.classList.toggle('open');
    },

    // ── Section Renderers ──

    renderISESection(s) {
        return `
        <div id="panel-ise" class="settings-panel">
            <div class="settings-section">
                <h2><i class="fas fa-server"></i> ISE Connection</h2>
                <div class="form-grid">
                    <div class="form-group">
                        <label>ISE PAN Hostname</label>
                        <input id="ise_host" value="${s.ise?.ise_host || ''}" placeholder="ise-pan.yourdomain.com">
                    </div>
                    <div class="form-group">
                        <label>Username</label>
                        <input id="ise_username" value="${s.ise?.ise_username || ''}" placeholder="admin">
                    </div>
                    <div class="form-group">
                        <label>Password</label>
                        <input id="ise_password" type="password" value="" placeholder="Enter password">
                    </div>
                    <div class="form-group">
                        <label>ERS Port</label>
                        <input id="ise_ers_port" type="number" value="${s.ise?.ise_ers_port || 9060}">
                    </div>
                    <div class="form-group">
                        <label>Open API Port</label>
                        <input id="ise_open_api_port" type="number" value="${s.ise?.ise_open_api_port || 443}">
                    </div>
                </div>
                <div class="btn-group">
                    <button class="btn btn-primary btn-sm" onclick="Settings.saveISE()">
                        <i class="fas fa-save"></i> Save ISE Settings
                    </button>
                    <button class="btn btn-outline btn-sm" onclick="Settings.testISE()">
                        <i class="fas fa-plug"></i> Test Open API
                    </button>
                    <button class="btn btn-outline btn-sm" onclick="Settings.testERS()">
                        <i class="fas fa-plug"></i> Test ERS
                    </button>
                </div>
            </div>

            <!-- ISE Nodes -->
            <div class="settings-section">
                <h2><i class="fas fa-network-wired"></i> ISE Nodes</h2>
                <div class="btn-group" style="margin-bottom:1rem">
                    <button class="btn btn-primary btn-sm" onclick="Settings.discoverNodes()">
                        <i class="fas fa-search"></i> Discover Nodes via ERS
                    </button>
                </div>
                <div id="discovery-results" style="display:none; margin-bottom:1rem; border:1px solid var(--border); border-radius:8px; padding:1rem">
                    <h3 style="margin-top:0"><i class="fas fa-satellite-dish"></i> Discovered Nodes</h3>
                    <table id="discovery-table"></table>
                    <div class="btn-group" style="margin-top:0.75rem">
                        <button class="btn btn-success btn-sm" onclick="Settings.syncDiscoveredNodes()">
                            <i class="fas fa-sync"></i> Sync Selected Nodes
                        </button>
                        <button class="btn btn-outline btn-sm" onclick="document.getElementById('discovery-results').style.display='none'">
                            <i class="fas fa-times"></i> Dismiss
                        </button>
                    </div>
                </div>
                <div id="nodes-list"></div>
                <details style="margin-top:1rem; border-top:1px solid var(--border); padding-top:1rem">
                    <summary style="cursor:pointer; color:var(--text-muted); font-size:0.9rem"><i class="fas fa-plus-circle"></i> Manual Node Entry</summary>
                    <div class="form-grid" style="margin-top:0.75rem">
                        <div class="form-group">
                            <label>Node Hostname (FQDN)</label>
                            <input id="new_node_name" placeholder="ise-psn01.yourdomain.com">
                        </div>
                        <div class="form-group">
                            <label>Role</label>
                            <select id="new_node_role">
                                <option value="PSN">PSN</option>
                                <option value="PAN">PAN</option>
                                <option value="MnT">MnT</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label>Primary Node?</label>
                            <select id="new_node_primary">
                                <option value="false">No</option>
                                <option value="true">Yes</option>
                            </select>
                        </div>
                    </div>
                    <div class="btn-group">
                        <button class="btn btn-success btn-sm" onclick="Settings.addNode()">
                            <i class="fas fa-plus"></i> Add Node
                        </button>
                    </div>
                </details>
            </div>
        </div>`;
    },

    renderACMESection(s) {
        const provider = s.acme?.acme_provider || 'digicert';
        return `
        <div id="panel-acme" class="settings-panel">
            <div class="settings-section">
                <h2><i class="fas fa-certificate"></i> ACME Provider</h2>
                <div class="form-grid">
                    <div class="form-group">
                        <label>Provider</label>
                        <select id="acme_provider" onchange="Settings.toggleACMEFields()">
                            <option value="digicert" ${provider === 'digicert' ? 'selected' : ''}>DigiCert</option>
                            <option value="letsencrypt" ${provider === 'letsencrypt' ? 'selected' : ''}>Let's Encrypt</option>
                        </select>
                    </div>
                    <div class="form-group acme-field acme-digicert" style="grid-column: span 2">
                        <label>ACME Directory URL</label>
                        <input id="acme_directory_url" value="${s.acme?.acme_directory_url || 'https://acme.digicert.com/v2/acme/directory/'}">
                    </div>
                    <div class="form-group acme-field acme-digicert">
                        <label>Key ID (KID)</label>
                        <input id="acme_kid" type="password" value="" placeholder="Enter KID">
                    </div>
                    <div class="form-group acme-field acme-digicert">
                        <label>HMAC Key</label>
                        <input id="acme_hmac_key" type="password" value="" placeholder="Enter HMAC key">
                    </div>
                    <div class="form-group acme-field acme-letsencrypt" style="display:none">
                        <label>Account Email</label>
                        <input id="acme_account_email" value="${s.acme?.acme_account_email || ''}" placeholder="admin@yourdomain.com">
                    </div>
                    <div class="form-group acme-field acme-letsencrypt" style="display:none; grid-column: span 2">
                        <label>ACME Directory URL</label>
                        <input id="acme_directory_url_le" value="${provider === 'letsencrypt' ? (s.acme?.acme_directory_url || 'https://acme-api.letsencrypt.org/directory') : 'https://acme-api.letsencrypt.org/directory'}">
                        <small style="color:var(--text-muted); font-size:0.75rem; margin-top:4px; display:block">Use https://acme-staging-v02.api.letsencrypt.org/directory for testing</small>
                    </div>
                </div>
                <div class="btn-group">
                    <button class="btn btn-primary btn-sm" onclick="Settings.saveACME()">
                        <i class="fas fa-save"></i> Save ACME Settings
                    </button>
                </div>
            </div>
        </div>`;
    },

    renderCertificatesSection(s) {
        return `
        <div id="panel-certificates" class="settings-panel">
            <div class="settings-section">
                <h2><i class="fas fa-lock"></i> Certificates</h2>

                <!-- ISE Certificate Discovery -->
                <div style="margin-bottom:1.5rem">
                    <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:0.75rem">
                        <h3 style="font-size:0.95rem; color:var(--text-muted)">Discovered ISE Certificates</h3>
                        <button class="btn btn-outline btn-sm" onclick="Settings.fetchISECertificates()">
                            <i class="fas fa-sync-alt"></i> Fetch from ISE
                        </button>
                    </div>
                    <div id="ise-certs-table">
                        <p style="color:var(--text-muted); font-size:0.875rem">Click "Fetch from ISE" to load available certificates.</p>
                    </div>
                </div>

                <!-- Managed Certificates -->
                <div>
                    <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:0.75rem">
                        <h3 style="font-size:0.95rem; color:var(--text-muted)">Managed Certificates (Auto-Renew)</h3>
                        <button class="btn btn-primary btn-sm" onclick="Settings.showCertForm()">
                            <i class="fas fa-plus"></i> Add Certificate
                        </button>
                    </div>
                    <div id="managed-certs-table">
                        <p style="color:var(--text-muted); font-size:0.875rem">Loading...</p>
                    </div>
                </div>

                <!-- Add/Edit Form (hidden by default) -->
                <div id="cert-form-panel" style="display:none; margin-top:1.5rem; border-top:1px solid var(--border); padding-top:1.25rem">
                    <h3 style="font-size:0.95rem; margin-bottom:1rem" id="cert-form-title">Add Certificate</h3>
                    <input type="hidden" id="cert-form-id">
                    <div class="form-grid">
                        <div class="form-group">
                            <label>Common Name</label>
                            <input id="cert-cn" placeholder="guest.yourdomain.com">
                        </div>
                        <div class="form-group">
                            <label>SAN Names (comma-separated)</label>
                            <input id="cert-san" placeholder="guest.yourdomain.com,portal.yourdomain.com">
                        </div>
                        <div class="form-group">
                            <label>Key Type</label>
                            <select id="cert-key-type">
                                <option value="RSA_2048">RSA 2048</option>
                                <option value="RSA_4096">RSA 4096</option>
                                <option value="ECDSA_256">ECDSA 256</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label>Certificate Mode</label>
                            <select id="cert-mode">
                                <option value="shared">Shared (one cert for all nodes)</option>
                                <option value="per-node">Per-Node (independent certs)</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label>Portal Group Tag</label>
                            <input id="cert-portal-tag" value="Default Portal Certificate Group">
                        </div>
                        <div class="form-group">
                            <label>Renewal Threshold (days)</label>
                            <input id="cert-threshold" type="number" value="30" min="1" max="365">
                        </div>
                        <div class="form-group">
                            <label>Enabled</label>
                            <select id="cert-enabled">
                                <option value="true">Yes</option>
                                <option value="false">No</option>
                            </select>
                        </div>
                        <div class="form-group" style="grid-column: span 2">
                            <label>Assign to ISE Nodes</label>
                            <div id="cert-node-checkboxes" style="display:flex; flex-wrap:wrap; gap:0.75rem; padding:0.5rem 0">
                                <span style="color:var(--text-muted); font-size:0.875rem">Loading nodes...</span>
                            </div>
                        </div>
                    </div>
                    <div class="btn-group">
                        <button class="btn btn-primary btn-sm" onclick="Settings.saveManagedCert()">
                            <i class="fas fa-save"></i> Save Certificate
                        </button>
                        <button class="btn btn-outline btn-sm" onclick="Settings.hideCertForm()">
                            <i class="fas fa-times"></i> Cancel
                        </button>
                    </div>
                </div>
            </div>
        </div>`;
    },

    renderDNSSection(s) {
        return `
        <div id="panel-dns" class="settings-panel">
            <div class="settings-section">
                <h2><i class="fas fa-globe"></i> DNS Provider</h2>
                <div class="form-grid">
                    <div class="form-group">
                        <label>Provider</label>
                        <select id="dns_provider" onchange="Settings.toggleDNSFields()">
                            <option value="cloudflare" ${s.dns?.dns_provider === 'cloudflare' ? 'selected' : ''}>Cloudflare</option>
                            <option value="aws_route53" ${s.dns?.dns_provider === 'aws_route53' ? 'selected' : ''}>AWS Route53</option>
                            <option value="azure_dns" ${s.dns?.dns_provider === 'azure_dns' ? 'selected' : ''}>Azure DNS</option>
                        </select>
                    </div>
                    <div class="form-group dns-field dns-cloudflare">
                        <label>Cloudflare API Token</label>
                        <input id="cloudflare_api_token" type="password" placeholder="Enter token">
                    </div>
                    <div class="form-group dns-field dns-cloudflare">
                        <label>Cloudflare Zone ID</label>
                        <input id="cloudflare_zone_id" value="${s.dns?.cloudflare_zone_id || ''}">
                    </div>
                    <div class="form-group dns-field dns-aws_route53" style="display:none">
                        <label>Hosted Zone ID</label>
                        <input id="aws_hosted_zone_id" value="${s.dns?.aws_hosted_zone_id || ''}">
                    </div>
                    <div class="form-group dns-field dns-aws_route53" style="display:none">
                        <label>AWS Region</label>
                        <input id="aws_region" value="${s.dns?.aws_region || 'us-east-1'}">
                    </div>
                    <div class="form-group dns-field dns-azure_dns" style="display:none">
                        <label>Subscription ID</label>
                        <input id="azure_subscription_id" value="${s.dns?.azure_subscription_id || ''}">
                    </div>
                    <div class="form-group dns-field dns-azure_dns" style="display:none">
                        <label>Resource Group</label>
                        <input id="azure_resource_group" value="${s.dns?.azure_resource_group || ''}">
                    </div>
                    <div class="form-group dns-field dns-azure_dns" style="display:none">
                        <label>DNS Zone Name</label>
                        <input id="azure_dns_zone_name" value="${s.dns?.azure_dns_zone_name || ''}">
                    </div>
                </div>
                <div class="btn-group">
                    <button class="btn btn-primary btn-sm" onclick="Settings.saveDNS()">
                        <i class="fas fa-save"></i> Save DNS Settings
                    </button>
                    <button class="btn btn-outline btn-sm" onclick="Settings.testDNS()">
                        <i class="fas fa-plug"></i> Test Connection
                    </button>
                </div>
            </div>
        </div>`;
    },

    renderNotificationsSection(s) {
        return `
        <div id="panel-notifications" class="settings-panel">
            <div class="settings-section">
                <h2><i class="fas fa-envelope"></i> Email Notifications</h2>
                <div class="form-grid">
                    <div class="form-group">
                        <label>SMTP Server</label>
                        <input id="smtp_server" value="${s.smtp?.smtp_server || ''}" placeholder="smtp.yourdomain.com">
                    </div>
                    <div class="form-group">
                        <label>SMTP Port</label>
                        <input id="smtp_port" type="number" value="${s.smtp?.smtp_port || 587}">
                    </div>
                    <div class="form-group">
                        <label>SMTP Username</label>
                        <input id="smtp_username" value="${s.smtp?.smtp_username || ''}" placeholder="alerts@yourdomain.com">
                    </div>
                    <div class="form-group">
                        <label>SMTP Password</label>
                        <input id="smtp_password" type="password" placeholder="Enter password">
                    </div>
                    <div class="form-group" style="grid-column: span 2">
                        <label>Alert Recipients (comma-separated)</label>
                        <input id="alert_recipients" value="${(s.smtp?.alert_recipients || []).join(',')}" placeholder="admin@yourdomain.com,noc@yourdomain.com">
                    </div>
                </div>
                <div class="btn-group">
                    <button class="btn btn-primary btn-sm" onclick="Settings.saveSMTP()">
                        <i class="fas fa-save"></i> Save SMTP Settings
                    </button>
                </div>
            </div>
        </div>`;
    },

    renderSchedulerSection(s) {
        return `
        <div id="panel-scheduler" class="settings-panel">
            <div class="settings-section">
                <h2><i class="fas fa-clock"></i> Scheduler</h2>
                <div class="form-grid">
                    <div class="form-group">
                        <label>Enable Scheduler</label>
                        <select id="scheduler_enabled">
                            <option value="true" ${s.scheduler?.scheduler_enabled ? 'selected' : ''}>Enabled</option>
                            <option value="false" ${!s.scheduler?.scheduler_enabled ? 'selected' : ''}>Disabled</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Run at Hour (0-23)</label>
                        <input id="scheduler_cron_hour" type="number" value="${s.scheduler?.scheduler_cron_hour ?? 2}" min="0" max="23">
                    </div>
                    <div class="form-group">
                        <label>Run at Minute (0-59)</label>
                        <input id="scheduler_cron_minute" type="number" value="${s.scheduler?.scheduler_cron_minute ?? 0}" min="0" max="59">
                    </div>
                    <div class="form-group">
                        <label>Interval (hours)</label>
                        <input id="scheduler_interval_hours" type="number" value="${s.scheduler?.scheduler_interval_hours || 24}" min="1" max="168">
                    </div>
                </div>
                <div class="btn-group">
                    <button class="btn btn-primary btn-sm" onclick="Settings.saveScheduler()">
                        <i class="fas fa-save"></i> Save Scheduler Settings
                    </button>
                </div>
            </div>
        </div>`;
    },

    renderSystemSection(s) {
        return `
        <div id="panel-system" class="settings-panel">
            <div class="settings-section">
                <h2><i class="fas fa-sliders-h"></i> System Settings</h2>
                <div class="form-grid">
                    <div class="form-group">
                        <label>Custom DNS Server <small style="color:var(--text-muted)">(optional — for resolving ISE FQDN)</small></label>
                        <input id="ise_dns_server" value="${s.ise?.ise_dns_server || ''}" placeholder="e.g. 192.168.1.53 (leave empty for system default)">
                    </div>
                </div>
                <div class="btn-group">
                    <button class="btn btn-primary btn-sm" onclick="Settings.saveSystem()">
                        <i class="fas fa-save"></i> Save System Settings
                    </button>
                </div>
            </div>
        </div>`;
    },

    // ── DNS field toggling ──

    toggleACMEFields() {
        const provider = document.getElementById('acme_provider')?.value;
        document.querySelectorAll('.acme-field').forEach(el => el.style.display = 'none');
        document.querySelectorAll(`.acme-${provider}`).forEach(el => el.style.display = 'flex');
    },

    toggleDNSFields() {
        const provider = document.getElementById('dns_provider')?.value;
        document.querySelectorAll('.dns-field').forEach(el => el.style.display = 'none');
        document.querySelectorAll(`.dns-${provider}`).forEach(el => el.style.display = 'flex');
    },

    // ── Node list ──

    async loadNodes() {
        try {
            const nodes = await api.getNodes();
            const container = document.getElementById('nodes-list');
            if (!container) return;

            if (nodes.length === 0) {
                container.innerHTML = '<p style="color:var(--text-muted);padding:1rem 0">No nodes configured yet.</p>';
                return;
            }

            container.innerHTML = `
                <table>
                    <thead>
                        <tr>
                            <th>Hostname</th>
                            <th>Role</th>
                            <th>Primary</th>
                            <th>Status</th>
                            <th>Days Remaining</th>
                            <th>Enabled</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${nodes.map(node => `
                        <tr>
                            <td><strong>${node.name}</strong></td>
                            <td><span class="badge info">${node.role}</span></td>
                            <td>${node.is_primary ? '<span class="badge success">PRIMARY</span>' : '—'}</td>
                            <td><span class="badge ${node.cert_status === 'ok' ? 'success' : node.cert_status === 'expiring' ? 'warning' : 'neutral'}">${node.cert_status}</span></td>
                            <td>${node.cert_days_remaining !== null ? node.cert_days_remaining + ' days' : '—'}</td>
                            <td>${node.enabled ? '✅' : '❌'}</td>
                            <td>
                                <button class="btn btn-outline btn-sm" onclick="Settings.toggleNode(${node.id}, ${!node.enabled}, '${node.name}', '${node.role}', ${node.is_primary})">
                                    <i class="fas fa-${node.enabled ? 'pause' : 'play'}"></i>
                                </button>
                                <button class="btn btn-danger btn-sm" onclick="Settings.deleteNode(${node.id}, '${node.name}')">
                                    <i class="fas fa-trash"></i>
                                </button>
                            </td>
                        </tr>`).join('')}
                    </tbody>
                </table>`;
        } catch (err) {
            Toast.error('Failed to load nodes: ' + err.message);
        }
    },

    // ── Save Methods ──

    async saveISE() {
        try {
            const data = {
                ise_host: document.getElementById('ise_host').value,
                ise_username: document.getElementById('ise_username').value,
                ise_password: document.getElementById('ise_password').value,
                ise_ers_port: parseInt(document.getElementById('ise_ers_port').value),
                ise_open_api_port: parseInt(document.getElementById('ise_open_api_port').value),
            };
            if (!data.ise_password) delete data.ise_password;
            await api.updateISE(data);
            Toast.success('ISE settings saved');
        } catch (err) { Toast.error('Failed to save: ' + err.message); }
    },

    async saveACME() {
        try {
            const provider = document.getElementById('acme_provider').value;
            const data = { acme_provider: provider };

            if (provider === 'digicert') {
                data.acme_directory_url = document.getElementById('acme_directory_url').value;
                data.acme_kid = document.getElementById('acme_kid').value;
                data.acme_hmac_key = document.getElementById('acme_hmac_key').value;
                if (!data.acme_kid) delete data.acme_kid;
                if (!data.acme_hmac_key) delete data.acme_hmac_key;
            } else {
                data.acme_directory_url = document.getElementById('acme_directory_url_le').value;
                data.acme_account_email = document.getElementById('acme_account_email').value;
            }

            await api.updateACME(data);
            Toast.success('ACME settings saved');
        } catch (err) { Toast.error('Failed to save: ' + err.message); }
    },

    async saveDNS() {
        try {
            const data = {
                dns_provider: document.getElementById('dns_provider').value,
                cloudflare_api_token: document.getElementById('cloudflare_api_token')?.value || null,
                cloudflare_zone_id: document.getElementById('cloudflare_zone_id')?.value || null,
                aws_hosted_zone_id: document.getElementById('aws_hosted_zone_id')?.value || null,
                aws_region: document.getElementById('aws_region')?.value || null,
                azure_subscription_id: document.getElementById('azure_subscription_id')?.value || null,
                azure_resource_group: document.getElementById('azure_resource_group')?.value || null,
                azure_dns_zone_name: document.getElementById('azure_dns_zone_name')?.value || null,
            };
            if (!data.cloudflare_api_token) delete data.cloudflare_api_token;
            await api.updateDNS(data);
            Toast.success('DNS settings saved');
        } catch (err) { Toast.error('Failed to save: ' + err.message); }
    },

    async saveSMTP() {
        try {
            const recipientsInput = document.getElementById('alert_recipients').value;
            const data = {
                smtp_server: document.getElementById('smtp_server').value || null,
                smtp_port: parseInt(document.getElementById('smtp_port').value),
                smtp_username: document.getElementById('smtp_username').value || null,
                smtp_password: document.getElementById('smtp_password').value || null,
                alert_recipients: recipientsInput ? recipientsInput.split(',').map(s => s.trim()).filter(Boolean) : [],
            };
            if (!data.smtp_password) delete data.smtp_password;
            await api.updateSMTP(data);
            Toast.success('SMTP settings saved');
        } catch (err) { Toast.error('Failed to save: ' + err.message); }
    },

    async saveScheduler() {
        try {
            const data = {
                scheduler_enabled: document.getElementById('scheduler_enabled').value === 'true',
                scheduler_cron_hour: parseInt(document.getElementById('scheduler_cron_hour').value),
                scheduler_cron_minute: parseInt(document.getElementById('scheduler_cron_minute').value),
                scheduler_interval_hours: parseInt(document.getElementById('scheduler_interval_hours').value),
            };
            await api.updateScheduler(data);
            Toast.success('Scheduler settings saved and applied');
        } catch (err) { Toast.error('Failed to save: ' + err.message); }
    },

    async saveSystem() {
        try {
            const data = {
                ise_dns_server: document.getElementById('ise_dns_server').value || null,
            };
            await api.updateISE(data);
            Toast.success('System settings saved');
        } catch (err) { Toast.error('Failed to save: ' + err.message); }
    },

    // ── Connection Tests ──

    async testISE() {
        try {
            Toast.info('Testing ISE connection...');
            const result = await api.testISE();
            if (result.success) Toast.success('ISE connection successful!');
            else Toast.error('ISE connection failed: ' + result.message);
        } catch (err) { Toast.error('Test failed: ' + err.message); }
    },

    async testERS() {
        try {
            Toast.info('Testing ERS connection...');
            const result = await api.testERS();
            if (result.success) Toast.success('ERS connection successful!');
            else Toast.error('ERS connection failed: ' + result.message);
        } catch (err) { Toast.error('Test failed: ' + err.message); }
    },

    async testDNS() {
        try {
            Toast.info('Testing DNS provider connection...');
            const result = await api.testDNS();
            if (result.success) Toast.success('DNS connection successful: ' + result.message);
            else Toast.error('DNS connection failed: ' + result.message);
        } catch (err) { Toast.error('Test failed: ' + err.message); }
    },

    // ── Node Management ──

    async addNode() {
        try {
            const data = {
                name: document.getElementById('new_node_name').value,
                role: document.getElementById('new_node_role').value,
                enabled: true,
                is_primary: document.getElementById('new_node_primary').value === 'true',
            };
            if (!data.name) { Toast.warning('Please enter a node hostname'); return; }
            await api.addNode(data);
            Toast.success(`Node ${data.name} added`);
            document.getElementById('new_node_name').value = '';
            this.loadNodes();
        } catch (err) { Toast.error('Failed to add node: ' + err.message); }
    },

    async toggleNode(id, enabled, name, role, isPrimary) {
        try {
            await api.updateNode(id, { name, role, enabled, is_primary: isPrimary });
            Toast.success(`Node ${name} ${enabled ? 'enabled' : 'disabled'}`);
            this.loadNodes();
        } catch (err) { Toast.error('Failed to update node: ' + err.message); }
    },

    async deleteNode(id, name) {
        if (!confirm(`Delete node ${name}? This cannot be undone.`)) return;
        try {
            await api.deleteNode(id);
            Toast.success(`Node ${name} deleted`);
            this.loadNodes();
        } catch (err) { Toast.error('Failed to delete node: ' + err.message); }
    },

    // ── ERS Discovery ──

    async discoverNodes() {
        try {
            Toast.info('Discovering ISE deployment nodes...');
            const result = await api.discoverNodes();
            this._discoveredNodes = result.nodes;

            const container = document.getElementById('discovery-results');
            const table = document.getElementById('discovery-table');
            if (!container || !table) return;

            table.innerHTML = `
                <thead>
                    <tr>
                        <th><input type="checkbox" id="discovery-select-all" onchange="Settings.toggleDiscoverySelectAll(this.checked)" checked></th>
                        <th>Name</th><th>FQDN</th><th>Roles</th><th>Primary PAN</th>
                    </tr>
                </thead>
                <tbody>
                    ${result.nodes.map((node, idx) => {
                        const hasPSN = node.roles.includes('PSN');
                        return `<tr>
                            <td><input type="checkbox" class="discovery-check" data-idx="${idx}" ${hasPSN ? 'checked' : ''}></td>
                            <td><strong>${node.name}</strong></td>
                            <td>${node.fqdn}</td>
                            <td>${node.roles.map(r => `<span class="badge ${r === 'PSN' ? 'success' : r === 'PAN' ? 'info' : 'neutral'}">${r}</span>`).join(' ')}</td>
                            <td>${node.is_primary_pan ? '<span class="badge success">YES</span>' : ''}</td>
                        </tr>`;
                    }).join('')}
                </tbody>`;

            container.style.display = 'block';
            Toast.success(`Discovered ${result.total} nodes (${result.psn_count} PSN)`);
        } catch (err) { Toast.error('Discovery failed: ' + err.message); }
    },

    toggleDiscoverySelectAll(checked) {
        document.querySelectorAll('.discovery-check').forEach(cb => cb.checked = checked);
    },

    async syncDiscoveredNodes() {
        try {
            const checks = document.querySelectorAll('.discovery-check:checked');
            if (checks.length === 0) { Toast.warning('No nodes selected'); return; }
            const nodes = [];
            checks.forEach(cb => {
                const node = this._discoveredNodes[parseInt(cb.dataset.idx)];
                if (node) nodes.push({ name: node.fqdn, role: node.roles.join(','), enabled: true, is_primary: node.is_primary_pan });
            });
            const result = await api.syncNodes(nodes);
            Toast.success(result.message);
            document.getElementById('discovery-results').style.display = 'none';
            this.loadNodes();
        } catch (err) { Toast.error('Sync failed: ' + err.message); }
    },

    // ── Managed Certificates UI ──

    _extractCN(subject) {
        if (!subject) return '';
        const match = subject.match(/CN=([^,]+)/i);
        return match ? match[1].trim() : subject;
    },

    async fetchISECertificates() {
        const container = document.getElementById('ise-certs-table');
        if (!container) return;
        container.innerHTML = '<p style="color:var(--text-muted); font-size:0.875rem">Fetching...</p>';
        try {
            const certs = await api.getCertificates();
            if (!certs.length) {
                container.innerHTML = '<p style="color:var(--text-muted); font-size:0.875rem">No certificates found on ISE.</p>';
                return;
            }
            container.innerHTML = `
                <div class="table-container">
                <table>
                    <thead><tr>
                        <th>Friendly Name</th><th>Subject / CN</th><th>Issuer</th>
                        <th>Expiry</th><th>Used By</th><th>Action</th>
                    </tr></thead>
                    <tbody>
                        ${certs.map(cert => {
                            const cn = this._extractCN(cert.subject);
                            const expiry = cert.expiration_date ? cert.expiration_date.split('T')[0] : '—';
                            return `<tr>
                                <td>${cert.friendly_name}</td>
                                <td><code style="font-size:0.8rem">${cn}</code></td>
                                <td style="font-size:0.8rem; color:var(--text-muted)">${cert.issuer || '—'}</td>
                                <td style="font-size:0.8rem">${expiry}</td>
                                <td style="font-size:0.8rem">${cert.used_by || '—'}</td>
                                <td>
                                    <button class="btn btn-outline btn-sm" onclick="Settings.showCertForm('${cn.replace(/'/g, "\\'")}')">
                                        <i class="fas fa-plus"></i> Add to Auto-Renew
                                    </button>
                                </td>
                            </tr>`;
                        }).join('')}
                    </tbody>
                </table>
                </div>`;
        } catch (err) {
            container.innerHTML = `<p style="color:var(--danger); font-size:0.875rem">Failed to load: ${err.message}</p>`;
        }
    },

    async loadManagedCerts() {
        const container = document.getElementById('managed-certs-table');
        if (!container) return;
        try {
            const certs = await api.getManagedCertificates();
            if (!certs.length) {
                container.innerHTML = '<p style="color:var(--text-muted); font-size:0.875rem">No managed certificates configured yet.</p>';
                return;
            }
            container.innerHTML = `
                <div class="table-container">
                <table>
                    <thead><tr>
                        <th>Common Name</th><th>Key Type</th><th>Mode</th>
                        <th>Threshold</th><th>Assigned Nodes</th><th>Enabled</th><th>Actions</th>
                    </tr></thead>
                    <tbody>
                        ${certs.map(cert => `<tr>
                            <td><strong>${cert.common_name}</strong></td>
                            <td><span class="badge info">${cert.key_type}</span></td>
                            <td><span class="badge neutral">${cert.certificate_mode}</span></td>
                            <td>${cert.renewal_threshold_days}d</td>
                            <td style="font-size:0.8rem">${cert.nodes.map(n => n.name).join(', ') || '—'}</td>
                            <td>${cert.enabled ? '<span class="badge success">Yes</span>' : '<span class="badge neutral">No</span>'}</td>
                            <td>
                                <button class="btn btn-outline btn-sm" onclick="Settings.editManagedCert(${cert.id})">
                                    <i class="fas fa-edit"></i>
                                </button>
                                <button class="btn btn-danger btn-sm" onclick="Settings.deleteManagedCert(${cert.id}, '${cert.common_name.replace(/'/g, "\\'")}')">
                                    <i class="fas fa-trash"></i>
                                </button>
                            </td>
                        </tr>`).join('')}
                    </tbody>
                </table>
                </div>`;
        } catch (err) {
            container.innerHTML = `<p style="color:var(--danger); font-size:0.875rem">Failed to load: ${err.message}</p>`;
        }
    },

    async showCertForm(prefillCN = '') {
        // Ensure we're on the certificates panel
        this.showSection('certificates');

        const panel = document.getElementById('cert-form-panel');
        const title = document.getElementById('cert-form-title');
        if (!panel) return;

        // Reset form
        document.getElementById('cert-form-id').value = '';
        document.getElementById('cert-cn').value = prefillCN;
        document.getElementById('cert-san').value = '';
        document.getElementById('cert-key-type').value = 'RSA_2048';
        document.getElementById('cert-mode').value = 'shared';
        document.getElementById('cert-portal-tag').value = 'Default Portal Certificate Group';
        document.getElementById('cert-threshold').value = '30';
        document.getElementById('cert-enabled').value = 'true';
        if (title) title.textContent = 'Add Certificate';

        panel.style.display = 'block';
        panel.scrollIntoView({ behavior: 'smooth', block: 'start' });

        await this._loadNodeCheckboxes([]);
    },

    async editManagedCert(id) {
        try {
            const certs = await api.getManagedCertificates();
            const cert = certs.find(c => c.id === id);
            if (!cert) return;

            this.showSection('certificates');
            const panel = document.getElementById('cert-form-panel');
            const title = document.getElementById('cert-form-title');
            if (!panel) return;

            document.getElementById('cert-form-id').value = cert.id;
            document.getElementById('cert-cn').value = cert.common_name;
            document.getElementById('cert-san').value = (cert.san_names || []).join(',');
            document.getElementById('cert-key-type').value = cert.key_type;
            document.getElementById('cert-mode').value = cert.certificate_mode;
            document.getElementById('cert-portal-tag').value = cert.portal_group_tag;
            document.getElementById('cert-threshold').value = cert.renewal_threshold_days;
            document.getElementById('cert-enabled').value = cert.enabled ? 'true' : 'false';
            if (title) title.textContent = 'Edit Certificate';

            panel.style.display = 'block';
            panel.scrollIntoView({ behavior: 'smooth', block: 'start' });

            const assignedIds = cert.nodes.map(n => n.id);
            await this._loadNodeCheckboxes(assignedIds);
        } catch (err) { Toast.error('Failed to load certificate: ' + err.message); }
    },

    async _loadNodeCheckboxes(selectedIds) {
        const container = document.getElementById('cert-node-checkboxes');
        if (!container) return;
        try {
            const nodes = await api.getNodes();
            if (!nodes.length) {
                container.innerHTML = '<span style="color:var(--text-muted); font-size:0.875rem">No nodes configured.</span>';
                return;
            }
            container.innerHTML = nodes.map(node => `
                <label style="display:flex; align-items:center; gap:6px; font-size:0.875rem; cursor:pointer">
                    <input type="checkbox" class="cert-node-cb" value="${node.id}" ${selectedIds.includes(node.id) ? 'checked' : ''}>
                    ${node.name} <span class="badge ${node.is_primary ? 'success' : 'neutral'}" style="font-size:0.7rem">${node.is_primary ? 'PRIMARY' : node.role}</span>
                </label>`).join('');
        } catch (err) {
            container.innerHTML = '<span style="color:var(--danger); font-size:0.875rem">Failed to load nodes.</span>';
        }
    },

    hideCertForm() {
        const panel = document.getElementById('cert-form-panel');
        if (panel) panel.style.display = 'none';
    },

    async saveManagedCert() {
        try {
            const id = document.getElementById('cert-form-id').value;
            const sanInput = document.getElementById('cert-san').value;
            const nodeIds = Array.from(document.querySelectorAll('.cert-node-cb:checked')).map(cb => parseInt(cb.value));

            const data = {
                common_name: document.getElementById('cert-cn').value,
                san_names: sanInput ? sanInput.split(',').map(s => s.trim()).filter(Boolean) : [],
                key_type: document.getElementById('cert-key-type').value,
                certificate_mode: document.getElementById('cert-mode').value,
                portal_group_tag: document.getElementById('cert-portal-tag').value,
                renewal_threshold_days: parseInt(document.getElementById('cert-threshold').value),
                enabled: document.getElementById('cert-enabled').value === 'true',
                node_ids: nodeIds,
            };

            if (!data.common_name) { Toast.warning('Please enter a Common Name'); return; }

            if (id) {
                await api.updateManagedCertificate(parseInt(id), data);
                Toast.success('Certificate updated');
            } else {
                await api.createManagedCertificate(data);
                Toast.success('Certificate added');
            }

            this.hideCertForm();
            this.loadManagedCerts();
        } catch (err) { Toast.error('Failed to save: ' + err.message); }
    },

    async deleteManagedCert(id, cn) {
        if (!confirm(`Delete managed certificate "${cn}"? This cannot be undone.`)) return;
        try {
            await api.deleteManagedCertificate(id);
            Toast.success(`Certificate "${cn}" deleted`);
            this.loadManagedCerts();
        } catch (err) { Toast.error('Failed to delete: ' + err.message); }
    },
};
