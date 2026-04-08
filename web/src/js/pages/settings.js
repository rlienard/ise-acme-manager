/**
 * Settings page — sidebar-navigated layout with 7 sections.
 */

const Settings = {
    currentSettings: {},
    _activeSection: 'ise',
    _discoveredNodes: [],
    _acmeProviders: [],
    _portalGroupTags: [],
    _iseCertsCache: [],

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
        this.toggleACMEProviderFormFields();
        this.toggleDNSFields();
        this.loadNodes();
        this.loadACMEProviders();
        this.loadManagedCerts();
        this.loadSystemInfo();
    },

    async loadSystemInfo() {
        try {
            const info = await api.getSystemInfo();
            const el = document.getElementById('container_dns_server');
            if (el) el.value = info.custom_dns_server || 'Not configured (using Docker default DNS)';
        } catch (err) {
            const el = document.getElementById('container_dns_server');
            if (el) el.value = 'Unable to retrieve';
        }
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
        return `
        <div id="panel-acme" class="settings-panel">
            <div class="settings-section">
                <h2><i class="fas fa-certificate"></i> ACME Providers</h2>
                <p style="color:var(--text-muted); font-size:0.875rem; margin-top:-0.5rem">
                    Configure one or more ACME providers. Each managed certificate can be
                    renewed through a different provider.
                </p>

                <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:0.75rem">
                    <h3 style="font-size:0.95rem; color:var(--text-muted); margin:0">Configured Providers</h3>
                    <button class="btn btn-primary btn-sm" onclick="Settings.showACMEProviderForm()">
                        <i class="fas fa-plus"></i> Add Provider
                    </button>
                </div>
                <div id="acme-providers-table">
                    <p style="color:var(--text-muted); font-size:0.875rem">Loading...</p>
                </div>

                <!-- Add/Edit Provider Form (hidden by default) -->
                <div id="acme-provider-form-panel" style="display:none; margin-top:1.5rem; border-top:1px solid var(--border); padding-top:1.25rem">
                    <h3 style="font-size:0.95rem; margin-bottom:1rem" id="acme-provider-form-title">Add ACME Provider</h3>
                    <input type="hidden" id="acme-provider-form-id">
                    <div class="form-grid">
                        <div class="form-group">
                            <label>Name (unique label)</label>
                            <input id="acme-provider-name" placeholder="e.g. Production DigiCert">
                        </div>
                        <div class="form-group">
                            <label>Provider Type</label>
                            <select id="acme-provider-type" onchange="Settings.toggleACMEProviderFormFields()">
                                <option value="digicert">DigiCert</option>
                                <option value="letsencrypt">Let's Encrypt</option>
                            </select>
                        </div>
                        <div class="form-group" style="grid-column: span 2">
                            <label>ACME Directory URL</label>
                            <input id="acme-provider-directory-url" placeholder="https://acme.example.com/directory">
                            <small class="acme-provider-field acme-provider-letsencrypt" style="color:var(--text-muted); font-size:0.75rem; margin-top:4px; display:none">
                                Use https://acme-staging-v02.api.letsencrypt.org/directory for testing
                            </small>
                        </div>
                        <div class="form-group acme-provider-field acme-provider-digicert">
                            <label>Key ID (KID)</label>
                            <input id="acme-provider-kid" type="password" placeholder="Enter KID">
                        </div>
                        <div class="form-group acme-provider-field acme-provider-digicert">
                            <label>HMAC Key</label>
                            <input id="acme-provider-hmac-key" type="password" placeholder="Enter HMAC key">
                        </div>
                        <div class="form-group acme-provider-field acme-provider-letsencrypt" style="display:none">
                            <label>Account Email</label>
                            <input id="acme-provider-account-email" placeholder="admin@yourdomain.com">
                        </div>
                    </div>
                    <div class="btn-group">
                        <button class="btn btn-primary btn-sm" onclick="Settings.saveACMEProvider()">
                            <i class="fas fa-save"></i> Save Provider
                        </button>
                        <button class="btn btn-outline btn-sm" onclick="Settings.hideACMEProviderForm()">
                            <i class="fas fa-times"></i> Cancel
                        </button>
                    </div>
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
                            <label>ACME Provider</label>
                            <select id="cert-acme-provider">
                                <option value="">— Select provider —</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label>
                                Portal Group Tag
                                <button type="button" class="btn btn-outline btn-sm" style="margin-left:6px; padding:2px 8px; font-size:0.7rem" onclick="Settings.refreshPortalGroupTags()" title="Re-discover from ISE">
                                    <i class="fas fa-sync-alt"></i>
                                </button>
                            </label>
                            <select id="cert-portal-tag" style="display:none">
                                <option value="Default Portal Certificate Group">Default Portal Certificate Group</option>
                            </select>
                            <input id="cert-portal-tag-input" value="Default Portal Certificate Group" placeholder="Default Portal Certificate Group">
                            <small style="color:var(--text-muted); font-size:0.75rem; margin-top:4px; display:block">
                                Click the refresh button to auto-discover tags from ISE.
                            </small>
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
                            <label>Target ISE Nodes (push certificate to)</label>
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
                            <option value="ovhcloud" ${s.dns?.dns_provider === 'ovhcloud' ? 'selected' : ''}>OVHcloud</option>
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
                    <div class="form-group dns-field dns-ovhcloud" style="display:none">
                        <label>API Endpoint</label>
                        <select id="ovh_endpoint">
                            <option value="ovh-eu" ${s.dns?.ovh_endpoint === 'ovh-eu' ? 'selected' : ''}>OVH Europe (ovh-eu)</option>
                            <option value="ovh-us" ${s.dns?.ovh_endpoint === 'ovh-us' ? 'selected' : ''}>OVH US (ovh-us)</option>
                            <option value="ovh-ca" ${s.dns?.ovh_endpoint === 'ovh-ca' ? 'selected' : ''}>OVH Canada (ovh-ca)</option>
                            <option value="kimsufi-eu" ${s.dns?.ovh_endpoint === 'kimsufi-eu' ? 'selected' : ''}>Kimsufi Europe (kimsufi-eu)</option>
                            <option value="kimsufi-ca" ${s.dns?.ovh_endpoint === 'kimsufi-ca' ? 'selected' : ''}>Kimsufi Canada (kimsufi-ca)</option>
                            <option value="soyoustart-eu" ${s.dns?.ovh_endpoint === 'soyoustart-eu' ? 'selected' : ''}>So You Start Europe (soyoustart-eu)</option>
                            <option value="soyoustart-ca" ${s.dns?.ovh_endpoint === 'soyoustart-ca' ? 'selected' : ''}>So You Start Canada (soyoustart-ca)</option>
                        </select>
                    </div>
                    <div class="form-group dns-field dns-ovhcloud" style="display:none">
                        <label>Application Key</label>
                        <input id="ovh_application_key" type="password" placeholder="Enter application key">
                    </div>
                    <div class="form-group dns-field dns-ovhcloud" style="display:none">
                        <label>Application Secret</label>
                        <input id="ovh_application_secret" type="password" placeholder="Enter application secret">
                    </div>
                    <div class="form-group dns-field dns-ovhcloud" style="display:none">
                        <label>Consumer Key</label>
                        <input id="ovh_consumer_key" type="password" placeholder="Enter consumer key">
                    </div>
                    <div class="form-group dns-field dns-ovhcloud" style="display:none">
                        <label>DNS Zone</label>
                        <input id="ovh_dns_zone" value="${s.dns?.ovh_dns_zone || ''}" placeholder="example.com">
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

                <div class="info-banner" style="margin-bottom:1.25rem;padding:0.85rem 1rem;border-left:3px solid var(--accent);background:var(--bg-secondary);border-radius:4px;font-size:0.875rem;line-height:1.55">
                    <strong><i class="fas fa-network-wired"></i> Global Container DNS</strong><br>
                    To route <em>all</em> container traffic through a custom DNS server, set the
                    <code>CUSTOM_DNS_SERVER</code> variable in a <code>.env</code> file next to
                    <code>docker-compose.yml</code>, then uncomment the <code>dns:</code> line in
                    <code>docker-compose.yml</code> under the <code>daemon</code> service, and
                    restart the container (<code>docker compose down &amp;&amp; docker compose up -d</code>).<br>
                    See <code>.env.example</code> for the full instructions.
                </div>

                <div class="form-grid">
                    <div class="form-group">
                        <label>Global Container DNS Server <small style="color:var(--text-muted)">(read-only — set via <code>CUSTOM_DNS_SERVER</code> in <code>.env</code>)</small></label>
                        <input id="container_dns_server" readonly value="Loading…" style="background:var(--bg-secondary);cursor:default;color:var(--text-muted)">
                        <small style="color:var(--text-muted);margin-top:0.25rem;display:block">
                            Reflects the <code>CUSTOM_DNS_SERVER</code> environment variable active in the container.
                            A container restart is required for changes to take effect.
                        </small>
                    </div>
                </div>
            </div>
        </div>`;
    },

    // ── DNS field toggling ──

    toggleACMEProviderFormFields() {
        const providerType = document.getElementById('acme-provider-type')?.value;
        document.querySelectorAll('.acme-provider-field').forEach(el => el.style.display = 'none');
        document.querySelectorAll(`.acme-provider-${providerType}`).forEach(el => el.style.display = 'flex');
        // <small> helper text is inline; force it to block when shown
        document.querySelectorAll(`small.acme-provider-${providerType}`).forEach(el => el.style.display = 'block');
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

    // ── ACME Providers ──

    async loadACMEProviders() {
        const container = document.getElementById('acme-providers-table');
        try {
            const providers = await api.getACMEProviders();
            this._acmeProviders = providers;
            if (!container) return;
            if (!providers.length) {
                container.innerHTML = '<p style="color:var(--text-muted); font-size:0.875rem">No ACME providers configured yet. Click "Add Provider" to create one.</p>';
                return;
            }
            container.innerHTML = `
                <div class="table-container">
                <table>
                    <thead><tr>
                        <th>Name</th><th>Type</th><th>Directory URL</th>
                        <th>Account Email</th><th>Actions</th>
                    </tr></thead>
                    <tbody>
                        ${providers.map(p => `<tr>
                            <td><strong>${this._escape(p.name)}</strong></td>
                            <td><span class="badge ${p.provider_type === 'letsencrypt' ? 'info' : 'neutral'}">${p.provider_type}</span></td>
                            <td style="font-size:0.8rem; word-break:break-all">${this._escape(p.directory_url)}</td>
                            <td style="font-size:0.8rem">${this._escape(p.account_email || '—')}</td>
                            <td>
                                <button class="btn btn-outline btn-sm" onclick="Settings.editACMEProvider(${p.id})">
                                    <i class="fas fa-edit"></i>
                                </button>
                                <button class="btn btn-danger btn-sm" onclick="Settings.deleteACMEProvider(${p.id})">
                                    <i class="fas fa-trash"></i>
                                </button>
                            </td>
                        </tr>`).join('')}
                    </tbody>
                </table>
                </div>`;
        } catch (err) {
            if (container) container.innerHTML = `<p style="color:var(--danger); font-size:0.875rem">Failed to load: ${err.message}</p>`;
        }
    },

    _escape(s) {
        if (s === null || s === undefined) return '';
        return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    },

    showACMEProviderForm() {
        this.showSection('acme');
        const panel = document.getElementById('acme-provider-form-panel');
        const title = document.getElementById('acme-provider-form-title');
        if (!panel) return;
        document.getElementById('acme-provider-form-id').value = '';
        document.getElementById('acme-provider-name').value = '';
        document.getElementById('acme-provider-type').value = 'digicert';
        document.getElementById('acme-provider-directory-url').value = 'https://acme.digicert.com/v2/acme/directory/';
        document.getElementById('acme-provider-kid').value = '';
        document.getElementById('acme-provider-hmac-key').value = '';
        document.getElementById('acme-provider-account-email').value = '';
        if (title) title.textContent = 'Add ACME Provider';
        this.toggleACMEProviderFormFields();
        panel.style.display = 'block';
        panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
    },

    editACMEProvider(id) {
        const provider = this._acmeProviders.find(p => p.id === id);
        if (!provider) return;
        this.showSection('acme');
        const panel = document.getElementById('acme-provider-form-panel');
        const title = document.getElementById('acme-provider-form-title');
        if (!panel) return;
        document.getElementById('acme-provider-form-id').value = provider.id;
        document.getElementById('acme-provider-name').value = provider.name;
        document.getElementById('acme-provider-type').value = provider.provider_type;
        document.getElementById('acme-provider-directory-url').value = provider.directory_url;
        document.getElementById('acme-provider-kid').value = '';
        document.getElementById('acme-provider-hmac-key').value = '';
        document.getElementById('acme-provider-account-email').value = provider.account_email || '';
        if (title) title.textContent = `Edit ACME Provider — ${provider.name}`;
        this.toggleACMEProviderFormFields();
        panel.style.display = 'block';
        panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
    },

    hideACMEProviderForm() {
        const panel = document.getElementById('acme-provider-form-panel');
        if (panel) panel.style.display = 'none';
    },

    async saveACMEProvider() {
        try {
            const id = document.getElementById('acme-provider-form-id').value;
            const providerType = document.getElementById('acme-provider-type').value;

            const data = {
                name: document.getElementById('acme-provider-name').value.trim(),
                provider_type: providerType,
                directory_url: document.getElementById('acme-provider-directory-url').value.trim(),
            };
            if (!data.name) { Toast.warning('Please enter a provider name'); return; }
            if (!data.directory_url) { Toast.warning('Please enter the ACME directory URL'); return; }

            if (providerType === 'digicert') {
                const kid = document.getElementById('acme-provider-kid').value;
                const hmac = document.getElementById('acme-provider-hmac-key').value;
                if (kid) data.kid = kid;
                if (hmac) data.hmac_key = hmac;
            } else {
                data.account_email = document.getElementById('acme-provider-account-email').value.trim() || null;
            }

            if (id) {
                await api.updateACMEProvider(parseInt(id), data);
                Toast.success('ACME provider updated');
            } else {
                await api.createACMEProvider(data);
                Toast.success('ACME provider added');
            }

            this.hideACMEProviderForm();
            this.loadACMEProviders();
        } catch (err) { Toast.error('Failed to save provider: ' + err.message); }
    },

    async deleteACMEProvider(id) {
        const provider = this._acmeProviders.find(p => p.id === id);
        if (!provider) return;
        if (!confirm(`Delete ACME provider "${provider.name}"? This cannot be undone.`)) return;
        try {
            await api.deleteACMEProvider(id);
            Toast.success(`Provider "${provider.name}" deleted`);
            this.loadACMEProviders();
        } catch (err) { Toast.error('Failed to delete: ' + err.message); }
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
                ovh_endpoint: document.getElementById('ovh_endpoint')?.value || 'ovh-eu',
                ovh_application_key: document.getElementById('ovh_application_key')?.value || null,
                ovh_application_secret: document.getElementById('ovh_application_secret')?.value || null,
                ovh_consumer_key: document.getElementById('ovh_consumer_key')?.value || null,
                ovh_dns_zone: document.getElementById('ovh_dns_zone')?.value || null,
            };
            if (!data.cloudflare_api_token) delete data.cloudflare_api_token;
            if (!data.ovh_application_key) delete data.ovh_application_key;
            if (!data.ovh_application_secret) delete data.ovh_application_secret;
            if (!data.ovh_consumer_key) delete data.ovh_consumer_key;
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

    // ── Connection Tests ──

    _getISEFormData() {
        const data = {
            ise_host: document.getElementById('ise_host').value,
            ise_username: document.getElementById('ise_username').value,
            ise_ers_port: parseInt(document.getElementById('ise_ers_port').value),
            ise_open_api_port: parseInt(document.getElementById('ise_open_api_port').value),
        };
        const password = document.getElementById('ise_password').value;
        if (password) data.ise_password = password;
        return data;
    },

    async testISE() {
        try {
            Toast.info('Testing ISE connection...');
            const result = await api.testISE(this._getISEFormData());
            if (result.success) Toast.success('ISE connection successful!');
            else Toast.error('ISE connection failed: ' + result.message);
        } catch (err) { Toast.error('Test failed: ' + err.message); }
    },

    async testERS() {
        try {
            Toast.info('Testing ERS connection...');
            const result = await api.testERS(this._getISEFormData());
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
            this._iseCertsCache = certs;
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
                        ${certs.map((cert, idx) => {
                            const cn = this._extractCN(cert.subject);
                            const expiry = cert.expiration_date ? cert.expiration_date.split('T')[0] : '—';
                            return `<tr>
                                <td>${this._escape(cert.friendly_name)}</td>
                                <td><code style="font-size:0.8rem">${this._escape(cn)}</code></td>
                                <td style="font-size:0.8rem; color:var(--text-muted)">${this._escape(cert.issuer || '—')}</td>
                                <td style="font-size:0.8rem">${this._escape(expiry)}</td>
                                <td style="font-size:0.8rem">${this._escape(cert.used_by || '—')}</td>
                                <td>
                                    <button class="btn btn-outline btn-sm" onclick="Settings.showCertFormFromISE(${idx})">
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

    showCertFormFromISE(idx) {
        const cert = this._iseCertsCache[idx];
        if (!cert) return;
        const prefill = {
            common_name: this._extractCN(cert.subject),
            san_names: cert.san_names || [],
            key_type: this._normalizeKeyType(cert.key_type),
            portal_group_tag: cert.portal_group_tag || 'Default Portal Certificate Group',
            node_ids: cert.node_id ? [cert.node_id] : [],
        };
        this.showCertForm(prefill);
    },

    _normalizeKeyType(keyType) {
        if (!keyType) return 'RSA_2048';
        const supported = ['RSA_2048', 'RSA_4096', 'ECDSA_256'];
        const upper = String(keyType).toUpperCase().replace(/[^A-Z0-9]/g, '_');
        const match = supported.find(k => upper.includes(k.replace('_', '')) || upper === k);
        return match || 'RSA_2048';
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
                        <th>Provider</th><th>Target Nodes</th><th>Threshold</th>
                        <th>Enabled</th><th>Actions</th>
                    </tr></thead>
                    <tbody>
                        ${certs.map(cert => `<tr>
                            <td><strong>${this._escape(cert.common_name)}</strong></td>
                            <td><span class="badge info">${this._escape(cert.key_type)}</span></td>
                            <td><span class="badge neutral">${this._escape(cert.certificate_mode)}</span></td>
                            <td style="font-size:0.8rem">${cert.acme_provider_name ? this._escape(cert.acme_provider_name) : '<span style="color:var(--text-muted)">— not set —</span>'}</td>
                            <td style="font-size:0.8rem">${cert.nodes.map(n => this._escape(n.name)).join(', ') || '—'}</td>
                            <td>${cert.renewal_threshold_days}d</td>
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

    async showCertForm(prefill = {}) {
        // Backwards compatibility: string = common_name
        if (typeof prefill === 'string') {
            prefill = { common_name: prefill };
        }
        prefill = prefill || {};

        // Ensure we're on the certificates panel
        this.showSection('certificates');

        const panel = document.getElementById('cert-form-panel');
        const title = document.getElementById('cert-form-title');
        if (!panel) return;

        // Reset form
        document.getElementById('cert-form-id').value = '';
        document.getElementById('cert-cn').value = prefill.common_name || '';
        document.getElementById('cert-san').value = (prefill.san_names || []).join(',');
        document.getElementById('cert-key-type').value = prefill.key_type || 'RSA_2048';
        document.getElementById('cert-mode').value = prefill.certificate_mode || 'shared';
        document.getElementById('cert-threshold').value = prefill.renewal_threshold_days || '30';
        document.getElementById('cert-enabled').value = 'true';
        if (title) title.textContent = 'Add Certificate';

        panel.style.display = 'block';
        panel.scrollIntoView({ behavior: 'smooth', block: 'start' });

        await Promise.all([
            this._loadNodeCheckboxes(prefill.node_ids || []),
            this._loadACMEProvidersDropdown(prefill.acme_provider_id || null),
            this._loadPortalGroupTagsDropdown(prefill.portal_group_tag || 'Default Portal Certificate Group'),
        ]);
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
            document.getElementById('cert-threshold').value = cert.renewal_threshold_days;
            document.getElementById('cert-enabled').value = cert.enabled ? 'true' : 'false';
            if (title) title.textContent = 'Edit Certificate';

            panel.style.display = 'block';
            panel.scrollIntoView({ behavior: 'smooth', block: 'start' });

            const assignedIds = cert.nodes.map(n => n.id);
            await Promise.all([
                this._loadNodeCheckboxes(assignedIds),
                this._loadACMEProvidersDropdown(cert.acme_provider_id || null),
                this._loadPortalGroupTagsDropdown(cert.portal_group_tag || 'Default Portal Certificate Group'),
            ]);
        } catch (err) { Toast.error('Failed to load certificate: ' + err.message); }
    },

    async _loadACMEProvidersDropdown(selectedId) {
        const select = document.getElementById('cert-acme-provider');
        if (!select) return;
        try {
            const providers = this._acmeProviders && this._acmeProviders.length
                ? this._acmeProviders
                : await api.getACMEProviders();
            this._acmeProviders = providers;

            const options = ['<option value="">— Select provider —</option>']
                .concat(providers.map(p =>
                    `<option value="${p.id}" ${p.id === selectedId ? 'selected' : ''}>${this._escape(p.name)} (${p.provider_type})</option>`
                ));
            select.innerHTML = options.join('');

            if (!providers.length) {
                select.innerHTML = '<option value="">— No providers configured —</option>';
            }
        } catch (err) {
            select.innerHTML = '<option value="">— Failed to load —</option>';
        }
    },

    async _loadPortalGroupTagsDropdown(selectedTag) {
        const select = document.getElementById('cert-portal-tag');
        const input = document.getElementById('cert-portal-tag-input');
        if (!select || !input) return;

        // If we have cached tags, use them; otherwise keep the free-text input.
        if (this._portalGroupTags && this._portalGroupTags.length) {
            this._populatePortalGroupSelect(selectedTag);
            return;
        }

        // Start with the free-text input visible, prefill with selectedTag
        input.value = selectedTag || 'Default Portal Certificate Group';
        input.style.display = '';
        select.style.display = 'none';
    },

    _populatePortalGroupSelect(selectedTag) {
        const select = document.getElementById('cert-portal-tag');
        const input = document.getElementById('cert-portal-tag-input');
        if (!select || !input) return;

        const tags = this._portalGroupTags || [];
        const current = selectedTag || input.value || 'Default Portal Certificate Group';

        // Ensure the currently-selected tag is present in the dropdown list.
        const allTags = Array.from(new Set([current, ...tags])).filter(Boolean);

        select.innerHTML = allTags.map(t =>
            `<option value="${this._escape(t)}" ${t === current ? 'selected' : ''}>${this._escape(t)}</option>`
        ).join('');

        select.style.display = '';
        input.style.display = 'none';
    },

    async refreshPortalGroupTags() {
        try {
            Toast.info('Fetching portal group tags from ISE...');
            const tags = await api.getPortalGroupTags();
            this._portalGroupTags = tags;

            // Preserve whatever was previously entered/selected
            const input = document.getElementById('cert-portal-tag-input');
            const select = document.getElementById('cert-portal-tag');
            const currentValue = (select && select.style.display !== 'none')
                ? select.value
                : (input ? input.value : 'Default Portal Certificate Group');

            this._populatePortalGroupSelect(currentValue);
            Toast.success(`Discovered ${tags.length} portal group tag(s)`);
        } catch (err) {
            Toast.error('Failed to fetch portal group tags: ' + err.message);
        }
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

    _getPortalGroupTagValue() {
        const select = document.getElementById('cert-portal-tag');
        const input = document.getElementById('cert-portal-tag-input');
        if (select && select.style.display !== 'none') return select.value;
        if (input) return input.value;
        return 'Default Portal Certificate Group';
    },

    async saveManagedCert() {
        try {
            const id = document.getElementById('cert-form-id').value;
            const sanInput = document.getElementById('cert-san').value;
            const nodeIds = Array.from(document.querySelectorAll('.cert-node-cb:checked')).map(cb => parseInt(cb.value));
            const providerId = document.getElementById('cert-acme-provider').value;

            const data = {
                common_name: document.getElementById('cert-cn').value,
                san_names: sanInput ? sanInput.split(',').map(s => s.trim()).filter(Boolean) : [],
                key_type: document.getElementById('cert-key-type').value,
                certificate_mode: document.getElementById('cert-mode').value,
                portal_group_tag: this._getPortalGroupTagValue(),
                renewal_threshold_days: parseInt(document.getElementById('cert-threshold').value),
                enabled: document.getElementById('cert-enabled').value === 'true',
                acme_provider_id: providerId ? parseInt(providerId) : null,
                node_ids: nodeIds,
            };

            if (!data.common_name) { Toast.warning('Please enter a Common Name'); return; }
            if (!nodeIds.length) { Toast.warning('Please select at least one target ISE node'); return; }
            if (!data.acme_provider_id) { Toast.warning('Please select an ACME provider'); return; }

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
