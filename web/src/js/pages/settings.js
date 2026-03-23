/**
 * Settings page — configure all daemon parameters.
 */

const Settings = {
    currentSettings: {},

    async render() {
        try {
            this.currentSettings = await api.getSettings();
            const s = this.currentSettings;

            return `
            <div class="page-header">
                <h1><i class="fas fa-cog"></i> Settings</h1>
            </div>

            <!-- ISE Settings -->
            <div class="settings-section">
                <h2><i class="fas fa-server"></i> Cisco ISE Connection</h2>
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
                        <label>Open API Port</label>
                        <input id="ise_open_api_port" type="number" value="${s.ise?.ise_open_api_port || 443}">
                    </div>
                </div>
                <div class="btn-group">
                    <button class="btn btn-primary btn-sm" onclick="Settings.saveISE()">
                        <i class="fas fa-save"></i> Save
                    </button>
                    <button class="btn btn-outline btn-sm" onclick="Settings.testISE()">
                        <i class="fas fa-plug"></i> Test Connection
                    </button>
                </div>
            </div>

            <!-- ACME Settings -->
            <div class="settings-section">
                <h2><i class="fas fa-certificate"></i> ACME / DigiCert</h2>
                <div class="form-grid">
                    <div class="form-group">
                        <label>ACME Directory URL</label>
                        <input id="acme_directory_url" value="${s.acme?.acme_directory_url || ''}">
                    </div>
                    <div class="form-group">
                        <label>Key ID (KID)</label>
                        <input id="acme_kid" type="password" value="" placeholder="Enter KID">
                    </div>
                    <div class="form-group">
                        <label>HMAC Key</label>
                        <input id="acme_hmac_key" type="password" value="" placeholder="Enter HMAC key">
                    </div>
                </div>
                <div class="btn-group">
                    <button class="btn btn-primary btn-sm" onclick="Settings.saveACME()">
                        <i class="fas fa-save"></i> Save
                    </button>
                </div>
            </div>

            <!-- Certificate Settings -->
            <div class="settings-section">
                <h2><i class="fas fa-lock"></i> Certificate</h2>
                <div class="form-grid">
                    <div class="form-group">
                        <label>Common Name</label>
                        <input id="common_name" value="${s.certificate?.common_name || ''}" placeholder="guest.yourdomain.com">
                    </div>
                    <div class="form-group">
                        <label>SAN Names (comma-separated)</label>
                        <input id="san_names" value="${(s.certificate?.san_names || []).join(',')}" placeholder="guest.yourdomain.com,portal.yourdomain.com">
                    </div>
                    <div class="form-group">
                        <label>Key Type</label>
                        <select id="key_type">
                            <option value="RSA_2048" ${s.certificate?.key_type === 'RSA_2048' ? 'selected' : ''}>RSA 2048</option>
                            <option value="RSA_4096" ${s.certificate?.key_type === 'RSA_4096' ? 'selected' : ''}>RSA 4096</option>
                            <option value="ECDSA_256" ${s.certificate?.key_type === 'ECDSA_256' ? 'selected' : ''}>ECDSA 256</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Certificate Mode</label>
                        <select id="certificate_mode">
                            <option value="shared" ${s.certificate?.certificate_mode === 'shared' ? 'selected' : ''}>Shared</option>
                            <option value="per-node" ${s.certificate?.certificate_mode === 'per-node' ? 'selected' : ''}>Per-Node</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Portal Group Tag</label>
                        <input id="portal_group_tag" value="${s.certificate?.portal_group_tag || ''}">
                    </div>
                    <div class="form-group">
                        <label>Renewal Threshold (days)</label>
                        <input id="renewal_threshold_days" type="number" value="${s.certificate?.renewal_threshold_days || 30}">
                    </div>
                </div>
                <div class="btn-group">
                    <button class="btn btn-primary btn-sm" onclick="Settings.saveCertificate()">
                        <i class="fas fa-save"></i> Save
                    </button>
                </div>
            </div>

            <!-- DNS Settings -->
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
                    <div class="form-group dns-cloudflare">
                        <label>Cloudflare API Token</label>
                        <input id="cloudflare_api_token" type="password" placeholder="Enter token">
                    </div>
                    <div class="form-group dns-cloudflare">
                        <label>Cloudflare Zone ID</label>
                        <input id="cloudflare_zone_id" value="${s.dns?.cloudflare_zone_id || ''}">
                    </div>
                    <div class="form-group dns-aws" style="display:none">
                        <label>Hosted Zone ID</label>
                        <input id="aws_hosted_zone_id" value="${s.dns?.aws_hosted_zone_id || ''}">
                    </div>
                    <div class="form-group dns-aws" style="display:none">
                        <label>AWS Region</label>
                        <input id="aws_region" value="${s.dns?.aws_region || 'us-east-1'}">
                    </div>
                    <div class="form-group dns-azure" style="display:none">
                        <label>Subscription ID</label>
                        <input id="azure_subscription_id" value="${s.dns?.azure_subscription_id || ''}">
                    </div>
                    <div class="form-group dns-azure" style="display:none">
                        <label>Resource Group</label>
                        <input id="azure_resource_group" value="${s.dns?.azure_resource_group || ''}">
                    </div>
                    <div class="form-group dns-azure" style="display:none">
                        <label>DNS Zone Name</label>
                        <input id="azure_dns_zone_name" value="${s.dns?.azure_dns_zone_name || ''}">
                    </div>
                </div>
                <div class="
