/**
 * API Client — communicates with the ACME daemon.
 */

const API_BASE = window.location.hostname === 'localhost'
    ? 'http://localhost:8443'
    : `${window.location.protocol}//${window.location.hostname}:8443`;

const api = {
    async request(method, path, body = null) {
        const options = {
            method,
            headers: { 'Content-Type': 'application/json' },
        };
        if (body) options.body = JSON.stringify(body);

        const response = await fetch(`${API_BASE}${path}`, options);

        if (!response.ok) {
            const error = await response.json().catch(() => ({ detail: 'Unknown error' }));
            throw new Error(error.detail || `HTTP ${response.status}`);
        }

        return response.json();
    },

    // Status
    getStatus() { return this.request('GET', '/api/v1/status'); },

    // Settings
    getSettings() { return this.request('GET', '/api/v1/settings'); },
    updateISE(data) { return this.request('PUT', '/api/v1/settings/ise', data); },
    updateACME(data) { return this.request('PUT', '/api/v1/settings/acme', data); },
    updateCertificate(data) { return this.request('PUT', '/api/v1/settings/certificate', data); },
    updateDNS(data) { return this.request('PUT', '/api/v1/settings/dns', data); },
    updateSMTP(data) { return this.request('PUT', '/api/v1/settings/smtp', data); },
    updateScheduler(data) { return this.request('PUT', '/api/v1/settings/scheduler', data); },

    // Nodes
    getNodes() { return this.request('GET', '/api/v1/settings/nodes'); },
    addNode(data) { return this.request('POST', '/api/v1/settings/nodes', data); },
    updateNode(id, data) { return this.request('PUT', `/api/v1/settings/nodes/${id}`, data); },
    deleteNode(id) { return this.request('DELETE', `/api/v1/settings/nodes/${id}`); },

    // Discovery
    discoverNodes() { return this.request('POST', '/api/v1/settings/nodes/discover'); },
    syncNodes(nodes) { return this.request('POST', '/api/v1/settings/nodes/sync', nodes); },

    // Certificates
    getCertificates() { return this.request('GET', '/api/v1/settings/certificates'); },

    // Tests
    testISE() { return this.request('POST', '/api/v1/settings/test/ise'); },
    testERS() { return this.request('POST', '/api/v1/settings/test/ers'); },
    testDNS() { return this.request('POST', '/api/v1/settings/test/dns'); },

    // Actions
    triggerAction(action, modeOverride = null) {
        const body = { action };
        if (modeOverride) body.mode_override = modeOverride;
        return this.request('POST', '/api/v1/actions/run', body);
    },

    // History
    getHistory(page = 1, pageSize = 20, status = null) {
        let url = `/api/v1/history?page=${page}&page_size=${pageSize}`;
        if (status) url += `&status=${status}`;
        return this.request('GET', url);
    },
    getRunDetail(runId) { return this.request('GET', `/api/v1/history/${runId}`); },
    getRunLogs(runId) { return this.request('GET', `/api/v1/history/${runId}/logs`); },

    // Health
    getHealth() { return this.request('GET', '/health'); },

    // Managed Certificates
    getManagedCertificates() { return this.request('GET', '/api/v1/certificates'); },
    createManagedCertificate(data) { return this.request('POST', '/api/v1/certificates', data); },
    updateManagedCertificate(id, data) { return this.request('PUT', `/api/v1/certificates/${id}`, data); },
    deleteManagedCertificate(id) { return this.request('DELETE', `/api/v1/certificates/${id}`); },
};
