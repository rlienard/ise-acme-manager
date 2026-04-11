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
    getSystemInfo() { return this.request('GET', '/api/v1/settings/system'); },
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

    // Certificates (fetched from ISE)
    getCertificates() { return this.request('GET', '/api/v1/settings/certificates'); },
    inspectCertificate(nodeId, certId) {
        return this.request('GET', `/api/v1/settings/certificates/${nodeId}/${encodeURIComponent(certId)}/inspect`);
    },
    getPortalGroupTags() { return this.request('GET', '/api/v1/settings/portal-group-tags'); },

    // Tests
    testISE(data) { return this.request('POST', '/api/v1/settings/test/ise', data || null); },
    testERS(data) { return this.request('POST', '/api/v1/settings/test/ers', data || null); },
    testDNS() { return this.request('POST', '/api/v1/settings/test/dns'); },
    testSMTP(data) { return this.request('POST', '/api/v1/settings/test/smtp', data || null); },

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

    /**
     * Request a new certificate from an ACME provider and push it to ISE,
     * consuming the Server-Sent Events stream returned by the daemon.
     *
     * @param {object} payload Request payload (CN, SANs, provider, nodes…)
     * @param {object} handlers { onLog, onComplete, onError } callbacks
     * @returns {Promise<void>} Resolves when the stream is fully consumed.
     */
    async requestCertificateStream(payload, handlers = {}) {
        const { onLog, onComplete, onError } = handlers;
        let response;
        try {
            response = await fetch(`${API_BASE}/api/v1/certificates/request`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'text/event-stream',
                },
                body: JSON.stringify(payload),
            });
        } catch (err) {
            if (onError) onError(err);
            throw err;
        }

        if (!response.ok) {
            let detail = `HTTP ${response.status}`;
            try {
                const body = await response.json();
                detail = body.detail || detail;
            } catch (_) { /* ignore */ }
            const err = new Error(detail);
            if (onError) onError(err);
            throw err;
        }

        const reader = response.body.getReader();
        const decoder = new TextDecoder('utf-8');
        let buffer = '';

        // Parse SSE frames: each frame is delimited by a blank line, and
        // contains `event:` and `data:` fields.
        const processFrame = (frame) => {
            let eventType = 'message';
            let dataLines = [];
            frame.split('\n').forEach(line => {
                if (line.startsWith('event:')) {
                    eventType = line.slice(6).trim();
                } else if (line.startsWith('data:')) {
                    dataLines.push(line.slice(5).trim());
                }
            });
            if (!dataLines.length) return;
            let data;
            try {
                data = JSON.parse(dataLines.join('\n'));
            } catch (e) {
                console.warn('Malformed SSE frame:', dataLines.join('\n'));
                return;
            }
            if (eventType === 'log' && onLog) onLog(data);
            else if (eventType === 'complete' && onComplete) onComplete(data);
            else if (eventType === 'cert_obtained' && handlers.onCertObtained) handlers.onCertObtained(data);
        };

        try {
            while (true) {
                const { value, done } = await reader.read();
                if (done) break;
                buffer += decoder.decode(value, { stream: true });
                let idx;
                while ((idx = buffer.indexOf('\n\n')) !== -1) {
                    const frame = buffer.slice(0, idx);
                    buffer = buffer.slice(idx + 2);
                    if (frame.trim()) processFrame(frame);
                }
            }
            if (buffer.trim()) processFrame(buffer);
        } catch (err) {
            if (onError) onError(err);
            throw err;
        }
    },

    /**
     * Stream ISE import progress after a certificate has been obtained via
     * ACME.  Calls onLog for each progress event and onComplete when done.
     */
    async pushCertToIseStream(payload, handlers = {}) {
        const { onLog, onComplete, onError } = handlers;
        let response;
        try {
            response = await fetch(`${API_BASE}/api/v1/certificates/push-to-ise`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'text/event-stream',
                },
                body: JSON.stringify(payload),
            });
        } catch (err) {
            if (onError) onError(err);
            throw err;
        }

        if (!response.ok) {
            let detail = `HTTP ${response.status}`;
            try {
                const body = await response.json();
                detail = body.detail || detail;
            } catch (_) { /* ignore */ }
            const err = new Error(detail);
            if (onError) onError(err);
            throw err;
        }

        const reader = response.body.getReader();
        const decoder = new TextDecoder('utf-8');
        let buffer = '';

        const processFrame = (frame) => {
            let eventType = 'message';
            let dataLines = [];
            frame.split('\n').forEach(line => {
                if (line.startsWith('event:')) {
                    eventType = line.slice(6).trim();
                } else if (line.startsWith('data:')) {
                    dataLines.push(line.slice(5).trim());
                }
            });
            if (!dataLines.length) return;
            let data;
            try {
                data = JSON.parse(dataLines.join('\n'));
            } catch (e) {
                console.warn('Malformed SSE frame:', dataLines.join('\n'));
                return;
            }
            if (eventType === 'log' && onLog) onLog(data);
            else if (eventType === 'complete' && onComplete) onComplete(data);
        };

        try {
            while (true) {
                const { value, done } = await reader.read();
                if (done) break;
                buffer += decoder.decode(value, { stream: true });
                let idx;
                while ((idx = buffer.indexOf('\n\n')) !== -1) {
                    const frame = buffer.slice(0, idx);
                    buffer = buffer.slice(idx + 2);
                    if (frame.trim()) processFrame(frame);
                }
            }
            if (buffer.trim()) processFrame(buffer);
        } catch (err) {
            if (onError) onError(err);
            throw err;
        }
    },

    /**
     * Download a ZIP bundle containing the certificate (PEM) and private key.
     * When the pre-split components (leafPem, intermediatePem, rootPem,
     * caChainPem) are provided, they are included as separate files in the
     * archive.  Triggers a browser file-save dialog.
     */
    async downloadCertBundle(certPem, keyPem, commonName, leafPem, intermediatePem, rootPem, caChainPem) {
        const body = { cert_pem: certPem, key_pem: keyPem, common_name: commonName };
        if (leafPem) body.leaf_pem = leafPem;
        if (intermediatePem) body.intermediate_pem = intermediatePem;
        if (rootPem) body.root_pem = rootPem;
        if (caChainPem) body.ca_chain_pem = caChainPem;
        const response = await fetch(`${API_BASE}/api/v1/certificates/download-bundle`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${commonName}-bundle.zip`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    },

    /**
     * Parse a PEM bundle and return a human-readable summary of each
     * certificate.  Used by the frontend to show the content of the
     * leaf / CA chain before the user confirms an ISE push.
     */
    decodeCertificateChain(pem) {
        return this.request('POST', '/api/v1/certificates/decode-chain', { pem });
    },

    // ACME Providers
    getACMEProviders() { return this.request('GET', '/api/v1/acme-providers'); },
    getACMEProvider(id) { return this.request('GET', `/api/v1/acme-providers/${id}`); },
    createACMEProvider(data) { return this.request('POST', '/api/v1/acme-providers', data); },
    updateACMEProvider(id, data) { return this.request('PUT', `/api/v1/acme-providers/${id}`, data); },
    deleteACMEProvider(id) { return this.request('DELETE', `/api/v1/acme-providers/${id}`); },
    testACMEProvider(id) { return this.request('POST', `/api/v1/acme-providers/${id}/test`); },

    // DNS Providers
    getDNSProviders() { return this.request('GET', '/api/v1/dns-providers'); },
    getDNSProvider(id) { return this.request('GET', `/api/v1/dns-providers/${id}`); },
    createDNSProvider(data) { return this.request('POST', '/api/v1/dns-providers', data); },
    updateDNSProvider(id, data) { return this.request('PUT', `/api/v1/dns-providers/${id}`, data); },
    deleteDNSProvider(id) { return this.request('DELETE', `/api/v1/dns-providers/${id}`); },
    testDNSProvider(id) { return this.request('POST', `/api/v1/dns-providers/${id}/test`); },
    requestOVHConsumerKey(data) { return this.request('POST', '/api/v1/dns-providers/ovh/request-consumer-key', data); },
};
