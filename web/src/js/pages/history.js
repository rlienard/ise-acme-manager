/**
 * History page — shows all certificate renewal history.
 */

const History = {
    currentPage: 1,
    pageSize: 15,
    statusFilter: null,

    async render() {
        try {
            const data = await api.getHistory(this.currentPage, this.pageSize, this.statusFilter);

            return `
            <div class="page-header">
                <h1><i class="fas fa-history"></i> Renewal History</h1>
                <div class="btn-group">
                    <select id="history-filter" onchange="History.filterByStatus(this.value)" style="
                        background:var(--input-bg);border:1px solid var(--border);
                        color:var(--text);padding:8px 14px;border-radius:8px;font-size:0.85rem">
                        <option value="" ${!this.statusFilter ? 'selected' : ''}>All Statuses</option>
                        <option value="success" ${this.statusFilter === 'success' ? 'selected' : ''}>Success</option>
                        <option value="failed" ${this.statusFilter === 'failed' ? 'selected' : ''}>Failed</option>
                        <option value="partial" ${this.statusFilter === 'partial' ? 'selected' : ''}>Partial</option>
                        <option value="skipped" ${this.statusFilter === 'skipped' ? 'selected' : ''}>Skipped</option>
                    </select>
                    <button class="btn btn-outline btn-sm" onclick="History.refresh()">
                        <i class="fas fa-sync-alt"></i> Refresh
                    </button>
                </div>
            </div>

            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Run ID</th>
                            <th>Status</th>
                            <th>Trigger</th>
                            <th>Mode</th>
                            <th>Common Name</th>
                            <th>Started</th>
                            <th>Duration</th>
                            <th>Nodes</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${data.items.length === 0 ? `
                        <tr>
                            <td colspan="9" style="text-align:center;padding:3rem;color:var(--text-muted)">
                                <i class="fas fa-inbox fa-2x" style="display:block;margin-bottom:1rem"></i>
                                No renewal history yet
                            </td>
                        </tr>` : data.items.map(item => this.renderRow(item)).join('')}
                    </tbody>
                </table>
            </div>

            ${data.total > this.pageSize ? this.renderPagination(data.total) : ''}

            <!-- Detail Modal -->
            <div id="history-modal" class="modal-overlay" style="display:none">
                <div class="modal-content">
                    <div class="modal-header">
                        <h3 id="modal-title">Renewal Details</h3>
                        <button class="btn btn-outline btn-sm" onclick="History.closeModal()">
                            <i class="fas fa-times"></i>
                        </button>
                    </div>
                    <div id="modal-body"></div>
                </div>
            </div>`;
        } catch (err) {
            return `<div class="settings-section" style="border-color:var(--danger)">
                <h2><i class="fas fa-exclamation-triangle" style="color:var(--danger)"></i> Error</h2>
                <p>Failed to load history: ${err.message}</p>
            </div>`;
        }
    },

    renderRow(item) {
        const statusBadge = {
            success: 'success', failed: 'danger', partial: 'warning',
            skipped: 'neutral', in_progress: 'info', pending: 'info'
        };

        const triggerIcons = {
            scheduled: 'clock', manual: 'hand-pointer', force: 'bolt'
        };

        const started = new Date(item.started_at).toLocaleString();
        const duration = item.duration_seconds
            ? (item.duration_seconds < 60
                ? `${Math.round(item.duration_seconds)}s`
                : `${Math.round(item.duration_seconds / 60)}m ${Math.round(item.duration_seconds % 60)}s`)
            : '—';

        const nodeCount = item.node_results ? Object.keys(item.node_results).length : 0;
        const nodeSuccess = item.node_results
            ? Object.values(item.node_results).filter(r => r.status === 'ok' || r.status === 'renewed').length
            : 0;

        return `
        <tr>
            <td><code style="font-size:0.8rem;color:var(--primary)">${item.run_id.substring(0, 8)}</code></td>
            <td><span class="badge ${statusBadge[item.status] || 'neutral'}">${item.status.toUpperCase()}</span></td>
            <td><i class="fas fa-${triggerIcons[item.trigger] || 'question'}" style="margin-right:4px;color:var(--text-muted)"></i>${item.trigger}</td>
            <td><span class="badge info">${item.mode}</span></td>
            <td>${item.common_name || '—'}</td>
            <td style="font-size:0.85rem">${started}</td>
            <td>${duration}</td>
            <td>${nodeCount > 0 ? `<span style="color:var(--success)">${nodeSuccess}</span>/${nodeCount}` : '—'}</td>
            <td>
                <button class="btn btn-outline btn-sm" onclick="History.showDetail('${item.run_id}')" title="View Details">
                    <i class="fas fa-eye"></i>
                </button>
                <button class="btn btn-outline btn-sm" onclick="History.showLogs('${item.run_id}')" title="View Logs">
                    <i class="fas fa-file-alt"></i>
                </button>
            </td>
        </tr>`;
    },

    renderPagination(total) {
        const totalPages = Math.ceil(total / this.pageSize);
        let buttons = '';

        buttons += `<button ${this.currentPage <= 1 ? 'disabled' : ''} onclick="History.goToPage(${this.currentPage - 1})">
            <i class="fas fa-chevron-left"></i>
        </button>`;

        for (let i = 1; i <= totalPages; i++) {
            if (i === 1 || i === totalPages || (i >= this.currentPage - 2 && i <= this.currentPage + 2)) {
                buttons += `<button class="${i === this.currentPage ? 'active' : ''}" onclick="History.goToPage(${i})">${i}</button>`;
            } else if (i === this.currentPage - 3 || i === this.currentPage + 3) {
                buttons += `<button disabled>...</button>`;
            }
        }

        buttons += `<button ${this.currentPage >= totalPages ? 'disabled' : ''} onclick="History.goToPage(${this.currentPage + 1})">
            <i class="fas fa-chevron-right"></i>
        </button>`;

        return `<div class="pagination">${buttons}</div>`;
    },

    async showDetail(runId) {
        try {
            const detail = await api.getRunDetail(runId);

            let nodeRows = '';
            if (detail.node_results) {
                for (const [node, result] of Object.entries(detail.node_results)) {
                    const status = result.status || 'unknown';
                    const badgeClass = status === 'ok' || status === 'renewed' ? 'success' : status === 'failed' ? 'danger' : 'neutral';
                    const errorMsg = result.error ? `<br><small style="color:var(--danger)">${result.error}</small>` : '';
                    const daysMsg = result.days_remaining !== undefined ? ` (${result.days_remaining} days remaining)` : '';

                    nodeRows += `
                    <tr>
                        <td><strong>${node}</strong></td>
                        <td><span class="badge ${badgeClass}">${status.toUpperCase()}</span>${daysMsg}</td>
                        <td>${result.certificate_id || '—'}${errorMsg}</td>
                    </tr>`;
                }
            }

            document.getElementById('modal-title').textContent = `Renewal Run: ${runId.substring(0, 8)}`;
            document.getElementById('modal-body').innerHTML = `
                <div class="form-grid" style="margin-bottom:1.5rem">
                    <div class="form-group">
                        <label>Status</label>
                        <span class="badge ${detail.status === 'success' ? 'success' : detail.status === 'failed' ? 'danger' : 'warning'}" style="width:fit-content">${detail.status.toUpperCase()}</span>
                    </div>
                    <div class="form-group">
                        <label>Trigger</label>
                        <span>${detail.trigger}</span>
                    </div>
                    <div class="form-group">
                        <label>Mode</label>
                        <span>${detail.mode}</span>
                    </div>
                    <div class="form-group">
                        <label>Duration</label>
                        <span>${detail.duration_seconds ? Math.round(detail.duration_seconds) + 's' : '—'}</span>
                    </div>
                    <div class="form-group">
                        <label>Started</label>
                        <span>${new Date(detail.started_at).toLocaleString()}</span>
                    </div>
                    <div class="form-group">
                        <label>Completed</label>
                        <span>${detail.completed_at ? new Date(detail.completed_at).toLocaleString() : '—'}</span>
                    </div>
                </div>

                ${detail.error_message ? `
                <div style="background:rgba(231,76,60,0.1);border:1px solid var(--danger);border-radius:8px;padding:1rem;margin-bottom:1.5rem">
                    <strong style="color:var(--danger)">Error:</strong>
                    <pre style="color:var(--danger);margin-top:0.5rem;white-space:pre-wrap;font-size:0.85rem">${detail.error_message}</pre>
                </div>` : ''}

                <h3 style="margin-bottom:0.75rem"><i class="fas fa-network-wired" style="color:var(--primary);margin-right:8px"></i>Node Results</h3>
                <div class="table-container">
                    <table>
                        <thead><tr><th>Node</th><th>Status</th><th>Certificate ID</th></tr></thead>
                        <tbody>${nodeRows || '<tr><td colspan="3" style="text-align:center;color:var(--text-muted)">No node results</td></tr>'}</tbody>
                    </table>
                </div>

                <div style="margin-top:1rem;display:flex;gap:0.5rem">
                    <span class="badge ${detail.dns_challenge_created ? 'success' : 'neutral'}">DNS Challenge: ${detail.dns_challenge_created ? 'Created' : 'No'}</span>
                    <span class="badge ${detail.dns_challenge_cleaned ? 'success' : 'neutral'}">DNS Cleanup: ${detail.dns_challenge_cleaned ? 'Done' : 'No'}</span>
                    <span class="badge ${detail.notification_sent ? 'success' : 'neutral'}">Notification: ${detail.notification_sent ? 'Sent' : 'No'}</span>
                </div>`;

            document.getElementById('history-modal').style.display = 'flex';
        } catch (err) {
            Toast.error('Failed to load details: ' + err.message);
        }
    },

    async showLogs(runId) {
        try {
            const data = await api.getRunLogs(runId);
            document.getElementById('modal-title').textContent = `Logs: ${runId.substring(0, 8)}`;
            document.getElementById('modal-body').innerHTML = `
                <pre style="background:var(--dark);padding:1rem;border-radius:8px;
                    max-height:500px;overflow:auto;font-size:0.8rem;line-height:1.6;
                    white-space:pre-wrap;word-break:break-all">${data.logs || 'No logs available'}</pre>`;
            document.getElementById('history-modal').style.display = 'flex';
        } catch (err) {
            Toast.error('Failed to load logs: ' + err.message);
        }
    },

    closeModal() {
        document.getElementById('history-modal').style.display = 'none';
    },

    filterByStatus(status) {
        this.statusFilter = status || null;
        this.currentPage = 1;
        App.navigate('history');
    },

    goToPage(page) {
        this.currentPage = page;
        App.navigate('history');
    },

    async refresh() {
        App.navigate('history');
        Toast.info('History refreshed');
    }
};
