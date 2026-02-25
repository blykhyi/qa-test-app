const API = '';
const SCANNER_API = 'http://localhost:8001';
let findingsCache = [];
let vulnsCache = {};

document.addEventListener('DOMContentLoaded', () => {
    loadSummary();
    loadFindings();
    loadAssets();
    loadVulnerabilities();
});

// ========== Summary ==========

async function loadSummary() {
    try {
        const resp = await fetch(`${API}/stats/summary`);
        const data = await resp.json();

        const active = data.total_findings - data.resolved_findings - data.false_positive_findings;
        document.getElementById('total-count').textContent = active;
        document.getElementById('critical-count').textContent = data.by_severity.critical || 0;
        document.getElementById('high-count').textContent = data.by_severity.high || 0;
        document.getElementById('medium-count').textContent = data.by_severity.medium || 0;
        document.getElementById('low-count').textContent = data.by_severity.low || 0;

        document.getElementById('last-updated').textContent =
            'Updated: ' + new Date().toLocaleTimeString();
    } catch (err) {
        console.error('Failed to load summary:', err);
    }
}

// ========== Vulnerabilities Cache ==========

async function loadVulnerabilities() {
    try {
        const resp = await fetch(`${API}/vulnerabilities`);
        const data = await resp.json();
        data.forEach(v => { vulnsCache[v.id] = v; });
    } catch (err) {
        console.error('Failed to load vulns:', err);
    }
}

// ========== Findings ==========

async function loadFindings() {
    try {
        let url = `${API}/findings?per_page=50`;
        const severity = document.getElementById('filter-severity').value;
        const status = document.getElementById('filter-status').value;
        if (severity) url += `&severity=${severity}`;
        if (status) url += `&status=${status}`;

        const resp = await fetch(url);
        const data = await resp.json();
        findingsCache = data.items;
        renderFindings(data.items);
    } catch (err) {
        console.error('Failed to load findings:', err);
    }
}

function renderFindings(findings) {
    const tbody = document.getElementById('findings-table');
    if (!findings || findings.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:#64748b;padding:30px">No findings match your filters</td></tr>';
        return;
    }

    tbody.innerHTML = findings.map(f => {
        const vuln = vulnsCache[f.vulnerability_id] || {};
        return `
        <tr>
            <td class="text-muted">#${f.id}</td>
            <td><span class="cve-link">${vuln.cve_id || '—'}</span></td>
            <td>${vuln.title || 'Unknown'}</td>
            <td><span class="severity severity-${vuln.severity || 'low'}">${vuln.severity || '—'}</span></td>
            <td>${vuln.cvss_score != null ? vuln.cvss_score.toFixed(1) : '—'}</td>
            <td>${f.asset_id}</td>
            <td><span class="status status-${f.status}">${f.status.replace('_', ' ')}</span></td>
            <td>
                <select class="status-select" onchange="updateStatus(${f.id}, this.value)">
                    <option value="" disabled selected>Change…</option>
                    <option value="open">Open</option>
                    <option value="confirmed">Confirmed</option>
                    <option value="in_progress">In Progress</option>
                    <option value="resolved">Resolved</option>
                    <option value="false_positive">False Positive</option>
                </select>
            </td>
        </tr>`;
    }).join('');
}

async function updateStatus(findingId, newStatus) {
    const msgDiv = document.getElementById('findings-message');
    try {
        const resp = await fetch(`${API}/findings/${findingId}/status`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status: newStatus }),
        });

        if (!resp.ok) {
            const err = await resp.json();
            msgDiv.innerHTML = `<div class="message message-error">${err.detail || 'Update failed'}</div>`;
            return;
        }

        msgDiv.innerHTML = `<div class="message message-success">Finding #${findingId} updated to ${newStatus}</div>`;

        // BUG #8: Not refreshing the findings table or summary after status update
        // A correct implementation would call:
        // loadFindings();
        // loadSummary();

    } catch (err) {
        msgDiv.innerHTML = `<div class="message message-error">Error: ${err.message}</div>`;
    }
}

// ========== Assets ==========

async function loadAssets() {
    try {
        const resp = await fetch(`${SCANNER_API}/assets?per_page=50`);
        const data = await resp.json();
        renderAssets(data.items);
    } catch (err) {
        console.error('Failed to load assets:', err);
    }
}

function renderAssets(assets) {
    const tbody = document.getElementById('assets-table');
    if (!assets || assets.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:#64748b">No assets</td></tr>';
        return;
    }

    const envColors = {
        production: '#ef4444',
        staging: '#eab308',
        development: '#3b82f6',
    };

    tbody.innerHTML = assets.map(a => `
        <tr>
            <td>${a.hostname}</td>
            <td class="text-muted">${a.ip_address || '—'}</td>
            <td>${a.asset_type}</td>
            <td><span style="color:${envColors[a.environment] || '#94a3b8'}">${a.environment}</span></td>
        </tr>
    `).join('');
}
