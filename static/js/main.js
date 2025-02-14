/**
 * VulnScan Frontend JavaScript
 * Handles user interactions, scan requests, and results display
 */

// Start a new vulnerability scan
function startScan() {
    const target = document.getElementById('target').value;
    if (!target) {
        showError('Please enter a target IP or domain');
        return;
    }

    // Hide the warning box with animation after first scan
    const warningBox = document.querySelector('.warning-box');
    if (warningBox) {
        warningBox.classList.add('hidden');
        // Remove from DOM after animation completes
        setTimeout(() => {
            warningBox.style.display = 'none';
        }, 300);
    }

    // Clear previous results and errors
    document.getElementById('scanResults').innerHTML = '';
    clearError();

    // Show loading and results section
    const results = document.getElementById('results');
    const loading = document.getElementById('loading');
    const scanResults = document.getElementById('scanResults');
    
    results.style.display = 'block';
    loading.style.display = 'flex';
    scanResults.style.display = 'none';

    // Send scan request to server
    const formData = new FormData();
    formData.append('target', target);

    fetch('/scan', {
        method: 'POST',
        body: formData
    })
    .then(response => {
        if (!response.ok) {
            return response.json().then(err => {
                throw new Error(err.error || 'Failed to scan target');
            });
        }
        return response.json();
    })
    .then(data => {
        loading.style.display = 'none';
        scanResults.style.display = 'block';
        displayResults(data);
        loadReports(); // Refresh reports list after new scan
    })
    .catch(error => {
        loading.style.display = 'none';
        scanResults.style.display = 'block';
        showError(error.message);
    });
}

/**
 * Truncate text to a specific length
 * @param {string} text - Text to truncate
 * @param {number} length - Maximum length
 * @returns {string} Truncated text
 */
function truncateText(text, length) {
    if (!text) return '';
    return text.length > length ? text.substring(0, length) + '...' : text;
}

/**
 * Display scan results in a formatted table
 * @param {Object} data - Scan results from server
 */
function displayResults(data) {
    const resultsDiv = document.getElementById('scanResults');
    let html = '<h3>Scan Results for ' + data.target + '</h3>';
    html += '<p>Scan completed at: ' + new Date(data.timestamp).toLocaleString() + '</p>';
    
    if (!data.ports || data.ports.length === 0) {
        html += '<p>No open ports found.</p>';
    } else {
        html += '<table class="table">';
        html += '<thead><tr><th>Port</th><th>Protocol</th><th>Service</th><th>Version</th><th>State</th><th>Vulnerabilities</th></tr></thead>';
        html += '<tbody>';
        
        data.ports.forEach(port => {
            html += '<tr>';
            html += `<td>${port.port || ''}</td>`;
            html += `<td>${port.protocol || ''}</td>`;
            html += `<td>${port.service || ''}</td>`;
            html += `<td>${port.version || ''}</td>`;
            html += `<td>${port.state || ''}</td>`;
            html += '<td class="vulnerability-cell">';
            
            if (port.vulnerabilities && port.vulnerabilities.vulnerabilities) {
                const vulns = port.vulnerabilities.vulnerabilities;
                // Sort vulnerabilities by severity
                vulns.sort((a, b) => {
                    const severityOrder = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 };
                    const severityA = extractSeverity(a);
                    const severityB = extractSeverity(b);
                    return severityOrder[severityB] - severityOrder[severityA];
                });

                // Show only top 2 vulnerabilities initially
                const initialVulns = vulns.slice(0, 2);
                const remainingCount = vulns.length - 2;

                initialVulns.forEach(vuln => {
                    const severity = extractSeverity(vuln);
                    const severityClass = getSeverityClass(severity);
                    const description = vuln.cve.descriptions[0]?.value || 'No description available';
                    
                    html += `<div class="vulnerability-item ${severityClass}">`;
                    html += `<div class="vulnerability-header">`;
                    html += `<span class="vulnerability-id">${vuln.cve.id}</span>`;
                    html += `<span class="severity-badge ${severityClass}">${severity}</span>`;
                    html += `</div>`;
                    html += `<div class="vulnerability-description">${truncateText(description, 100)}`;
                    html += `<button class="btn-link" onclick="showVulnerabilityDetails('${vuln.cve.id}', \`${description.replace(/`/g, '\\`')}\`, '${severity}')">More...</button>`;
                    html += `</div></div>`;
                });

                if (remainingCount > 0) {
                    html += `<button class="btn-accent btn-sm mt-2" onclick="showAllVulnerabilities('${port.port}', ${JSON.stringify(vulns).replace(/"/g, '&quot;')})">`;
                    html += `Show ${remainingCount} More Vulnerabilities</button>`;
                }
            } else {
                html += '<div class="text-muted">No vulnerabilities found</div>';
            }
            
            html += '</td>';
            html += '</tr>';
        });
        
        html += '</tbody></table>';
    }
    
    // Add modal for vulnerability details
    html += `
        <div id="vulnerabilityModal" class="modal">
            <div class="modal-content">
                <span class="close">&times;</span>
                <h4 id="modalTitle"></h4>
                <div id="modalBody"></div>
            </div>
        </div>
    `;
    
    resultsDiv.innerHTML = html;

    // Add modal close handler
    const modal = document.getElementById('vulnerabilityModal');
    const span = document.getElementsByClassName('close')[0];
    span.onclick = function() {
        modal.style.display = 'none';
    }
    window.onclick = function(event) {
        if (event.target == modal) {
            modal.style.display = 'none';
        }
    }
}

/**
 * Extract severity from vulnerability metrics
 */
function extractSeverity(vuln) {
    const metrics = vuln.cve?.metrics || {};
    
    if (metrics.cvssMetricV31) {
        return metrics.cvssMetricV31[0]?.cvssData?.baseSeverity;
    } else if (metrics.cvssMetricV30) {
        return metrics.cvssMetricV30[0]?.cvssData?.baseSeverity;
    } else if (metrics.cvssMetricV2) {
        const score = parseFloat(metrics.cvssMetricV2[0]?.cvssData?.baseScore || 0);
        if (score >= 9.0) return 'CRITICAL';
        else if (score >= 7.0) return 'HIGH';
        else if (score >= 4.0) return 'MEDIUM';
        else if (score > 0) return 'LOW';
    }
    return 'UNKNOWN';
}

/**
 * Toggle visibility of additional vulnerabilities
 * @param {string} portId - ID of the port's vulnerability container
 */
function toggleVulnerabilities(portId) {
    const container = document.getElementById(portId);
    const button = container.previousElementSibling;
    
    if (container.classList.contains('hidden')) {
        container.classList.remove('hidden');
        button.textContent = 'Show Less';
    } else {
        container.classList.add('hidden');
        button.textContent = `Show ${container.children.length} More`;
    }
}

/**
 * Get CSS class for vulnerability severity level
 * @param {string} severity - Vulnerability severity level
 * @returns {string} CSS class name
 */
function getSeverityClass(severity) {
    switch (severity.toUpperCase()) {
        case 'CRITICAL':
        case 'HIGH':
            return 'severity-high';
        case 'MEDIUM':
            return 'severity-medium';
        case 'LOW':
            return 'severity-low';
        default:
            return '';
    }
}

/**
 * Display error message to user
 * @param {string} message - Error message to display
 */
function showError(message) {
    const resultsDiv = document.getElementById('scanResults');
    resultsDiv.style.display = 'block';
    resultsDiv.innerHTML = `<div class="error-message">${message}</div>`;
}

/**
 * Clear any displayed error messages
 */
function clearError() {
    const resultsDiv = document.getElementById('scanResults');
    const errorDiv = resultsDiv.querySelector('.error-message');
    if (errorDiv) {
        errorDiv.remove();
    }
}

/**
 * Load and display available scan reports
 */
function loadReports() {
    fetch('/reports')
        .then(response => response.json())
        .then(reports => {
            const reportsListDiv = document.getElementById('reportsList');
            if (reports.length === 0) {
                reportsListDiv.innerHTML = '<p>No reports available</p>';
                return;
            }

            let html = '<ul class="list-group">';
            reports.forEach(report => {
                html += `
                    <li class="list-group-item d-flex justify-content-between align-items-center">
                        ${report}
                        <button class="btn-accent btn-sm" onclick="downloadReport('${report}')">Download</button>
                    </li>`;
            });
            html += '</ul>';
            reportsListDiv.innerHTML = html;
        })
        .catch(error => {
            document.getElementById('reportsList').innerHTML = 
                `<div class="error-message">Failed to load reports: ${error.message}</div>`;
        });
}

/**
 * Download a specific scan report
 * @param {string} filename - Name of the report file to download
 */
function downloadReport(filename) {
    window.location.href = `/download/${filename}`;
}

/**
 * Clear all scan reports
 */
function clearReports() {
    if (!confirm('Are you sure you want to delete all reports? This action cannot be undone.')) {
        return;
    }

    fetch('/clear-reports', {
        method: 'POST'
    })
    .then(response => {
        if (!response.ok) {
            return response.json().then(err => {
                throw new Error(err.error || 'Failed to clear reports');
            });
        }
        return response.json();
    })
    .then(data => {
        // Show success message
        const reportsListDiv = document.getElementById('reportsList');
        reportsListDiv.innerHTML = '<div class="success-message">' + data.message + '</div>';
        // Refresh reports list after a short delay
        setTimeout(loadReports, 2000);
    })
    .catch(error => {
        document.getElementById('reportsList').innerHTML = 
            `<div class="error-message">Failed to clear reports: ${error.message}</div>`;
    });
}

/**
 * Show vulnerability details in modal
 */
function showVulnerabilityDetails(id, description, severity) {
    const modal = document.getElementById('vulnerabilityModal');
    const title = document.getElementById('modalTitle');
    const body = document.getElementById('modalBody');

    title.innerHTML = `${id} <span class="severity-badge ${getSeverityClass(severity)}">${severity}</span>`;
    body.innerHTML = `<p>${description}</p>`;
    modal.style.display = 'block';
}

/**
 * Show all vulnerabilities for a port
 */
function showAllVulnerabilities(portId, vulnerabilities) {
    const modal = document.getElementById('vulnerabilityModal');
    const title = document.getElementById('modalTitle');
    const body = document.getElementById('modalBody');

    title.textContent = `All Vulnerabilities for Port ${portId}`;
    
    let html = '<div class="vulnerability-list">';
    vulnerabilities.forEach(vuln => {
        const severity = extractSeverity(vuln);
        const severityClass = getSeverityClass(severity);
        const description = vuln.cve.descriptions[0]?.value || 'No description available';
        
        html += `<div class="vulnerability-item ${severityClass}">`;
        html += `<div class="vulnerability-header">`;
        html += `<span class="vulnerability-id">${vuln.cve.id}</span>`;
        html += `<span class="severity-badge ${severityClass}">${severity}</span>`;
        html += `</div>`;
        html += `<div class="vulnerability-description">${description}</div>`;
        html += `</div>`;
    });
    html += '</div>';
    
    body.innerHTML = html;
    modal.style.display = 'block';
}

// Initialize when the page loads
document.addEventListener('DOMContentLoaded', function() {
    // Handle form submission
    document.getElementById('scanForm').addEventListener('submit', function(e) {
        e.preventDefault();
        startScan();
    });

    // Load initial reports
    loadReports();
});
