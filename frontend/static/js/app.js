// =========================================================
// SENTINELAI DASHBOARD
// =========================================================

const uploadButton = document.getElementById("uploadButton");
const projectFile = document.getElementById("projectFile");
const uploadArea = document.getElementById("uploadArea");
const newScanButton = document.getElementById("newScanButton");
const navNewScan = document.getElementById("navNewScan");

// Dashboard elements
const totalScansElement = document.getElementById("totalScans");
const totalProjectsElement = document.getElementById("totalProjects");
const totalVulnerabilitiesElement = document.getElementById("totalVulnerabilities");
const securityScoreElement = document.getElementById("securityScore");

const criticalCountElement = document.getElementById("criticalCount");
const highCountElement = document.getElementById("highCount");
const mediumCountElement = document.getElementById("mediumCount");
const lowCountElement = document.getElementById("lowCount");
const infoCountElement = document.getElementById("infoCount");

const vulnerabilityReportContainer =
    document.getElementById("vulnerabilityReportContainer");

const severityFilter =
    document.getElementById("severityFilter");

// =========================================================
// GLOBAL DATA
// =========================================================

let currentVulnerabilities = [];
let latestScanId = null;

// =========================================================
// OPEN FILE SELECTOR
// =========================================================

if (uploadButton) {
    uploadButton.addEventListener("click", function () {
        if (projectFile) {
            projectFile.click();
        }
    });
}

if (newScanButton) {
    newScanButton.addEventListener("click", function () {
        if (projectFile) {
            projectFile.click();
        }
    });
}

if (navNewScan) {
    navNewScan.addEventListener("click", function () {
        if (projectFile) {
            projectFile.click();
        }
    });
}

// =========================================================
// UPLOAD PROJECT
// =========================================================

if (projectFile) {
    projectFile.addEventListener("change", async function () {
        if (!projectFile.files || projectFile.files.length === 0) {
            return;
        }

        const file = projectFile.files[0];

        if (!file.name.toLowerCase().endsWith(".zip")) {
            alert("Please select a ZIP file.");
            projectFile.value = "";
            return;
        }

        if (uploadArea) {
            const heading = uploadArea.querySelector("h3");
            const paragraph = uploadArea.querySelector("p");

            if (heading) {
                heading.innerText = file.name;
            }

            if (paragraph) {
                paragraph.innerText = "Uploading and scanning project...";
            }
        }

        if (uploadButton) {
            uploadButton.disabled = true;
            uploadButton.innerText = "Scanning...";
        }

        const formData = new FormData();
        formData.append("file", file);

        try {
            const response = await fetch("/api/upload", {
                method: "POST",
                body: formData
            });

            const result = await response.json();

            if (!response.ok) {
                throw new Error(
                    result.detail || "Upload failed"
                );
            }

            latestScanId = result.scan_id;

            if (uploadArea) {
                const heading = uploadArea.querySelector("h3");
                const paragraph = uploadArea.querySelector("p");

                if (heading) {
                    heading.innerText = "Scan Completed Successfully";
                }

                if (paragraph) {
                    paragraph.innerText =
                        result.project_name + " scanned successfully";
                }
            }

            if (uploadButton) {
                uploadButton.innerText = "Upload Another Project";
            }

            console.log("Scan result:", result);

            // Refresh dashboard
            await loadDashboardStats();
            await loadRecentScans();

            // Load vulnerabilities from the latest scan only
            await loadVulnerabilityReports(result.scan_id);

            alert(
                "Project scanned successfully!\n\n" +
                "Project: " + result.project_name + "\n" +
                "Scan ID: " + result.scan_id + "\n" +
                "Files Scanned: " + result.files_scanned + "\n" +
                "Vulnerabilities: " + result.total_findings + "\n" +
                "Security Score: " + result.security_score
            );

        } catch (error) {
            if (uploadArea) {
                const heading = uploadArea.querySelector("h3");
                const paragraph = uploadArea.querySelector("p");

                if (heading) {
                    heading.innerText = "Upload Failed";
                }

                if (paragraph) {
                    paragraph.innerText = error.message;
                }
            }

            if (uploadButton) {
                uploadButton.innerText = "Try Again";
            }

            alert("Upload error: " + error.message);
            console.error(error);

        } finally {
            if (uploadButton) {
                uploadButton.disabled = false;
            }

            projectFile.value = "";
        }
    });
}

// =========================================================
// LOAD DASHBOARD STATISTICS
// =========================================================

async function loadDashboardStats() {
    try {
        const response = await fetch("/api/dashboard/stats");
        const data = await response.json();

        if (!response.ok) {
            throw new Error(
                data.detail || "Failed to load dashboard"
            );
        }

        if (totalScansElement) {
            totalScansElement.innerText = data.total_scans ?? 0;
        }

        if (totalProjectsElement) {
            totalProjectsElement.innerText = data.total_projects ?? 0;
        }

        if (totalVulnerabilitiesElement) {
            totalVulnerabilitiesElement.innerText =
                data.total_vulnerabilities ?? 0;
        }

        if (securityScoreElement) {
            securityScoreElement.innerText =
                data.security_score !== null
                    ? data.security_score + "/100"
                    : "--";
        }

        const severityCounts = data.severity_counts || {};

        const critical = severityCounts.CRITICAL ?? 0;
        const high = severityCounts.HIGH ?? 0;
        const medium = severityCounts.MEDIUM ?? 0;
        const low = severityCounts.LOW ?? 0;
        const info = severityCounts.INFO ?? 0;

        if (criticalCountElement) {
            criticalCountElement.innerText = critical;
        }

        if (highCountElement) {
            highCountElement.innerText = high;
        }

        if (mediumCountElement) {
            mediumCountElement.innerText = medium;
        }

        if (lowCountElement) {
            lowCountElement.innerText = low;
        }

        if (infoCountElement) {
            infoCountElement.innerText = info;
        }

        // Update severity progress bars
        const total =
            critical + high + medium + low + info;

        updateProgressBar("criticalProgress", critical, total);
        updateProgressBar("highProgress", high, total);
        updateProgressBar("mediumProgress", medium, total);
        updateProgressBar("lowProgress", low, total);
        updateProgressBar("infoProgress", info, total);

        console.log("Dashboard statistics loaded:", data);

    } catch (error) {
        console.error("Dashboard statistics error:", error);
    }
}

// =========================================================
// UPDATE SEVERITY PROGRESS BARS
// =========================================================

function updateProgressBar(elementId, count, total) {
    const element = document.getElementById(elementId);

    if (!element) {
        return;
    }

    const percentage = total > 0
        ? (count / total) * 100
        : 0;

    element.style.width = percentage + "%";
}

// =========================================================
// LOAD RECENT SCANS
// =========================================================

async function loadRecentScans() {
    try {
        const response = await fetch("/api/dashboard/recent-scans");
        const data = await response.json();

        if (!response.ok) {
            throw new Error(
                data.detail || "Failed to load recent scans"
            );
        }

        displayRecentScans(data.recent_scans || []);

        // Determine the latest scan
        if (data.recent_scans && data.recent_scans.length > 0) {
            latestScanId = data.recent_scans[0].scan_id;
        } else {
            latestScanId = null;
        }

        console.log("Recent scans loaded:", data);

    } catch (error) {
        console.error("Recent scans error:", error);
    }
}

// =========================================================
// DISPLAY RECENT SCANS
// =========================================================

function displayRecentScans(scans) {
    const container =
        document.getElementById("recentScansContainer");

    if (!container) {
        console.error("Recent scans container not found");
        return;
    }

    if (!scans || scans.length === 0) {
        container.innerHTML = `
            <div class="empty-message">
                <h3>No scans yet</h3>
                <p>Your scan history will appear here once you analyze your first project.</p>
            </div>
        `;

        return;
    }

    let tableHTML = `
        <div class="recent-scans-table-wrapper">
            <table class="recent-scans-table">
                <thead>
                    <tr>
                        <th>Scan ID</th>
                        <th>Project</th>
                        <th>Files</th>
                        <th>Findings</th>
                        <th>Security Score</th>
                        <th>Status</th>
                        <th>Date</th>
                    </tr>
                </thead>
                <tbody>
    `;

    scans.forEach(function (scan) {
        const score =
            scan.security_score !== null
                ? scan.security_score + "/100"
                : "--";

        const status = scan.scan_status || "UNKNOWN";

        const date = scan.created_at
            ? new Date(scan.created_at).toLocaleString()
            : "--";

        tableHTML += `
            <tr>
                <td>#${escapeHTML(scan.scan_id)}</td>
                <td>${escapeHTML(scan.project_name)}</td>
                <td>${escapeHTML(scan.files_scanned ?? 0)}</td>
                <td>
                    <span class="finding-badge">
                        ${escapeHTML(scan.total_findings ?? 0)}
                    </span>
                </td>
                <td>
                    <strong>${escapeHTML(score)}</strong>
                </td>
                <td>
                    <span class="status-badge ${escapeHTML(status.toLowerCase())}">
                        ${escapeHTML(status)}
                    </span>
                </td>
                <td>${escapeHTML(date)}</td>
            </tr>
        `;
    });

    tableHTML += `
                </tbody>
            </table>
        </div>
    `;

    container.innerHTML = tableHTML;
}

// =========================================================
// LOAD VULNERABILITY REPORTS
// LATEST SCAN ONLY
// =========================================================

async function loadVulnerabilityReports(scanId = null) {
    if (!vulnerabilityReportContainer) {
        return;
    }

    try {
        // If no scan ID is supplied, use latest scan
        if (scanId === null) {
            scanId = latestScanId;
        }

        // No scans available
        if (!scanId) {
            vulnerabilityReportContainer.innerHTML = `
                <div class="vulnerability-empty-state">
                    <div class="empty-icon">⚠</div>
                    <h3>No vulnerability reports available</h3>
                    <p>Upload and scan a project to view security findings.</p>
                </div>
            `;

            currentVulnerabilities = [];
            displayVulnerabilityReports();

            return;
        }

        const response = await fetch(
            `/api/dashboard/vulnerabilities?scan_id=${encodeURIComponent(scanId)}`
        );

        const data = await response.json();

        if (!response.ok || !data.success) {
            throw new Error(
                data.message || "Failed to load vulnerability reports"
            );
        }

        currentVulnerabilities = data.vulnerabilities || [];

        displayVulnerabilityReports();

        console.log(
            "Latest scan vulnerability reports loaded:",
            data
        );

    } catch (error) {
        console.error(
            "Failed to load vulnerability reports:",
            error
        );

        vulnerabilityReportContainer.innerHTML = `
            <div class="vulnerability-empty-state">
                <h3>Unable to load vulnerability reports</h3>
                <p>Please check your backend connection.</p>
            </div>
        `;
    }
}

// =========================================================
// SEVERITY FILTER
// =========================================================

if (severityFilter) {
    severityFilter.addEventListener("change", function () {
        displayVulnerabilityReports();
    });
}

// =========================================================
// DISPLAY VULNERABILITY REPORTS
// =========================================================

function displayVulnerabilityReports() {
    if (!vulnerabilityReportContainer) {
        return;
    }

    const selectedSeverity = severityFilter
        ? severityFilter.value
        : "ALL";

    let filteredVulnerabilities = currentVulnerabilities;

    if (selectedSeverity !== "ALL") {
        filteredVulnerabilities = currentVulnerabilities.filter(
            function (vulnerability) {
                return (
                    (vulnerability.severity || "").toUpperCase() ===
                    selectedSeverity.toUpperCase()
                );
            }
        );
    }

    // No vulnerabilities in the latest scan
    if (currentVulnerabilities.length === 0) {
        vulnerabilityReportContainer.innerHTML = `
            <div class="vulnerability-empty-state">
                <div class="empty-icon">✓</div>
                <h3>No vulnerabilities found</h3>
                <p>The latest scan did not detect any security findings.</p>
            </div>
        `;

        return;
    }

    // No results for selected severity
    if (filteredVulnerabilities.length === 0) {
        vulnerabilityReportContainer.innerHTML = `
            <div class="vulnerability-empty-state">
                <h3>No ${escapeHTML(selectedSeverity)} findings</h3>
                <p>Try selecting another severity level.</p>
            </div>
        `;

        return;
    }

    vulnerabilityReportContainer.innerHTML =
        filteredVulnerabilities.map(function (vulnerability) {
            const severity =
                (vulnerability.severity || "LOW").toUpperCase();

            return `
                <div class="vulnerability-card">
                    <div class="vulnerability-card-header">
                        <div>
                            <span class="severity-badge ${escapeHTML(severity.toLowerCase())}">
                                ${escapeHTML(severity)}
                            </span>

                            <h3>
                                ${escapeHTML(vulnerability.title)}
                            </h3>
                        </div>

                        <span class="report-scan-id">
                            Scan #${escapeHTML(vulnerability.scan_id)}
                        </span>
                    </div>

                    <div class="vulnerability-meta">
                        <span>
                            Project:
                            ${escapeHTML(vulnerability.project_name)}
                        </span>

                        <span>
                            File:
                            ${escapeHTML(vulnerability.file_path)}
                        </span>

                        <span>
                            Line:
                            ${escapeHTML(vulnerability.line_number ?? "N/A")}
                        </span>
                    </div>

                    <div class="vulnerability-details">
                        <div class="report-detail">
                            <h4>Description</h4>
                            <p>
                                ${escapeHTML(
                                    vulnerability.description ||
                                    "No description available."
                                )}
                            </p>
                        </div>

                        <div class="report-detail">
                            <h4>Potential Impact</h4>
                            <p>
                                ${escapeHTML(
                                    vulnerability.impact ||
                                    "No impact information available."
                                )}
                            </p>
                        </div>

                        <div class="report-detail recommendation">
                            <h4>Recommendation</h4>
                            <p>
                                ${escapeHTML(
                                    vulnerability.recommendation ||
                                    "No recommendation available."
                                )}
                            </p>
                        </div>

                        ${
                            vulnerability.code_snippet
                            ? `
                                <div class="report-detail">
                                    <h4>Code Snippet</h4>
                                    <pre><code>${escapeHTML(
                                        vulnerability.code_snippet
                                    )}</code></pre>
                                </div>
                            `
                            : ""
                        }
                    </div>

                    <div class="vulnerability-card-footer">
                        <span>
                            OWASP:
                            ${escapeHTML(
                                vulnerability.owasp_id || "N/A"
                            )}
                        </span>

                        <span>
                            Confidence:
                            ${escapeHTML(
                                vulnerability.confidence || "N/A"
                            )}
                        </span>

                        <span>
                            Status:
                            ${escapeHTML(
                                vulnerability.status || "OPEN"
                            )}
                        </span>
                    </div>
                </div>
            `;
        }).join("");
}

// =========================================================
// HTML ESCAPE
// =========================================================

function escapeHTML(value) {
    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

// =========================================================
// CHECK BACKEND
// =========================================================

async function checkSystem() {
    try {
        const response = await fetch("/api/health");
        const data = await response.json();

        console.log("Backend status:", data.status);

    } catch (error) {
        console.log("Backend unavailable");
    }
}

// =========================================================
// INITIALIZE DASHBOARD
// =========================================================

async function initializeDashboard() {
    await checkSystem();
    await loadDashboardStats();
    await loadRecentScans();
    await loadVulnerabilityReports(latestScanId);
}

initializeDashboard();