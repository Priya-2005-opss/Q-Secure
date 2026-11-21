async function secureFetch(url, options = {}) {
    const method = (options.method || "GET").toUpperCase();
    const headers = new Headers(options.headers || {});

    if (!["GET", "HEAD", "OPTIONS", "TRACE"].includes(method)) {
        const tokenResponse = await fetch("/api/auth/csrf", {
            method: "GET",
            credentials: "same-origin",
            cache: "no-store"
        });

        if (!tokenResponse.ok) {
            throw new Error("Unable to obtain CSRF security token.");
        }

        const csrfData = await tokenResponse.json();
        headers.set("X-CSRF-TOKEN", csrfData.token);
    }

    return fetch(url, {
        ...options,
        headers,
        credentials: "same-origin"
    });
}

/* ==========================================
   EMAIL THREAT ANALYSIS
========================================== */

async function analyzeEmail() {
    const email = document.getElementById("emailInput").value.trim();
    const button = document.getElementById("analyzeBtn");
    const message = document.getElementById("message");

    if (!email) {
        message.textContent = "Please paste an email before analyzing.";
        return;
    }

    button.disabled = true;
    button.textContent = "Analyzing...";

    try {
        message.textContent = "Step 1/3: Preparing email for analysis...";
        await new Promise(resolve => setTimeout(resolve, 700));

        message.textContent = "Step 2/3: Scanning email for security threats...";

        const response = await secureFetch("/api/email/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "same-origin",
            body: JSON.stringify({ emailText: email })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.message || "Email analysis failed.");
        }

        message.textContent = "Step 3/3: Generating security report...";
        await new Promise(resolve => setTimeout(resolve, 700));

        displayResults(data);

        message.textContent = "✓ Email analysis completed successfully.";

    } catch (error) {
        message.textContent = "Error: " + error.message;
    } finally {
        button.disabled = false;
        button.textContent = "Analyze Email →";
    }
}


function displayResults(data) {
    const resultsSection = document.getElementById("results");
    const quantumSection = document.getElementById("quantum");

    resultsSection.classList.remove("hidden");
    quantumSection.classList.remove("hidden");

    document.getElementById("riskScore").textContent = data.riskScore;

    const badge = document.getElementById("threatBadge");
    badge.textContent = data.threatLevel;

    const colors = {
        LOW: "#22c55e",
        MEDIUM: "#eab308",
        HIGH: "#f97316",
        CRITICAL: "#ef4444"
    };

    badge.style.color = colors[data.threatLevel] || "#60a5fa";

    const fill = document.getElementById("scoreFill");
    fill.style.width = data.riskScore + "%";
    fill.style.background = colors[data.threatLevel] || "#60a5fa";

    showList("threatList", data.threats);
    showList("recommendations", data.recommendations);
    showList("urlList", data.detectedUrls);

    const auth = document.getElementById("authResults");
    auth.replaceChildren();

    Object.entries(data.authentication || {}).forEach(([name, status]) => {
        const item = document.createElement("div");
        item.className = "auth-item";

        const heading = document.createElement("strong");
        heading.textContent = name;

        const result = document.createElement("span");
        result.textContent = status;

        result.style.color =
            status === "PASS" ? "#22c55e" :
            status === "FAIL" ? "#ef4444" : "#eab308";

        item.append(heading, result);
        auth.appendChild(item);
    });

    document.getElementById("quantumStatus").textContent =
        data.quantumAssessment || "Not available";

    document.getElementById("quantumDetails").textContent =
        data.quantumDetails || "";

    showSecurityAlert(data);
    showSection("results");
}


function showList(elementId, items) {
    const list = document.getElementById(elementId);
    list.replaceChildren();

    if (!items || items.length === 0) {
        const li = document.createElement("li");
        li.textContent = "No items detected.";
        list.appendChild(li);
        return;
    }

    items.forEach(item => {
        const li = document.createElement("li");
        li.textContent = item;
        list.appendChild(li);
    });
}


function clearEmail() {
    document.getElementById("emailInput").value = "";
    document.getElementById("message").textContent = "";

    document.getElementById("results").classList.add("hidden");
    document.getElementById("quantum").classList.add("hidden");

    showSection("scanner");
}


/* ==========================================
   QR CODE SCANNER
========================================== */

async function analyzeQR() {
    const fileInput = document.getElementById("qrFile");
    const button = document.getElementById("qrButton");
    const message = document.getElementById("qrMessage");

    if (!fileInput.files.length) {
        message.textContent = "Please select a QR code image.";
        return;
    }

    const formData = new FormData();
    formData.append("file", fileInput.files[0]);

    button.disabled = true;
    button.textContent = "Scanning QR Code...";
    message.textContent = "Extracting QR content...";

    try {
        const response = await secureFetch("/api/qr/analyze", {
            method: "POST",
            credentials: "same-origin",
            body: formData
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.message || "QR analysis failed.");
        }

        document.getElementById("qrResult").classList.remove("hidden");
        document.getElementById("decodedQR").textContent = data.decodedText;

        document.getElementById("qrRisk").textContent =
            "Risk Score: " + data.analysis.riskScore +
            "/100 | " + data.analysis.threatLevel;

        showList("qrThreats", data.analysis.threats);
        showList("qrDetectedUrls", data.analysis.detectedUrls || []);

        message.textContent = "QR code successfully analyzed.";

    } catch (error) {
        message.textContent = "Error: " + error.message;
    } finally {
        button.disabled = false;
        button.textContent = "Scan QR Code →";
    }
}


/* ==========================================
   DNS AUTHENTICATION VERIFICATION
========================================== */

async function checkDNSAuthentication() {
    const domain = document.getElementById("dnsDomain").value.trim();
    const selector = document.getElementById("dkimSelector").value.trim();

    const button = document.getElementById("dnsButton");
    const message = document.getElementById("dnsMessage");
    const results = document.getElementById("dnsResults");

    if (!domain) {
        message.textContent = "Please enter a sender domain.";
        return;
    }

    button.disabled = true;
    button.textContent = "Checking DNS Records...";
    message.textContent = "Connecting to DNS verification service...";
    results.classList.add("hidden");

    try {
        const response = await secureFetch("/api/dns/check", {
            method: "POST",
            credentials: "same-origin",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                domain: domain,
                selector: selector || null
            })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.message || "DNS verification failed.");
        }

        displayDNSResults(data);
        results.classList.remove("hidden");
        message.textContent = "DNS record lookup completed successfully.";

    } catch (error) {
        message.textContent = "Error: " + error.message;
    } finally {
        button.disabled = false;
        button.textContent = "Verify DNS Records →";
    }
}


function displayDNSResults(data) {
    const fields = {
        SPF: "dnsSPF",
        DKIM: "dnsDKIM",
        DMARC: "dnsDMARC"
    };

    Object.entries(fields).forEach(([key, elementId]) => {
        const element = document.getElementById(elementId);
        const status = data[key] || "NOT AVAILABLE";

        element.textContent = status;

        if (status === "FOUND") {
            element.style.color = "#22c55e";
        } else if (
            status === "NOT FOUND" ||
            status === "DNS LOOKUP ERROR"
        ) {
            element.style.color = "#ef4444";
        } else {
            element.style.color = "#eab308";
        }
    });
}


/* ==========================================
   EML EMAIL UPLOAD AND ANALYSIS
========================================== */

async function analyzeEml() {
    const fileInput = document.getElementById("emlFile");
    const button = document.getElementById("emlButton");
    const message = document.getElementById("emlMessage");
    const resultSection = document.getElementById("emlResult");

    if (!fileInput.files.length) {
        message.textContent = "Please select an EML file.";
        return;
    }

    const file = fileInput.files[0];

    if (!file.name.toLowerCase().endsWith(".eml")) {
        message.textContent = "Only .eml files are supported.";
        return;
    }

    const formData = new FormData();
    formData.append("file", file);

    button.disabled = true;
    button.textContent = "Parsing Email...";
    message.textContent = "Uploading and extracting email information...";
    resultSection.classList.add("hidden");

    try {
        const response = await secureFetch("/api/email/upload-eml", {
            method: "POST",
            credentials: "same-origin",
            body: formData
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(
                data.detail || data.message || "EML upload failed."
            );
        }

        document.getElementById("emlFilename").textContent =
            data.filename || file.name;

        document.getElementById("emlSender").textContent =
            data.sender || "Not available";

        document.getElementById("emlSubject").textContent =
            data.subject || "No subject";

        document.getElementById("emlSelector").textContent =
            data.dkimSelector || "Not found in email headers";

        document.getElementById("emlBody").textContent =
            data.emailBody || "No readable email body found.";

        const headerList = document.getElementById("emlHeaders");
        headerList.replaceChildren();

        const headers = data.headers || {};

        if (Object.keys(headers).length === 0) {
            const li = document.createElement("li");
            li.textContent = "No supported authentication headers found.";
            headerList.appendChild(li);
        } else {
            Object.entries(headers).forEach(([name, value]) => {
                const li = document.createElement("li");
                li.textContent = name + ": " + value;
                headerList.appendChild(li);
            });
        }

        resultSection.classList.remove("hidden");

        if (data.analysis) {
            displayResults(data.analysis);
        }

        message.textContent =
            "EML file parsed successfully and threat analysis completed.";

        resultSection.scrollIntoView({ behavior: "smooth" });

    } catch (error) {
        message.textContent = "Error: " + error.message;
    } finally {
        button.disabled = false;
        button.textContent = "Upload & Analyze EML →";
    }
}


/* ==========================================
   LOGOUT
========================================== */

document.addEventListener("DOMContentLoaded", () => {

    const logoutButton = document.getElementById("logoutButton");

    if (logoutButton) {
        logoutButton.addEventListener("click", async () => {
            try {
                const response = await secureFetch("/api/auth/logout", {
                    method: "POST",
                    credentials: "same-origin"
                });

                if (response.ok) {
                    window.location.replace("/login.html");
                } else {
                    alert("Logout failed. Please try again.");
                }

            } catch (error) {
                alert("Unable to logout. Please try again.");
            }
        });
    }

});
/* ==========================================
   Q-SECURE DASHBOARD NAVIGATION
========================================== */

function showSection(sectionId) {

    const sectionIds = [
        "scanner",
        "emlScanner",
        "bulkScanner",
        "qrScanner",
        "dnsScanner",
        "results",
        "quantum",
        "history",
        "admin",
        "settings",
        "domainManagement"
    ];

    const selectedSection = document.getElementById(sectionId);

    if (!selectedSection) {
        console.error("Section not found:", sectionId);
        return;
    }

    if (
        (sectionId === "results" || sectionId === "quantum") &&
        selectedSection.classList.contains("hidden")
    ) {
        alert("Please analyze an email first.");
        return;
    }

    sectionIds.forEach(id => {
        const section = document.getElementById(id);
        if (section) {
            section.style.display = "none";
        }
    });

    selectedSection.style.display = "block";

    document.querySelectorAll(".sidebar nav a").forEach(link => {
        link.classList.toggle(
            "active",
            link.getAttribute("href") === "#" + sectionId
        );
    });

    selectedSection.scrollIntoView({
        behavior: "smooth",
        block: "start"
    });
}



/* ==========================================
   SIDEBAR NAVIGATION EVENTS
========================================== */

document.addEventListener("DOMContentLoaded", () => {

    const sectionIds = [
        "scanner",
        "emlScanner",
        "bulkScanner",
        "qrScanner",
        "dnsScanner",
        "results",
        "quantum",
        "history",
        "admin",
        "settings",
        "domainManagement"
    ];

    sectionIds.forEach(id => {
        const section = document.getElementById(id);

        if (section) {
            section.style.display =
                id === "scanner" ? "block" : "none";
        }
    });

    document.querySelectorAll(".sidebar nav a").forEach(link => {

        link.addEventListener("click", event => {
            event.preventDefault();

            const sectionId =
                link.getAttribute("href").substring(1);

            showSection(sectionId);
        });

    });

});


/* ==========================================
   Q-SECURE THREAT HISTORY
========================================== */

let threatHistoryRecords = [];

let threatChartInstance = null;
let riskChartInstance = null;


/* ==========================================
   THREAT ANALYTICS CHARTS
========================================== */

function updateHistoryCharts(records) {

    if (typeof Chart === "undefined") {
        console.error("Chart.js library not loaded.");
        return;
    }

    const threatCounts = {
        LOW: 0,
        MEDIUM: 0,
        HIGH: 0,
        CRITICAL: 0
    };

    records.forEach(record => {
        const level = (record.threatLevel || "").toUpperCase();

        if (Object.prototype.hasOwnProperty.call(threatCounts, level)) {
            threatCounts[level]++;
        }
    });

    const threatCanvas = document.getElementById("threatChart");
    const riskCanvas = document.getElementById("riskChart");

    if (!threatCanvas || !riskCanvas) return;

    if (threatChartInstance) {
        threatChartInstance.destroy();
    }

    if (riskChartInstance) {
        riskChartInstance.destroy();
    }

    Chart.defaults.font.family = "Arial, sans-serif";
    Chart.defaults.color = "#94a3b8";

    threatChartInstance = new Chart(threatCanvas, {
        type: "doughnut",

        data: {
            labels: Object.keys(threatCounts),

            datasets: [{
                label: "Number of Scans",
                data: Object.values(threatCounts),

                backgroundColor: [
                    "#22c55e",
                    "#eab308",
                    "#f97316",
                    "#ef4444"
                ],

                borderColor: "#0b1628",
                borderWidth: 4,
                hoverOffset: 10
            }]
        },

        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: "68%",

            plugins: {
                legend: {
                    position: "bottom",

                    labels: {
                        color: "#cbd5e1",
                        padding: 18,
                        usePointStyle: true,
                        pointStyle: "circle"
                    }
                },

                tooltip: {
                    backgroundColor: "#172943",
                    titleColor: "#ffffff",
                    bodyColor: "#cbd5e1",
                    borderColor: "#3b82f6",
                    borderWidth: 1,
                    padding: 12
                }
            }
        }
    });

    riskChartInstance = new Chart(riskCanvas, {
        type: "bar",

        data: {
            labels: records.map(record => "Scan #" + record.id),

            datasets: [{
                label: "Risk Score",

                data: records.map(record =>
                    Number(record.riskScore) || 0
                ),

                backgroundColor: records.map(record => {
                    const score = Number(record.riskScore) || 0;

                    if (score >= 75) return "#ef4444";
                    if (score >= 50) return "#f97316";
                    if (score >= 25) return "#eab308";

                    return "#22c55e";
                }),

                borderRadius: 7,
                borderSkipped: false,
                maxBarThickness: 42
            }]
        },

        options: {
            responsive: true,
            maintainAspectRatio: false,

            scales: {
                y: {
                    beginAtZero: true,
                    max: 100,

                    grid: {
                        color: "rgba(148, 163, 184, 0.12)"
                    },

                    ticks: {
                        color: "#94a3b8",
                        stepSize: 20
                    },

                    title: {
                        display: true,
                        text: "Risk Score",
                        color: "#94a3b8"
                    }
                },

                x: {
                    grid: {
                        display: false
                    },

                    ticks: {
                        color: "#94a3b8"
                    }
                }
            },

            plugins: {
                legend: {
                    labels: {
                        color: "#cbd5e1",
                        usePointStyle: true
                    }
                },

                tooltip: {
                    backgroundColor: "#172943",
                    titleColor: "#ffffff",
                    bodyColor: "#cbd5e1",
                    borderColor: "#3b82f6",
                    borderWidth: 1,
                    padding: 12
                }
            }
        }
    });
}


/* ==========================================
   LOAD SCAN HISTORY
========================================== */

async function loadThreatHistory() {

    const message = document.getElementById("historyMessage");
    const tableBody = document.getElementById("historyTableBody");
    const details = document.getElementById("historyDetails");

    if (!message || !tableBody) return;

    message.textContent = "Loading scan history...";
    tableBody.replaceChildren();

    if (details) {
        details.replaceChildren();
    }

    try {

        const response = await fetch("/api/history", {
            method: "GET",
            credentials: "same-origin"
        });

        if (response.status === 401) {
            message.textContent = "Session expired. Please log in again.";
            return;
        }

        if (!response.ok) {
            throw new Error("Unable to load scan history.");
        }

        const records = await response.json();

        if (!Array.isArray(records)) {
            throw new Error("Invalid history response.");
        }

        threatHistoryRecords = records;

        updateHistoryCharts(threatHistoryRecords);

        document.getElementById("totalScans").textContent =
            records.length;

        const highRisk = records.filter(record =>
            ["HIGH", "CRITICAL"].includes(
                (record.threatLevel || "").toUpperCase()
            )
        );

        document.getElementById("highRiskScans").textContent =
            highRisk.length;

        const average = records.length
            ? Math.round(
                records.reduce(
                    (sum, record) =>
                        sum + (Number(record.riskScore) || 0), 0
                ) / records.length
            )
            : 0;

        document.getElementById("averageRisk").textContent =
            average + "/100";

        if (records.length === 0) {
            message.textContent = "No previous scans found.";
            filterThreatHistory();
            return;
        }

        filterThreatHistory();

    } catch (error) {

        console.error("Threat history error:", error);
        message.textContent = "Could not load scan history.";
    }
}


/* ==========================================
   DISPLAY INDIVIDUAL REPORT
========================================== */

function showThreatDetails(record) {

    const details = document.getElementById("historyDetails");

    if (!details) return;

    details.replaceChildren();

    const heading = document.createElement("h3");
    heading.textContent = "Threat Report #" + record.id;

    details.appendChild(heading);

    const fields = [
        ["Risk Score", (record.riskScore ?? 0) + "/100"],
        ["Threat Level", record.threatLevel],
        ["Email Content", record.emailContent],
        ["Detected Threats", record.threats],
        ["Recommendations", record.recommendations],
        ["Authentication", record.authentication],
        ["Detected URLs", record.detectedUrls],
        ["Quantum Assessment", record.quantumAssessment],
        ["Quantum Details", record.quantumDetails],
        ["Scan Date", record.createdAt
            ? new Date(record.createdAt).toLocaleString()
            : "Unknown"]
    ];

    fields.forEach(([label, value]) => {

        const container = document.createElement("div");
        const title = document.createElement("strong");
        const content = document.createElement("p");

        title.textContent = label;
        content.textContent = value || "Not available";

        container.appendChild(title);
        container.appendChild(content);

        details.appendChild(container);
    });

    const pdfButton = document.createElement("button");

    pdfButton.textContent = "Download PDF Report";
    pdfButton.type = "button";
    pdfButton.style.marginTop = "16px";
    pdfButton.style.display = "block";

    pdfButton.onclick = () => downloadThreatPDF(record);

    details.appendChild(pdfButton);

    details.scrollIntoView({ behavior: "smooth" });
}


/* ==========================================
   SEARCH AND FILTER HISTORY
========================================== */

function filterThreatHistory() {

    const search =
        document.getElementById("historySearch")
            ?.value.toLowerCase().trim() || "";

    const filter =
        document.getElementById("historyFilter")
            ?.value || "ALL";

    const filteredRecords = threatHistoryRecords.filter(record => {

        const level = (record.threatLevel || "").toUpperCase();
        const score = String(record.riskScore ?? "");

        const matchesSearch =
            level.toLowerCase().includes(search) ||
            score.includes(search);

        const matchesFilter =
            filter === "ALL" || level === filter;

        return matchesSearch && matchesFilter;
    });
        const tableBody =
        document.getElementById("historyTableBody");

    if (!tableBody) return;

    tableBody.replaceChildren();

    const message =
        document.getElementById("historyMessage");

    if (filteredRecords.length === 0) {

        const row = document.createElement("tr");
        const cell = document.createElement("td");

        cell.colSpan = 5;
        cell.textContent = "No matching scan records found.";

        row.appendChild(cell);
        tableBody.appendChild(row);

        if (message) {
            message.textContent = "No matching records.";
        }

        return;
    }

    if (message) {
        message.textContent =
            filteredRecords.length + " scan(s) found.";
    }

    filteredRecords.forEach(record => {

        const row = document.createElement("tr");

        const values = [
            record.id,
            (record.riskScore ?? 0) + "/100",
            record.threatLevel || "Unknown",
            record.createdAt
                ? new Date(record.createdAt).toLocaleString()
                : "Unknown"
        ];

        values.forEach(value => {

            const cell = document.createElement("td");
            cell.textContent = value;

            row.appendChild(cell);
        });

        const actionCell = document.createElement("td");
        const viewButton = document.createElement("button");

        viewButton.textContent = "View Report";
        viewButton.type = "button";

        viewButton.addEventListener("click", () => {
            showThreatDetails(record);
        });

        actionCell.appendChild(viewButton);
        row.appendChild(actionCell);

        tableBody.appendChild(row);
    });
}


/* ==========================================
   EXPORT HISTORY AS CSV
========================================== */

function exportThreatHistory() {

    if (threatHistoryRecords.length === 0) {
        alert("No scan history available to export.");
        return;
    }

    const headers = [
        "ID",
        "User Email",
        "Risk Score",
        "Threat Level",
        "Threats",
        "Recommendations",
        "Scan Date"
    ];

    const escapeCSV = value =>
        '"' + String(value ?? "").replace(/"/g, '""') + '"';

    const rows = threatHistoryRecords.map(record => [
        record.id,
        record.userEmail,
        record.riskScore,
        record.threatLevel,
        record.threats,
        record.recommendations,
        record.createdAt
    ]);

    const csv = [headers, ...rows]
        .map(row => row.map(escapeCSV).join(","))
        .join("\r\n");

    const blob = new Blob(["\uFEFF" + csv], {
        type: "text/csv;charset=utf-8;"
    });

    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");

    link.href = url;
    link.download = "Q-Secure-Threat-History.csv";

    document.body.appendChild(link);
    link.click();
    link.remove();

    URL.revokeObjectURL(url);
}


/* ==========================================
   DOWNLOAD INDIVIDUAL PDF REPORT
========================================== */

function downloadThreatPDF(record) {

    if (!window.jspdf) {
        alert("PDF library not loaded. Please refresh the page.");
        return;
    }

    const { jsPDF } = window.jspdf;
    const doc = new jsPDF();

    let y = 20;

    doc.setFontSize(20);
    doc.text("Q-SECURE", 20, y);

    y += 10;
    doc.setFontSize(14);
    doc.text("Email Threat Analysis Report", 20, y);

    y += 15;
    doc.setFontSize(11);

    const addLine = (label, value) => {

        const text = `${label}: ${value || "Not available"}`;
        const lines = doc.splitTextToSize(text, 170);

        if (y + lines.length * 7 > 275) {
            doc.addPage();
            y = 20;
        }

        doc.text(lines, 20, y);
        y += lines.length * 7 + 3;
    };

    addLine("Report ID", record.id);
    addLine("Date", record.createdAt);
    addLine("Risk Score", `${record.riskScore}/100`);
    addLine("Threat Level", record.threatLevel);
    addLine("Email Content", record.emailContent);
    addLine("Detected Threats", record.threats);
    addLine("Recommendations", record.recommendations);
    addLine("Authentication", record.authentication);
    addLine("Detected URLs", record.detectedUrls);
    addLine("Quantum Assessment", record.quantumAssessment);
    addLine("Quantum Details", record.quantumDetails);

    doc.save(`QSecure_Report_${record.id}.pdf`);
}


/* ==========================================
   HISTORY NAVIGATION AND EVENT LISTENERS
========================================== */

document.addEventListener("DOMContentLoaded", () => {

    const historyLink =
        document.querySelector('a[href="#history"]');

    if (historyLink) {
        historyLink.addEventListener("click", () => {
            loadThreatHistory();
        });
    }

    if (window.location.hash === "#history") {
        loadThreatHistory();
    }

    document.getElementById("historySearch")
        ?.addEventListener("input", filterThreatHistory);

    document.getElementById("historyFilter")
        ?.addEventListener("change", filterThreatHistory);

    document.getElementById("exportHistory")
        ?.addEventListener("click", exportThreatHistory);

});


/* ==========================================
   Q-SECURE ADMIN DASHBOARD
========================================== */

async function loadAdminDashboard() {

    const message = document.getElementById("adminMessage");
    const tableBody = document.getElementById("adminUsersTable");

    if (!message || !tableBody) return;

    message.textContent = "Loading administrator data...";
    tableBody.replaceChildren();

    try {

        const [usersResponse, summaryResponse] = await Promise.all([
            fetch("/api/admin/users", {
                credentials: "same-origin"
            }),
            fetch("/api/admin/summary", {
                credentials: "same-origin"
            })
        ]);

        if (usersResponse.status === 401 ||
            summaryResponse.status === 401) {
            message.textContent = "Session expired. Please log in again.";
            return;
        }

        if (usersResponse.status === 403 ||
            summaryResponse.status === 403) {
            message.textContent =
                "Access denied. This section is only for administrators.";
            return;
        }

        if (!usersResponse.ok || !summaryResponse.ok) {
            throw new Error("Unable to load admin information.");
        }

        const users = await usersResponse.json();
        const summary = await summaryResponse.json();

        document.getElementById("adminTotalUsers").textContent =
            summary.totalUsers;

        document.getElementById("adminTotalScans").textContent =
            summary.totalScans;

        if (users.length === 0) {
            message.textContent = "No registered users found.";
            return;
        }

        users.forEach(user => {

            const row = document.createElement("tr");

            [
                user.id,
                user.fullName,
                user.email,
                user.role,
                user.totalScans
            ].forEach(value => {
                const cell = document.createElement("td");
                cell.textContent = value ?? "Not available";
                row.appendChild(cell);
            });

            const actionCell = document.createElement("td");

            const roleSelect = document.createElement("select");
            roleSelect.className = "admin-role-select";

            const currentRole = (user.role || "USER")
                .replace("ROLE_", "");

            ["USER", "ADMIN"].forEach(role => {
                const option = document.createElement("option");
                option.value = role;
                option.textContent = role;
                roleSelect.appendChild(option);
            });

            roleSelect.value =
                ["USER", "ADMIN"].includes(currentRole)
                    ? currentRole
                    : "USER";

            const updateButton = document.createElement("button");
            updateButton.type = "button";
            updateButton.textContent = "Update Role";
            updateButton.className = "admin-update-button";

            updateButton.addEventListener("click", async () => {

                const newRole = roleSelect.value;

                if (newRole === currentRole) {
                    message.textContent = "No role changes were made.";
                    return;
                }

                updateButton.disabled = true;
                updateButton.textContent = "Updating...";

                try {

                    const response = await secureFetch(
                        `/api/admin/users/${user.id}/role`,
                        {
                            method: "PUT",
                            credentials: "same-origin",
                            headers: {
                                "Content-Type": "application/json"
                            },
                            body: JSON.stringify({
                                role: newRole
                            })
                        }
                    );

                    const result = await response.json();

                    if (!response.ok) {
                        throw new Error(
                            result.message || "Role update failed."
                        );
                    }

                    message.textContent =
                        `Role updated successfully for ${user.email}.`;

                    await loadAdminDashboard();

                } catch (error) {

                    message.textContent = error.message;
                    updateButton.disabled = false;
                    updateButton.textContent = "Update Role";
                }
            });

            actionCell.appendChild(roleSelect);
            actionCell.appendChild(updateButton);
            row.appendChild(actionCell);

            tableBody.appendChild(row);
        });

        message.textContent =
            users.length + " registered user(s) found.";

    } catch (error) {

        console.error("Admin dashboard error:", error);
        message.textContent = "Could not load admin dashboard.";
    }
}


// Admin navigation
document.addEventListener("DOMContentLoaded", () => {

    const adminLink = document.querySelector('a[href="#admin"]');

    if (adminLink) {
        adminLink.addEventListener("click", loadAdminDashboard);
    }

    if (window.location.hash === "#admin") {
        loadAdminDashboard();
    }

});

// Connect Security Assessment button to Threat History
document.addEventListener("DOMContentLoaded", () => {

    const reportHistoryButton =
        document.getElementById("reportThreatHistoryBtn");

    const historyLink =
        document.querySelector('a[href="#history"]');

    if (reportHistoryButton && historyLink) {

        reportHistoryButton.addEventListener("click", () => {
            historyLink.click();
        });

    }

});


/* ==========================================
   Q-SECURE SECURITY ALERT
========================================== */

function showSecurityAlert(data) {
    const results = document.getElementById("results");
    if (!results) return;

    let alertBox = document.getElementById("securityAlert");

    if (!alertBox) {
        alertBox = document.createElement("div");
        alertBox.id = "securityAlert";
        results.prepend(alertBox);
    }

    const rawLevel = String(data.threatLevel || "")
        .trim()
        .toUpperCase();

    const riskScore = Number(data.riskScore || 0);

    let level = rawLevel.replace(/[\s_-]+/g, "");

    if (level.includes("CRITICAL") || riskScore >= 85) {
        level = "CRITICAL";
    } else if (level.includes("HIGH") || riskScore >= 60) {
        level = "HIGH";
    } else if (level.includes("MEDIUM") || riskScore >= 30) {
        level = "MEDIUM";
    } else {
        level = "LOW";
    }

    const alertSettings = {
        CRITICAL: {
            title: "CRITICAL SECURITY ALERT",
            color: "#ef4444",
            background: "#450a0a",
            message: "Critical threat detected. Do not open links or share personal information."
        },
        HIGH: {
            title: "HIGH RISK WARNING",
            color: "#f97316",
            background: "#431407",
            message: "High-risk email detected. Verify the sender before taking action."
        },
        MEDIUM: {
            title: "SECURITY CAUTION",
            color: "#eab308",
            background: "#422006",
            message: "Suspicious indicators detected. Review the analysis carefully."
        },
        LOW: {
            title: "EMAIL SECURITY STATUS",
            color: "#22c55e",
            background: "#052e16",
            message: "No major threats detected by the current analysis rules."
        }
    };

    const settings = alertSettings[level];

    // Display security alert in the application
    alertBox.replaceChildren();
    alertBox.style.padding = "18px";
    alertBox.style.marginBottom = "20px";
    alertBox.style.borderRadius = "10px";
    alertBox.style.border = "1px solid " + settings.color;
    alertBox.style.background = settings.background;
    alertBox.style.color = "#ffffff";

    const heading = document.createElement("h3");
    heading.textContent = settings.title;
    heading.style.color = settings.color;

    const description = document.createElement("p");
    description.textContent = settings.message;

    const score = document.createElement("p");
    score.textContent = "Risk Score: " + riskScore + "/100";

    alertBox.append(heading, description, score);

    // Debug information
    console.log("Q-Secure notification check:", {
        threatLevel: level,
        riskScore: riskScore,
        permission: ("Notification" in window)
            ? Notification.permission
            : "NOT_SUPPORTED"
    });

    // Send Windows/browser notification for HIGH and CRITICAL
    if (
    "Notification" in window &&
    Notification.permission === "granted" &&
    localStorage.getItem("qsecureNotificationsEnabled") === "true" &&
    (level === "HIGH" || level === "CRITICAL")
) {
        try {
            const notification = new Notification(
                "Q-Secure: " + settings.title,
                {
                    body: settings.message + " Risk Score: " + riskScore + "/100",
                    tag: "qsecure-threat-" + Date.now(),
                    icon: "favicon.ico",
                    renotify: true,
                    silent: false
                }
            );

            notification.onshow = () => {
                console.log(
                    "Q-Secure notification displayed:",
                    level
                );
            };

            notification.onclick = () => {
                window.focus();
                notification.close();
            };

            notification.onerror = (error) => {
                console.error(
                    "Q-Secure notification error:",
                    error
                );
            };

        } catch (error) {
            console.error(
                "Q-Secure browser notification failed:",
                error
            );
        }
    } else {
        console.log(
            "Q-Secure notification skipped:",
            level,
            Notification.permission
        );
    }

    console.log("Q-Secure final threat level:", level);
}

/* ==========================================
   BROWSER NOTIFICATION SETTINGS
========================================== */

document.addEventListener("DOMContentLoaded", () => {
    const button = document.getElementById("enableNotifications");
    const status = document.getElementById("notificationStatus");

    if (!button || !status) return;

    function updateNotificationStatus() {
        if (!("Notification" in window)) {
            status.textContent =
                "This browser does not support notifications.";
            button.disabled = true;
            return;
        }

        const enabled =
            localStorage.getItem("qsecureNotificationsEnabled") === "true";

        if (Notification.permission === "denied") {
            localStorage.setItem("qsecureNotificationsEnabled", "false");

            status.textContent =
                "Notifications are blocked. Allow them in browser site settings.";

            button.textContent = "Notifications Blocked";
            button.disabled = true;
            return;
        }

        if (enabled && Notification.permission === "granted") {
            status.textContent =
                "Browser notifications are enabled.";

            button.textContent = "Disable Notifications";
        } else {
            status.textContent =
                "Browser notifications are disabled.";

            button.textContent = "Enable Notifications";
        }

        button.disabled = false;
    }

    updateNotificationStatus();

    button.addEventListener("click", async () => {
        if (!("Notification" in window)) return;

        const enabled =
            localStorage.getItem("qsecureNotificationsEnabled") === "true";

        if (enabled) {
            localStorage.setItem("qsecureNotificationsEnabled", "false");
            updateNotificationStatus();
            return;
        }

        try {
            const permission = await Notification.requestPermission();

            if (permission === "granted") {
                localStorage.setItem("qsecureNotificationsEnabled", "true");

                new Notification("Q-Secure", {
                    body: "Browser security notifications are enabled."
                });
            }

            updateNotificationStatus();

        } catch (error) {
            console.error(
                "Notification permission request failed:",
                error
            );

            status.textContent =
                "Unable to request notification permission.";
        }
    });
});

// BULK EMAIL SCANNER
document.addEventListener("DOMContentLoaded", () => {

    const fileInput = document.getElementById("bulkEmlFiles");
    const scanButton = document.getElementById("bulkScanButton");
    const message = document.getElementById("bulkScanMessage");
    const resultsContainer = document.getElementById("bulkScanResults");

    if (!fileInput || !scanButton || !message || !resultsContainer) {
        return;
    }

    scanButton.addEventListener("click", async () => {

        const files = Array.from(fileInput.files);

        if (files.length === 0) {
            message.textContent = "Please select EML files first.";
            return;
        }

        const invalidFiles = files.filter(
            file => !file.name.toLowerCase().endsWith(".eml")
        );

        if (invalidFiles.length > 0) {
            message.textContent = "Only EML files are supported.";
            return;
        }

        const formData = new FormData();

        files.forEach(file => {
            formData.append("files", file);
        });

        scanButton.disabled = true;
        scanButton.textContent = "Scanning...";
        message.textContent = "Uploading and analyzing " + files.length + " email(s)...";
        resultsContainer.replaceChildren();

        try {
            const response = await secureFetch("/api/email/upload-eml/bulk", {
                method: "POST",
                credentials: "same-origin",
                body: formData
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.message || "Bulk email scanning failed.");
            }

            message.textContent =
                "Completed! Total: " + data.totalFiles +
                " | Successful: " + data.successfulScans +
                " | Failed: " + data.failedScans;

            const heading = document.createElement("h3");
            heading.textContent = "Bulk Scan Results";
            resultsContainer.appendChild(heading);

            data.results.forEach(item => {

                const card = document.createElement("div");
                card.className = "settings-card";

                const filename = document.createElement("h4");
                filename.textContent = item.filename || "Unknown file";
                card.appendChild(filename);

                const status = document.createElement("p");
                status.textContent = "Status: " + item.status;
                card.appendChild(status);

                if (item.status === "SUCCESS" && item.result?.analysis) {

                    const analysis = item.result.analysis;

                    const score = document.createElement("p");
                    score.textContent =
                        "Risk Score: " + analysis.riskScore + "/100";
                    card.appendChild(score);

                    const level = document.createElement("p");
                    level.textContent =
                        "Threat Level: " + analysis.threatLevel;
                    card.appendChild(level);

                    const threats = document.createElement("p");
                    threats.textContent =
                        "Detected Threats: " +
                        ((analysis.threats || []).join(", ") || "None");
                    card.appendChild(threats);

                } else {
                    const error = document.createElement("p");
                    error.textContent = "Reason: " + (item.message || "Scan failed.");
                    card.appendChild(error);
                }

                resultsContainer.appendChild(card);
            });

        } catch (error) {
            message.textContent = "Error: " + error.message;
        } finally {
            scanButton.disabled = false;
            scanButton.textContent = "Scan All Emails";
        }
    });
});


document.addEventListener("DOMContentLoaded", () => {
    const domainInput = document.getElementById("domainInput");
    const domainCategory = document.getElementById("domainCategory");
    const addButton = document.getElementById("addDomainButton");
    const refreshButton = document.getElementById("refreshDomainsButton");
    const domainMessage = document.getElementById("domainMessage");
    const domainList = document.getElementById("domainList");

    if (!domainInput || !addButton || !domainList) return;

    async function loadDomains() {
        domainMessage.textContent = "Loading domains...";

        try {
            const response = await fetch("/api/domains", {
                credentials: "same-origin"
            });

            if (!response.ok) {
                throw new Error("Unable to load domains. Please log in again.");
            }

            const domains = await response.json();
            domainList.replaceChildren();

            if (domains.length === 0) {
                domainList.textContent = "No domains added yet.";
            }

            domains.forEach(domain => {
                const card = document.createElement("div");
                card.className = "domain-entry";

                const name = document.createElement("strong");
                name.textContent = domain.domain;

                const category = document.createElement("span");
                category.textContent = " — " + domain.category;

                const deleteButton = document.createElement("button");
                deleteButton.type = "button";
                deleteButton.textContent = "Delete";

                deleteButton.addEventListener("click", async () => {
                    if (!confirm("Delete " + domain.domain + "?")) return;

                    try {
                        const result = await secureFetch(
                            "/api/domains/" + domain.id,
                            {
                                method: "DELETE",
                                credentials: "same-origin"
                            }
                        );

                        if (!result.ok) {
                            throw new Error("Could not delete domain.");
                        }

                        domainMessage.textContent =
                            "Domain deleted successfully.";
                        await loadDomains();
                    } catch (error) {
                        domainMessage.textContent = error.message;
                    }
                });

                card.append(name, category, deleteButton);
                domainList.appendChild(card);
            });

            domainMessage.textContent =
                domains.length + " domain(s) loaded.";
        } catch (error) {
            domainMessage.textContent = error.message;
        }
    }

    addButton.addEventListener("click", async () => {
        const domain = domainInput.value.trim();
        const category = domainCategory.value;

        if (!domain) {
            domainMessage.textContent = "Please enter a domain name.";
            return;
        }

        addButton.disabled = true;
        domainMessage.textContent = "Adding domain...";

        try {
            const response = await secureFetch("/api/domains", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                credentials: "same-origin",
                body: JSON.stringify({ domain, category })
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.message || "Unable to add domain.");
            }

            domainInput.value = "";
            domainMessage.textContent = "Domain added successfully.";
            await loadDomains();
        } catch (error) {
            domainMessage.textContent = error.message;
        } finally {
            addButton.disabled = false;
        }
    });

    refreshButton.addEventListener("click", loadDomains);

    loadDomains();
});



function toggleSidebar() {
    const sidebar = document.querySelector(".sidebar");

    if (!sidebar) return;

    sidebar.classList.toggle("mobile-open");
}

document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll(".sidebar nav a").forEach(link => {
        link.addEventListener("click", () => {
            if (window.innerWidth <= 800) {
                document.querySelector(".sidebar")
                    ?.classList.remove("mobile-open");
            }
        });
    });
});