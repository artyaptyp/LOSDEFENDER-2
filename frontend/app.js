const API_URL =
    window.location.origin && window.location.origin !== "null"
        ? window.location.origin
        : "http://127.0.0.1:8000";


document.addEventListener("DOMContentLoaded", () => {
    const input = document.getElementById("urlInput");
    const button = document.getElementById("scanButton");

    if (!input || !button) {
        console.warn("Elementos do scanner não encontrados na página atual.");
        return;
    }

    button.addEventListener("click", scanWebsite);
    input.addEventListener("keydown", (event) => {
        if (event.key === "Enter") {
            scanWebsite();
        }
    });
});


async function scanWebsite() {
    const input = document.getElementById("urlInput");
    const error = document.getElementById("error");
    const loading = document.getElementById("loading");
    const results = document.getElementById("results");
    const button = document.getElementById("scanButton");

    if (!input || !error || !loading || !results || !button) {
        console.warn("A página do scanner não está totalmente carregada.");
        return;
    }

    const url = input.value.trim();

    error.textContent = "";

    if (!url) {
        error.textContent = "Digite uma URL para analisar.";
        return;
    }

    loading.classList.remove("hidden");
    results.classList.add("hidden");
    button.disabled = true;
    button.textContent = "SCAN...";

    try {
        const startResponse = await fetch(`${API_URL}/scan/start`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ url: url })
        });

        const startData = await startResponse.json();

        if (!startData.success) {
            throw new Error(startData.error || "Erro durante a análise.");
        }

        let data;
        while (!data) {
            await new Promise((resolve) => setTimeout(resolve, 1000));

            const statusResponse = await fetch(
                `${API_URL}/scan/status/${encodeURIComponent(startData.scan_id)}`,
                { cache: "no-store" }
            );
            const statusData = await statusResponse.json();

            if (!statusData.success) {
                throw new Error(statusData.error || "Não foi possível consultar o andamento da análise.");
            }

            if (statusData.status === "completed") {
                data = statusData.result;
            }
        }

        if (!data.success) {
            throw new Error(data.error || "Erro durante a análise.");
        }

        showResults(data);
    } catch (err) {
        error.textContent = err.message || "Não foi possível conectar ao scanner.";
    } finally {
        loading.classList.add("hidden");
        button.disabled = false;
        button.textContent = "SCAN";
    }
}


function showResults(data) {

    const results =
        document.getElementById("results");

    const status =
        document.getElementById("overallStatus");

    const scannedUrl =
        document.getElementById("scannedUrl");


    scannedUrl.textContent =
        data.url;


    status.className =
        `overall ${data.summary.overall}`;


    status.textContent =
        data.summary.overall.toUpperCase();


    document.getElementById(
        "cleanCount"
    ).textContent =
        data.summary.clean;


    document.getElementById(
        "warningCount"
    ).textContent =
        data.summary.warnings;


    document.getElementById(
        "dangerCount"
    ).textContent =
        data.summary.danger;


    document.getElementById(
        "totalCount"
    ).textContent =
        data.summary.total;


    const list = document.getElementById("engineList");
    list.innerHTML = "";

    const orderedResults = [...data.results];
    const vtIndex = orderedResults.findIndex((result) => result.name === "VirusTotal");

    if (vtIndex !== -1) {
        const [vtResult] = orderedResults.splice(vtIndex, 1);
        orderedResults.push(vtResult);
    }

    orderedResults.forEach((result) => {
        const item = document.createElement("div");
        item.className = "engine";

        const left = document.createElement("div");
        left.className = "engine-left";

        const name = document.createElement("div");
        name.className = "engine-name";
        name.textContent = result.name;

        const message = document.createElement("div");
        message.className = "engine-message";
        message.textContent = result.message;

        left.appendChild(name);
        left.appendChild(message);

        if (result.name === "VirusTotal" && Array.isArray(result.antivirus)) {
            const badge = document.createElement("div");
            badge.className = `engine-status status-${result.status}`;
            badge.textContent = result.status === "clean" ? "CLEAN" : result.status === "warning" ? "WARNING" : "DETECTED";

            const toggle = document.createElement("button");
            toggle.type = "button";
            toggle.className = "vt-toggle";
            toggle.setAttribute("aria-expanded", "false");
            toggle.title = "Expandir lista do VirusTotal";

            const arrow = document.createElement("span");
            arrow.className = "vt-arrow";
            arrow.textContent = "▸";
            toggle.appendChild(arrow);

            const panel = document.createElement("div");
            panel.className = "vt-panel hidden";

            const groups = {
                dangerous: [],
                undetected: [],
                safe: []
            };

            result.antivirus.forEach((antivirus) => {
                const value = String(antivirus.result || "unknown").toLowerCase();
                const category = String(antivirus.category || "undetected").toLowerCase();

                if (["malicious", "suspicious", "danger", "phishing"].includes(category) || ["malicious", "suspicious"].includes(value)) {
                    groups.dangerous.push(antivirus);
                } else if (["undetected", "unrated", "unknown", "notavailable"].includes(category) || ["unrated", "unknown"].includes(value)) {
                    groups.undetected.push(antivirus);
                } else {
                    groups.safe.push(antivirus);
                }
            });

            const categoryOrder = [
                { key: "dangerous", label: "Perigosos" },
                { key: "undetected", label: "Não avaliados" },
                { key: "safe", label: "Seguros" }
            ];

            const sectionList = document.createElement("ul");
            sectionList.className = "antivirus-list";

            categoryOrder.forEach(({ key, label }) => {
                const items = groups[key];
                if (!items.length) return;

                const sectionTitle = document.createElement("li");
                sectionTitle.className = "antivirus-section";
                sectionTitle.textContent = label;
                sectionList.appendChild(sectionTitle);

                items.forEach((antivirus) => {
                    const antivirusItem = document.createElement("li");
                    antivirusItem.className = "antivirus-item";

                    const dot = document.createElement("span");
                    const state = ["malicious", "suspicious", "danger", "phishing"].includes(String(antivirus.category || "").toLowerCase()) || ["malicious", "suspicious"].includes(String(antivirus.result || "").toLowerCase())
                        ? "danger"
                        : ["undetected", "unrated", "unknown", "notavailable"].includes(String(antivirus.category || "").toLowerCase()) || ["unrated", "unknown"].includes(String(antivirus.result || "").toLowerCase())
                            ? "warning"
                            : "clean";

                    dot.className = `antivirus-dot status-${state}`;

                    const labelEl = document.createElement("span");
                    labelEl.textContent = `${antivirus.engine}: ${antivirus.result || "unknown"}`;

                    antivirusItem.appendChild(dot);
                    antivirusItem.appendChild(labelEl);
                    sectionList.appendChild(antivirusItem);
                });
            });

            panel.appendChild(sectionList);

            toggle.addEventListener("click", () => {
                const isHidden = panel.classList.toggle("hidden");
                toggle.setAttribute("aria-expanded", String(!isHidden));
                arrow.style.transform = isHidden ? "rotate(0deg)" : "rotate(90deg)";
            });

            item.appendChild(left);
            item.appendChild(badge);
            item.appendChild(toggle);
            list.appendChild(item);
            list.appendChild(panel);
            return;
        }

        const badge = document.createElement("div");
        badge.className = `engine-status status-${result.status}`;

        if (result.status === "clean") {
            badge.textContent = "CLEAN";
        } else if (result.status === "warning") {
            badge.textContent = "WARNING";
        } else {
            badge.textContent = "DETECTED";
        }

        item.appendChild(left);
        item.appendChild(badge);
        list.appendChild(item);
    });

    results.classList.remove("hidden");

    results.scrollIntoView({
        behavior: "smooth"
    });
}
