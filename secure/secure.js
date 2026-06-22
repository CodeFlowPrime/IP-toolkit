// V2Ray Space Panel - Secure Core App Logic
// Serves IP Scanner engine and V2Ray Config Modifier engine

// Global states
let generatedOutput = '';
let scanResults = [];
let scanActive = false;
let activeControllers = [];
let importedIPs = []; // Stores IPs exported from scanner

// Cloudflare, Gcore, Fastly IP Ranges Snapshot (IPv4)
const IP_RANGES_DATABASE = {
    cloudflare: [
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
        "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22"
    ],
    gcore: [
        "92.223.122.0/24", "92.223.123.0/24", "92.223.84.0/22", "92.223.108.0/22",
        "92.223.112.0/22", "95.85.12.0/22", "146.185.216.0/22", "188.93.56.0/22"
    ],
    fastly: [
        "151.101.0.0/16", "199.232.0.0/16", "104.156.80.0/20", "151.101.0.0/16",
        "167.99.192.0/18", "185.199.108.0/22", "23.235.32.0/20", "43.249.72.0/22"
    ]
};



// ==========================================
// 2. TAB SWITCHER
// ==========================================
function switchTab(tabId) {
    const tabScanner = document.getElementById('tabScanner');
    const tabGenerator = document.getElementById('tabGenerator');
    const scannerPanel = document.getElementById('scannerPanel');
    const generatorPanel = document.getElementById('generatorPanel');
    
    if (!tabScanner || !tabGenerator || !scannerPanel || !generatorPanel) return;
    
    tabScanner.classList.remove('active');
    tabGenerator.classList.remove('active');
    scannerPanel.style.display = 'none';
    generatorPanel.style.display = 'none';
    
    if (tabId === 'scanner') {
        tabScanner.classList.add('active');
        scannerPanel.style.display = 'block';
    } else {
        tabGenerator.classList.add('active');
        generatorPanel.style.display = 'block';
    }
}

// ==========================================
// 3. COMMON NOTIFICATIONS
// ==========================================
function showMessage(message, type) {
    const messageBox = document.getElementById('messageBox');
    const messageText = document.getElementById('messageText');
    const alertIcon = document.getElementById('alertIcon');
    
    if (!messageBox || !messageText || !alertIcon) return;
    
    messageBox.style.display = 'none';
    messageBox.classList.remove('alert-success', 'alert-danger', 'alert-warning');
    messageText.textContent = message;
    
    let iconSvg = '';
    if (type === 'success') {
        messageBox.classList.add('alert-success');
        iconSvg = '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline>';
    } else if (type === 'warning') {
        messageBox.classList.add('alert-warning');
        iconSvg = '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"></path><line x1="12" x2="12" y1="9" y2="13"></line><line x1="12" x2="12.01" y1="17" y2="17"></line>';
    } else {
        messageBox.classList.add('alert-danger');
        iconSvg = '<circle cx="12" cy="12" r="10"></circle><line x1="15" x2="9" y1="9" y2="15"></line><line x1="9" x2="15" y1="9" y2="15"></line>';
    }
    alertIcon.innerHTML = iconSvg;
    
    setTimeout(() => {
        messageBox.style.display = 'flex';
        messageBox.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }, 100);
}

function showError(message) { showMessage(message, 'error'); }
function showWarning(message) { showMessage(message, 'warning'); }
function showSuccess(message) { showMessage(message, 'success'); }

function shuffleArray(array) {
    for (let i = array.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [array[i], array[j]] = [array[j], array[i]];
    }
    return array;
}

// ==========================================
// 4. IP SCANNER LOGIC (CLIENT SIDE)
// ==========================================
function onScanProviderChange() {
    const provider = document.getElementById('scanProvider').value;
    const customCidrGroup = document.getElementById('customCidrGroup');
    if (!customCidrGroup) return;
    
    if (provider === 'custom') {
        customCidrGroup.style.display = 'block';
    } else {
        customCidrGroup.style.display = 'none';
    }
}

function updateScanSampleCount() {
    const slider = document.getElementById('scanSampleSize');
    const display = document.getElementById('scanSampleSizeVal');
    if (slider && display) {
        display.textContent = slider.value;
    }
}

function sampleIpFromCidr(cidr) {
    try {
        const parts = cidr.trim().split('/');
        if (parts.length !== 2) return null;
        
        const ip = parts[0];
        const mask = parseInt(parts[1]);
        if (isNaN(mask) || mask < 0 || mask > 32) return null;
        
        const parsedIp = ipaddr.parse(ip);
        if (parsedIp.kind() !== 'ipv4') return null;
        
        const octets = parsedIp.octets;
        const ipNum = (octets[0] << 24) + (octets[1] << 16) + (octets[2] << 8) + octets[3];
        
        const hostBits = 32 - mask;
        const totalHosts = Math.pow(2, hostBits);
        
        let randomIndex = 0;
        if (totalHosts > 4) {
            randomIndex = Math.floor(Math.random() * (totalHosts - 2)) + 1;
        } else {
            randomIndex = Math.floor(Math.random() * totalHosts);
        }
        
        const maxHostVal = totalHosts - 1;
        const baseSubnet = ipNum & (~maxHostVal);
        const targetIpNum = baseSubnet + randomIndex;
        
        return [
            (targetIpNum >>> 24) & 0xFF,
            (targetIpNum >>> 16) & 0xFF,
            (targetIpNum >>> 8) & 0xFF,
            targetIpNum & 0xFF
        ].join('.');
    } catch (e) {
        console.error("CIDR sampling error:", e);
        return null;
    }
}

async function startScanning() {
    if (scanActive) return;
    
    scanResults = [];
    activeControllers = [];
    document.getElementById('scanResultsTableBody').innerHTML = '';
    document.getElementById('scanResultsSection').style.display = 'none';
    
    const provider = document.getElementById('scanProvider').value;
    const threadCount = parseInt(document.getElementById('scanThreads').value) || 50;
    const timeout = parseInt(document.getElementById('scanTimeout').value) || 1500;
    const sampleSize = parseInt(document.getElementById('scanSampleSize').value) || 200;
    const minLatency = parseInt(document.getElementById('scanMinLatency')?.value) || 0;
    
    let ranges = [];
    if (provider === 'custom') {
        const customText = document.getElementById('scanCustomCidr').value.trim();
        if (!customText) {
            showWarning("Please enter custom CIDR ranges.");
            return;
        }
        ranges = customText.split('\n').filter(r => r.trim() !== '');
    } else {
        ranges = IP_RANGES_DATABASE[provider] || [];
    }
    
    if (ranges.length === 0) {
        showWarning("No valid ranges found to scan.");
        return;
    }
    
    const selectedPorts = [];
    const portCheckboxes = document.querySelectorAll('#scannerPorts input[type="checkbox"]');
    portCheckboxes.forEach(cb => {
        if (cb.checked) selectedPorts.push(parseInt(cb.value));
    });
    
    if (selectedPorts.length === 0) {
        showWarning("Please select at least one port to scan.");
        return;
    }
    
    const candidates = [];
    const candidateKeys = new Set();
    let attempts = 0;
    const maxAttempts = sampleSize * 10;
    
    let rangeIndex = 0;
    while (candidates.length < sampleSize && attempts < maxAttempts) {
        attempts++;
        const currentCidr = ranges[rangeIndex];
        const sampledIp = sampleIpFromCidr(currentCidr);
        if (sampledIp) {
            const randomPort = selectedPorts[Math.floor(Math.random() * selectedPorts.length)];
            const key = `${sampledIp}:${randomPort}`;
            if (!candidateKeys.has(key)) {
                candidateKeys.add(key);
                candidates.push({ ip: sampledIp, port: randomPort });
            }
        }
        rangeIndex = (rangeIndex + 1) % ranges.length;
    }
    
    if (candidates.length === 0) {
        showWarning("Could not parse IP ranges or sample any candidates.");
        return;
    }
    
    scanActive = true;
    document.getElementById('startScanBtn').disabled = true;
    document.getElementById('stopScanBtn').disabled = false;
    document.getElementById('progressPanel').style.display = 'block';
    
    document.getElementById('statTotal').textContent = candidates.length;
    document.getElementById('statScanned').textContent = '0';
    document.getElementById('statHealthy').textContent = '0';
    document.getElementById('progressBarFill').style.width = '0%';
    document.getElementById('progressStatusText').textContent = 'Scanning IP addresses...';
    
    let index = 0;
    let scannedCount = 0;
    let healthyCount = 0;
    
    async function runWorker() {
        while (index < candidates.length && scanActive) {
            const current = candidates[index++];
            if (!current) break;
            
            try {
                const latency = await testIpConnection(current.ip, current.port, timeout);
                scannedCount++;
                
                if (latency !== null) {
                    if (latency >= minLatency) {
                        healthyCount++;
                        scanResults.push({ ip: current.ip, port: current.port, latency });
                        scanResults.sort((a, b) => a.latency - b.latency);
                        renderResultsTable();
                    } else {
                        console.log(`Filtered out IP ${current.ip}:${current.port} with low latency: ${latency}ms (potential fake reset)`);
                    }
                }
                
                document.getElementById('statScanned').textContent = scannedCount;
                document.getElementById('statHealthy').textContent = healthyCount;
                const percent = Math.round((scannedCount / candidates.length) * 100);
                document.getElementById('progressBarFill').style.width = `${percent}%`;
            } catch (e) {
                console.error(e);
            }
        }
    }
    
    const workers = [];
    const actualThreads = Math.min(threadCount, candidates.length);
    for (let i = 0; i < actualThreads; i++) {
        workers.push(runWorker());
    }
    
    await Promise.all(workers);
    
    scanActive = false;
    document.getElementById('startScanBtn').disabled = false;
    document.getElementById('stopScanBtn').disabled = true;
    document.getElementById('progressStatusText').textContent = 'Scan completed!';
    
    if (scanResults.length > 0) {
        showSuccess(`Scan complete. Found ${scanResults.length} responsive IPs.`);
    } else {
        showError("Scan completed, but no responsive IPs were found. Check your connection or increase timeout.");
    }
}

function stopScanning() {
    if (!scanActive) return;
    scanActive = false;
    
    activeControllers.forEach(ctrl => {
        try { ctrl.abort(); } catch(e){}
    });
    activeControllers = [];
    
    document.getElementById('startScanBtn').disabled = false;
    document.getElementById('stopScanBtn').disabled = true;
    document.getElementById('progressStatusText').textContent = 'Scan stopped by user.';
    showWarning("Scan stopped. Results gathered so far are displayed below.");
}

function testIpConnection(ip, port, timeout) {
    return new Promise((resolve) => {
        if (!scanActive) {
            resolve(null);
            return;
        }
        
        const controller = new AbortController();
        activeControllers.push(controller);
        
        const timeoutId = setTimeout(() => {
            controller.abort();
        }, timeout);
        
        const startTime = performance.now();
        const protocol = (port === 80 || port === 8080) ? 'http' : 'https';
        const url = `${protocol}://${ip}:${port}/cdn-cgi/trace?_t=${Date.now()}`;
        
        fetch(url, {
            mode: 'no-cors',
            cache: 'no-store',
            credentials: 'omit',
            signal: controller.signal
        })
        .then(() => {
            const duration = Math.round(performance.now() - startTime);
            clearTimeout(timeoutId);
            removeController(controller);
            resolve(duration);
        })
        .catch(err => {
            const duration = Math.round(performance.now() - startTime);
            clearTimeout(timeoutId);
            removeController(controller);
            
            if (err.name === 'AbortError') {
                resolve(null);
            } else {
                if (duration < timeout) {
                    resolve(duration);
                } else {
                    resolve(null);
                }
            }
        });
    });
}

function removeController(ctrl) {
    const idx = activeControllers.indexOf(ctrl);
    if (idx > -1) activeControllers.splice(idx, 1);
}

function renderResultsTable() {
    const tbody = document.getElementById('scanResultsTableBody');
    if (!tbody) return;
    
    document.getElementById('scanResultsSection').style.display = 'block';
    
    let html = '';
    const displayList = scanResults.slice(0, 50);
    
    displayList.forEach(item => {
        let pingClass = 'ping-good';
        if (item.latency > 150 && item.latency <= 300) pingClass = 'ping-medium';
        if (item.latency > 300) pingClass = 'ping-bad';
        
        html += `
            <tr>
                <td style="font-family: monospace; font-weight: 600;">${item.ip}</td>
                <td><span class="slider-val" style="background: var(--bg-tertiary); color: var(--text-primary); border-radius: 4px;">${item.port}</span></td>
                <td><span class="ping-badge ${pingClass}">${item.latency} ms</span></td>
                <td><span style="color: var(--success); font-weight: 600;">✓ Responsive</span></td>
                <td>
                    <button class="btn btn-primary" style="padding: 0.3rem 0.6rem; font-size: 0.75rem; border-radius: 6px;" onclick="sendSingleIPToGenerator('${item.ip}:${item.port}')">
                        Use in Config
                    </button>
                </td>
            </tr>
        `;
    });
    
    tbody.innerHTML = html;
}

function getScannedIPText() {
    return scanResults.map(item => `${item.ip}:${item.port}`).join('\n');
}

function copyTextToClipboard(text, successCallback, errorCallback) {
    if (!navigator.clipboard) {
        // Fallback for non-secure HTTP / local context
        const textArea = document.createElement("textarea");
        textArea.value = text;
        textArea.style.top = "0";
        textArea.style.left = "0";
        textArea.style.position = "fixed";
        textArea.style.opacity = "0";
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        try {
            const successful = document.execCommand('copy');
            document.body.removeChild(textArea);
            if (successful) {
                if (successCallback) successCallback();
            } else {
                if (errorCallback) errorCallback("Failed to execute copy command");
            }
        } catch (err) {
            document.body.removeChild(textArea);
            if (errorCallback) errorCallback(err);
        }
    } else {
        // Modern Clipboard API
        navigator.clipboard.writeText(text).then(() => {
            if (successCallback) successCallback();
        }).catch(err => {
            if (errorCallback) errorCallback(err);
        });
    }
}

function copyScannedIPs() {
    const text = getScannedIPText();
    if (!text) {
        showWarning("No scan results to copy.");
        return;
    }
    copyTextToClipboard(
        text,
        () => showSuccess("All working IPs copied to clipboard."),
        (err) => {
            console.error(err);
            showError("Copy error: " + err);
        }
    );
}

function downloadScannedIPs() {
    const text = getScannedIPText();
    if (!text) {
        showWarning("No scan results to download.");
        return;
    }
    const blob = new Blob([text], { type: 'text/plain' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = `cloudflare_clean_ips_${Date.now()}.txt`;
    link.click();
    URL.revokeObjectURL(link.href);
}

function sendScannedIPsToGenerator() {
    if (scanResults.length === 0) {
        showWarning("No scan results to export.");
        return;
    }
    
    importedIPs = scanResults.map(item => `${item.ip}:${item.port}`);
    
    document.getElementById('loadedIPsCount').textContent = importedIPs.length;
    document.getElementById('loadedIPsBadge').style.display = 'inline-block';
    document.getElementById('ipList').value = importedIPs.join('\n');
    
    document.getElementById('inputType').value = 'list';
    toggleInputFields();
    
    switchTab('generator');
    showSuccess(`Successfully loaded ${importedIPs.length} working IPs into the Generator tab!`);
}

function sendSingleIPToGenerator(ipEndpoint) {
    importedIPs = [ipEndpoint];
    document.getElementById('loadedIPsCount').textContent = importedIPs.length;
    document.getElementById('loadedIPsBadge').style.display = 'inline-block';
    document.getElementById('ipList').value = ipEndpoint;
    document.getElementById('inputType').value = 'list';
    toggleInputFields();
    switchTab('generator');
    showSuccess(`Loaded IP ${ipEndpoint} into the Generator tab!`);
}

// ==========================================
// 5. CONFIG GENERATOR LOGIC
// ==========================================
function toggleInputFields() {
    const inputType = document.getElementById('inputType').value;
    const cidrFields = document.getElementById('cidrFields');
    const listFields = document.getElementById('listFields');
    const configListFields = document.getElementById('configListFields');
    const sniSpoofFields = document.getElementById('sniSpoofFields');

    if (!cidrFields || !listFields || !configListFields || !sniSpoofFields) return;

    cidrFields.style.display = 'none';
    listFields.style.display = 'none';
    configListFields.style.display = 'none';
    sniSpoofFields.style.display = 'none';

    if (inputType === 'cidr') {
        cidrFields.style.display = 'block';
    } else if (inputType === 'list') {
        listFields.style.display = 'block';
    } else if (inputType === 'configList') {
        configListFields.style.display = 'block';
    } else if (inputType === 'sniSpoof') {
        sniSpoofFields.style.display = 'block';
    }
}

function updateOutputCountValue() {
    const slider = document.getElementById('outputCount');
    const display = document.getElementById('outputCountValue');
    if (slider && display) {
        display.textContent = slider.value;
    }
}

function clearGeneratorIPList() {
    document.getElementById('ipList').value = '';
    importedIPs = [];
    document.getElementById('loadedIPsBadge').style.display = 'none';
}

function isValidCIDR(cidr) {
    return /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/.test(cidr) || /^[0-9a-fA-F:]+\/\d{1,3}$/.test(cidr);
}

function incrementIP(ip) {
    if (ip.kind() === 'ipv4') {
        let currentIpNumeric = ip.octets.reduce((acc, octet) => (acc << 8) + octet, 0);
        currentIpNumeric += 1;
        const nextIpOctets = [
            (currentIpNumeric >>> 24) & 0xFF,
            (currentIpNumeric >>> 16) & 0xFF,
            (currentIpNumeric >>> 8) & 0xFF,
            currentIpNumeric & 0xFF
        ];
        return new ipaddr.IPv4(nextIpOctets);
    } else if (ip.kind() === 'ipv6') {
        let parts = ip.parts.map(part => BigInt(part));
        let i = parts.length - 1;
        while (i >= 0) {
            parts[i] = parts[i] + 1n;
            if (parts[i] > 0xFFFFn) {
                parts[i] = 0n;
                i--;
            } else {
                break;
            }
        }
        return ipaddr.IPv6.parse(parts.map(part => part.toString(16)).join(':'));
    }
}

function isValidConfigFormat(inputConfig) {
    return inputConfig.startsWith('vmess://') || inputConfig.startsWith('vless://') ||
           inputConfig.startsWith('wireguard://') || inputConfig.startsWith('trojan://');
}

function detectConfigType(inputConfig) {
    if (inputConfig.startsWith('vmess://')) return 'vmess';
    if (inputConfig.startsWith('vless://')) return 'vless';
    if (inputConfig.startsWith('wireguard://')) return 'wireguard';
    if (inputConfig.startsWith('trojan://')) return 'trojan';
    return null;
}

function generateConfigs() {
    const inputType = document.getElementById('inputType').value;
    const rawInput = document.getElementById('inputConfig').value.trim();

    if (!rawInput) {
        showWarning('Please enter a base configuration.');
        return;
    }

    const baseConfigs = rawInput.split('\n').filter(c => isValidConfigFormat(c.trim()));

    if (baseConfigs.length === 0) {
        showWarning('No valid base configurations found. Must begin with vless://, vmess://, trojan://, or wireguard://');
        return;
    }

    if (inputType === 'cidr') {
        modifyConfigsFromCIDR(baseConfigs);
    } else if (inputType === 'list') {
        modifyConfigsFromList(baseConfigs);
    } else if (inputType === 'configList') {
        modifyConfigsFromConfigsList(baseConfigs);
    } else if (inputType === 'sniSpoof') {
        modifyConfigsFromSNISpoof(baseConfigs);
    }
}

function modifyConfigsFromCIDR(baseConfigs) {
    const ipRanges = document.getElementById('ipRange').value.trim().split('\n').filter(range => range.trim() !== '');
    const outputCount = parseInt(document.getElementById('outputCount').value);

    if (ipRanges.length === 0) {
        showWarning('Please enter at least one IP range.');
        return;
    }

    for (const ipRange of ipRanges) {
        if (!isValidCIDR(ipRange.trim())) {
            showWarning(`Invalid IP range format: ${ipRange}`);
            return;
        }
    }

    generatedOutput = '';
    let count = 0;

    for (const config of baseConfigs) {
        if (count >= outputCount) break;

        for (const ipRange of ipRanges) {
            const [ip, range] = ipaddr.parseCIDR(ipRange.trim());
            let currentIp = ip;

            while (currentIp.match(ipaddr.parseCIDR(ipRange.trim())) && count < outputCount) {
                generatedOutput += replaceIPAndPortInConfig(config.trim(), currentIp);
                count++;
                currentIp = incrementIP(currentIp);
            }

            if (count >= outputCount) break;
        }
    }

    displayResult(count);
}

function modifyConfigsFromList(baseConfigs) {
    const rawText = document.getElementById('ipList').value.trim();

    if (rawText.length === 0) {
        showWarning('Please enter a list of IPs.');
        return;
    }

    const lines = rawText.split('\n').map(l => l.trim()).filter(l => l !== '');
    const validEndpoints = [];

    lines.forEach(line => {
        let ipPart = line;
        let portPart = null;
        
        if (line.includes('[') && line.includes(']')) {
            const match = line.match(/^\[([^\]]+)\](?::(\d+))?$/);
            if (match) {
                ipPart = match[1];
                portPart = match[2] ? parseInt(match[2]) : null;
            }
        } else if ((line.match(/:/g) || []).length === 1) {
            const parts = line.split(':');
            ipPart = parts[0];
            portPart = parseInt(parts[1]);
        } else if ((line.match(/:/g) || []).length > 1) {
            ipPart = line;
            portPart = null;
        }

        if (ipaddr.isValid(ipPart)) {
            validEndpoints.push({ ip: ipPart, port: portPart });
        }
    });

    if (validEndpoints.length === 0) {
        showWarning('No valid IP addresses found in the list.');
        return;
    }

    generatedOutput = '';
    let count = 0;

    for (const config of baseConfigs) {
        for (const endpoint of validEndpoints) {
            const parsedIp = ipaddr.parse(endpoint.ip);
            generatedOutput += replaceIPAndPortInConfig(config.trim(), parsedIp, endpoint.port);
            count++;
        }
    }

    displayResult(count);
}

function modifyConfigsFromConfigsList(baseConfigs) {
    const configList = document.getElementById('configList').value.trim().split('\n').filter(config => config.trim() !== '');

    if (configList.length === 0) {
        showWarning('Please enter a list of configs.');
        return;
    }

    generatedOutput = '';
    let count = 0;

    for (const baseConfig of baseConfigs) {
        for (const targetConfig of configList) {
            const address = extractAddressFromConfig(targetConfig.trim());
            if (address) {
                let ipPart = address;
                let portPart = null;
                
                if (address.includes('[') && address.includes(']')) {
                    const match = address.match(/^\[([^\]]+)\](?::(\d+))?$/);
                    if (match) {
                        ipPart = match[1];
                        portPart = match[2] ? parseInt(match[2]) : null;
                    }
                } else if (!address.includes(':')) {
                    ipPart = address;
                } else if ((address.match(/:/g) || []).length === 1) {
                    const parts = address.split(':');
                    ipPart = parts[0];
                    portPart = parseInt(parts[1]);
                }

                generatedOutput += replaceIPAndPortInConfig(baseConfig.trim(), ipPart, portPart);
                count++;
            }
        }
    }

    displayResult(count);
}

function modifyConfigsFromSNISpoof(baseConfigs) {
    const spoofIp = document.getElementById('spoofIp').value.trim();
    const spoofPort = document.getElementById('spoofPort').value.trim();

    if (!spoofIp || !spoofPort) {
        showWarning('Please enter both Spoof IP and Port.');
        return;
    }

    generatedOutput = '';
    let count = 0;

    for (const config of baseConfigs) {
        generatedOutput += replaceIPAndPortInConfig(config.trim(), spoofIp, spoofPort);
        count++;
    }

    displayResult(count);
}

function extractAddressFromConfig(config) {
    let configType = detectConfigType(config);

    try {
        if (configType === 'vmess') {
            const base64Str = config.substring(8);
            const decodedStr = Base64.decode(base64Str);
            const vmessConfig = JSON.parse(decodedStr);
            return vmessConfig.add;
        } else if (configType === 'vless') {
            const regex = /vless:\/\/([^@]+)@([^:]+):(\d+)(\?[^#]*)?(#.*)?/;
            const match = config.match(regex);
            return match ? match[2] : null;
        } else if (configType === 'wireguard') {
            const regex = /wireguard:\/\/[^@]+@([^:]+):.+/;
            const match = config.match(regex);
            return match ? match[1] : null;
        } else if (configType === 'trojan') {
            const regex = /trojan:\/\/[^@]+@([^:]+):.+/;
            const match = config.match(regex);
            return match ? match[1] : null;
        }
    } catch(e) {
        console.error("Extraction error:", e);
    }

    return null;
}

function replaceIPAndPortInConfig(inputConfig, ipOrAddress, newPort = null) {
    let configType = detectConfigType(inputConfig);
    let addressStr = typeof ipOrAddress === 'string' ? ipOrAddress : ipOrAddress.toString();
    let result = '';

    if (configType === 'vmess') {
        let vmessConfig = JSON.parse(Base64.decode(inputConfig.replace('vmess://', '')));
        vmessConfig.add = addressStr;
        if (newPort) vmessConfig.port = parseInt(newPort);
        result = `vmess://${Base64.encode(JSON.stringify(vmessConfig))}\n`;
    } else if (configType === 'vless') {
        if (addressStr.includes(':') && !addressStr.startsWith('[')) {
            addressStr = `[${addressStr}]`;
        }
        const match = inputConfig.match(/^(vless:\/\/[^@]+)@([^:]+):(\d+)(.*)$/);
        if (match) {
            const [_, start, domain, port, end] = match;
            result = `${start}@${addressStr}:${newPort || port}${end}\n`;
        } else {
            result = inputConfig + '\n';
        }
    } else if (configType === 'wireguard') {
        const regex = /^(wireguard:\/\/[^@]+@)[^:]+:(\d+)(.*)$/;
        result = inputConfig.replace(regex, (m, p1, p2, p3) => `${p1}${addressStr}:${newPort || p2}${p3}\n`);
    } else if (configType === 'trojan') {
        const regex = /^(trojan:\/\/[^@]+@)[^:]+:(\d+)(.*)$/;
        result = inputConfig.replace(regex, (m, p1, p2, p3) => `${p1}${addressStr}:${newPort || p2}${p3}\n`);
    }

    return result;
}

function displayResult(count) {
    const copyButton = document.getElementById('copyButton');
    const downloadButton = document.getElementById('downloadButton');

    if (generatedOutput) {
        showSuccess(`Successfully generated ${count} configs.`);
        copyButton.style.display = 'inline-block';
        downloadButton.style.display = 'inline-block';
    } else {
        showError('No configs were generated.');
        copyButton.style.display = 'none';
        downloadButton.style.display = 'none';
    }
}

async function loadIPRanges(service) {
    const url = `https://raw.githubusercontent.com/seramo/cdn-ip-ranges/main/${service}.json`;

    try {
        const response = await fetch(url);
        if (!response.ok) {
            throw new Error(`Error retrieving data: ${response.statusText}`);
        }

        const data = await response.json();
        const ipRanges = data.ipv4 || [];

        if (ipRanges.length === 0) {
            showWarning('No IP range found in response.');
            return;
        }

        let selectedRanges = [];
        if (service !== 'gcore') {
            selectedRanges = shuffleArray(ipRanges).slice(0, 4);
        } else {
            selectedRanges = ipRanges;
        }
        document.getElementById('ipRange').value = selectedRanges.join('\n');
        showSuccess(`Loaded ranges for ${service.toUpperCase()} successfully.`);
    } catch (error) {
        console.error(error);
        const fallback = IP_RANGES_DATABASE[service];
        if (fallback) {
            document.getElementById('ipRange').value = shuffleArray([...fallback]).slice(0, 4).join('\n');
            showSuccess(`Offline: Loaded cached local ranges for ${service.toUpperCase()}.`);
        } else {
            showError('An error occurred while loading IPs.');
        }
    }
}

function copyToClipboard() {
    if (generatedOutput) {
        copyTextToClipboard(
            generatedOutput.trimEnd(),
            () => showSuccess('Configs copied to clipboard.'),
            (err) => {
                console.error(err);
                showError('Copy error: ' + err);
            }
        );
    }
}

function downloadOutput() {
    if (generatedOutput) {
        const blob = new Blob([generatedOutput.trimEnd()], { type: 'text/plain' });
        const now = new Date();
        const date = now.toISOString().split('T')[0];
        const time = now.toTimeString().split(' ')[0].replace(/:/g, '-');
        const fileName = `v2ray_configs_${date}_${time}.txt`;

        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = fileName;
        link.click();
        URL.revokeObjectURL(link.href);
    }
}

// Initialize App Core (directly, since DOM is already loaded)
toggleInputFields();
updateOutputCountValue();
updateScanSampleCount();
