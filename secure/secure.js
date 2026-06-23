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
    ],
    arvancloud: [
        "185.143.232.0/22", "188.229.116.16/30", "94.101.182.0/27", "2.144.3.128/28",
        "37.32.16.0/27", "37.32.17.0/27", "37.32.18.0/27", "37.32.19.0/27",
        "185.215.232.0/22", "178.131.120.48/28", "94.101.183.0/28", "78.157.36.112/28"
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
    const container = document.getElementById('toastContainer');
    if (!container) return;
    
    const toast = document.createElement('div');
    toast.className = `toast-notification toast-${type}`;
    
    let iconSvg = '';
    if (type === 'success') {
        iconSvg = '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="toast-icon"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>';
    } else if (type === 'warning') {
        iconSvg = '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="toast-icon"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"></path><line x1="12" x2="12" y1="9" y2="13"></line><line x1="12" x2="12.01" y1="17" y2="17"></line></svg>';
    } else {
        iconSvg = '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="toast-icon"><circle cx="12" cy="12" r="10"></circle><line x1="15" x2="9" y1="9" y2="15"></line><line x1="9" x2="15" y1="9" y2="15"></line></svg>';
    }
    
    toast.innerHTML = `
        ${iconSvg}
        <span class="toast-message">${message}</span>
        <button class="toast-close">&times;</button>
    `;
    
    container.appendChild(toast);
    
    const closeToast = () => {
        toast.classList.add('toast-leaving');
        setTimeout(() => {
            if (toast.parentElement) {
                toast.remove();
            }
        }, 300);
    };
    
    const closeBtn = toast.querySelector('.toast-close');
    if (closeBtn) {
        closeBtn.onclick = closeToast;
    }
    
    // Auto-remove after 3 seconds
    setTimeout(() => {
        if (toast.parentElement) {
            closeToast();
        }
    }, 3000);
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
    const rangeSelectorGroup = document.getElementById('rangeSelectorGroup');
    const container = document.getElementById('providerRangesContainer');
    if (!customCidrGroup || !rangeSelectorGroup || !container) return;
    
    if (provider === 'custom') {
        customCidrGroup.style.display = 'block';
        rangeSelectorGroup.style.display = 'none';
    } else {
        customCidrGroup.style.display = 'none';
        rangeSelectorGroup.style.display = 'block';
        
        // Populate ranges checkboxes
        const ranges = IP_RANGES_DATABASE[provider] || [];
        let html = '';
        ranges.forEach((range, idx) => {
            const id = `range_${provider}_${idx}`;
            html += `
                <div style="display: inline-block;">
                    <input type="checkbox" id="${id}" class="pill-checkbox" value="${range}" checked>
                    <label for="${id}" class="pill-label" style="font-family: monospace; font-size: 0.8rem; padding: 0.4rem 0.8rem; border-radius: 15px;">${range}</label>
                </div>
            `;
        });
        container.innerHTML = html;
    }

    // Auto-adjust min latency filter based on provider
    const minLatencySelect = document.getElementById('scanMinLatency');
    if (minLatencySelect) {
        if (provider === 'arvancloud') {
            minLatencySelect.value = "0"; // Disabled for domestic CDN (low native latency)
        } else {
            minLatencySelect.value = "20"; // Reset to default 20ms for foreign CDNs
        }
    }
}

function selectAllRanges(status) {
    const checkboxes = document.querySelectorAll('#providerRangesContainer input[type="checkbox"]');
    checkboxes.forEach(cb => {
        cb.checked = status;
    });
}

function updateScanSampleCount() {
    const slider = document.getElementById('scanSampleSize');
    const display = document.getElementById('scanSampleSizeVal');
    if (slider && display) {
        display.textContent = slider.value;
    }
}

// Convert IPv4 string to unsigned 32-bit integer
function ipToNum(ipStr) {
    const octets = ipStr.split('.').map(Number);
    return ((octets[0] << 24) >>> 0) + 
           ((octets[1] << 16) >>> 0) + 
           ((octets[2] << 8) >>> 0) + 
           (octets[3] >>> 0);
}

// Convert unsigned 32-bit integer to IPv4 string
function numToIp(num) {
    return [
        (num >>> 24) & 0xFF,
        (num >>> 16) & 0xFF,
        (num >>> 8) & 0xFF,
        num & 0xFF
    ].join('.');
}

// Parse IPv4 CIDR range and calculate its details
function parseCIDRBlock(cidrStr) {
    try {
        const parts = cidrStr.trim().split('/');
        if (parts.length !== 2) return null;
        const ipStr = parts[0];
        const mask = parseInt(parts[1], 10);
        if (isNaN(mask) || mask < 0 || mask > 32) return null;
        
        const parsed = ipaddr.parse(ipStr);
        if (parsed.kind() !== 'ipv4') return null;
        const octets = parsed.octets;
        const ipNum = ((octets[0] << 24) >>> 0) + 
                      ((octets[1] << 16) >>> 0) + 
                      ((octets[2] << 8) >>> 0) + 
                      (octets[3] >>> 0);
                      
        const hostBits = 32 - mask;
        const capacity = Math.pow(2, hostBits);
        const startNum = (ipNum - (ipNum % capacity)) >>> 0;
        const endNum = (startNum + capacity - 1) >>> 0;
        
        return {
            cidr: cidrStr,
            startNum,
            endNum,
            capacity,
            mask
        };
    } catch (e) {
        console.error("Error parsing CIDR:", cidrStr, e);
        return null;
    }
}

// Dynamically split a CIDR block into subnets of a target capacity
function splitCIDRBlockIntoSubnets(cidrStr, targetCapacity = 1024) {
    const parsed = parseCIDRBlock(cidrStr);
    if (!parsed) return [];
    
    // If the capacity is already within the target, no need to split
    if (parsed.capacity <= targetCapacity) {
        return [parsed];
    }
    
    const subnets = [];
    // We want each sub-subnet to have subCapacity <= targetCapacity
    const hostBits = Math.floor(Math.log2(targetCapacity));
    const subMask = 32 - hostBits;
    const subCapacity = Math.pow(2, hostBits);
    
    for (let num = parsed.startNum; num <= parsed.endNum; num += subCapacity) {
        const subCidr = `${numToIp(num)}/${subMask}`;
        subnets.push({
            cidr: subCidr,
            startNum: num,
            endNum: num + subCapacity - 1,
            capacity: subCapacity,
            mask: subMask
        });
    }
    return subnets;
}

// Generate IP string from a subnet start number and host offset
function getIpFromOffset(startNum, offset) {
    return numToIp((startNum + offset) >>> 0);
}

// Generate an array of unique, random offsets within a capacity without duplication
function sampleOffsets(capacity, count) {
    const offsets = new Set();
    if (count >= capacity) {
        // If budget meets or exceeds capacity, take all possible offsets
        const arr = [];
        for (let i = 0; i < capacity; i++) {
            arr.push(i);
        }
        return shuffleArray(arr);
    }
    
    // For small capacity, generate all offsets, shuffle, and slice
    if (capacity <= 10000) {
        const arr = [];
        for (let i = 0; i < capacity; i++) {
            arr.push(i);
        }
        shuffleArray(arr);
        return arr.slice(0, count);
    }
    
    // For large capacity, do sparse random sampling with collision detection
    while (offsets.size < count) {
        const randVal = Math.floor(Math.random() * capacity);
        offsets.add(randVal);
    }
    return Array.from(offsets);
}

// Fair budget distribution with capacity constraint and surplus redistribution
function distributeBudget(subnets, totalBudget) {
    const n = subnets.length;
    if (n === 0) return new Map();
    
    const allocations = new Map();
    subnets.forEach(s => allocations.set(s, 0));
    
    let remainingBudget = totalBudget;
    let activeSubnets = new Set(subnets);
    
    while (remainingBudget > 0 && activeSubnets.size > 0) {
        const share = Math.floor(remainingBudget / activeSubnets.size);
        const remainder = remainingBudget % activeSubnets.size;
        
        if (share === 0) {
            let rem = remainingBudget;
            for (const s of activeSubnets) {
                if (rem === 0) break;
                const currentAlloc = allocations.get(s);
                if (currentAlloc < s.capacity) {
                    allocations.set(s, currentAlloc + 1);
                    rem--;
                }
            }
            remainingBudget = rem;
            break;
        }
        
        let newSurplus = 0;
        let saturatedThisRound = [];
        
        for (const s of activeSubnets) {
            const currentAlloc = allocations.get(s);
            const targetAlloc = currentAlloc + share;
            
            if (targetAlloc >= s.capacity) {
                allocations.set(s, s.capacity);
                newSurplus += (targetAlloc - s.capacity);
                saturatedThisRound.push(s);
            } else {
                allocations.set(s, targetAlloc);
            }
        }
        
        saturatedThisRound.forEach(s => activeSubnets.delete(s));
        remainingBudget = newSurplus + remainder;
        
        if (activeSubnets.size === 0) {
            break;
        }
    }
    return allocations;
}

// Proportional budget distribution that respects Quality Scores and capacity limits
function distributeProportionalBudget(subnets, targetBudgets) {
    const allocations = new Map();
    subnets.forEach(s => allocations.set(s, 0));
    
    let remainingBudget = 0;
    subnets.forEach(s => {
        remainingBudget += targetBudgets.get(s) || 0;
    });
    
    let activeSubnets = new Set(subnets);
    
    // First pass: allocate up to target budget or capacity
    subnets.forEach(s => {
        const target = targetBudgets.get(s) || 0;
        const alloc = Math.min(s.capacity, target);
        allocations.set(s, alloc);
        remainingBudget -= alloc;
        if (alloc === s.capacity) {
            activeSubnets.delete(s);
        }
    });
    
    // Second pass: distribute any surplus/remainder to non-saturated subnets
    while (remainingBudget > 0 && activeSubnets.size > 0) {
        const share = Math.floor(remainingBudget / activeSubnets.size);
        const remainder = remainingBudget % activeSubnets.size;
        
        if (share === 0) {
            let rem = remainingBudget;
            for (const s of activeSubnets) {
                if (rem === 0) break;
                const currentAlloc = allocations.get(s);
                if (currentAlloc < s.capacity) {
                    allocations.set(s, currentAlloc + 1);
                    rem--;
                }
            }
            remainingBudget = rem;
            break;
        }
        
        let newSurplus = 0;
        let saturatedThisRound = [];
        
        for (const s of activeSubnets) {
            const currentAlloc = allocations.get(s);
            const targetAlloc = currentAlloc + share;
            
            if (targetAlloc >= s.capacity) {
                allocations.set(s, s.capacity);
                newSurplus += (targetAlloc - s.capacity);
                saturatedThisRound.push(s);
            } else {
                allocations.set(s, targetAlloc);
            }
        }
        
        saturatedThisRound.forEach(s => activeSubnets.delete(s));
        remainingBudget = newSurplus + remainder;
    }
    
    return allocations;
}

// Global scanner state extensions
let scanStartTime = 0;
let totalPingsExpected = 0;
let completedPingsCount = 0;
let topCandidates = [];
let parsedSubnets = [];

// Helper to format remaining time in mm:ss
function formatTime(ms) {
    if (ms <= 0 || isNaN(ms)) return "00:00";
    const totalSecs = Math.floor(ms / 1000);
    const mins = Math.floor(totalSecs / 60);
    const secs = totalSecs % 60;
    return `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
}

// Latency score: 1.0 for <=20ms, decreasing linearly to 0 at timeout
function getLatencyScore(avgLatency, timeout) {
    if (!avgLatency || avgLatency >= timeout) return 0;
    const minL = 20;
    if (avgLatency <= minL) return 1.0;
    return Math.max(0, 1 - (avgLatency - minL) / (timeout - minL));
}

// Jitter score: 1.0 for 0ms jitter, decreasing linearly to 100ms
function getJitterScore(jitter) {
    if (jitter === undefined || isNaN(jitter)) return 0;
    return Math.max(0, 1 - jitter / 100);
}

// Render real-time subnets performance table
function renderSubnetsTable() {
    const tbody = document.getElementById('subnetsTableBody');
    if (!tbody) return;
    
    // Filter to only include subnets that are actually allocated budget or have been active
    const activeSubnetsList = parsedSubnets.filter(s => 
        s.discoveryBudget > 0 || s.validationBudget > 0 || s.completedCount > 0
    );
    
    // Sort active subnets: highest quality score first, then healthy count, then attempts
    activeSubnetsList.sort((a, b) => {
        if (b.qualityScore !== a.qualityScore) return b.qualityScore - a.qualityScore;
        if (b.healthyCount !== a.healthyCount) return b.healthyCount - a.healthyCount;
        return b.attempts - a.attempts;
    });
    
    // Show top 15 subnets in the UI to prevent browser lagging
    const displayLimit = 15;
    const toRender = activeSubnetsList.slice(0, displayLimit);
    
    let html = '';
    toRender.forEach(s => {
        const totalBudget = s.discoveryBudget + s.validationBudget;
        const progressPercent = totalBudget > 0 ? Math.round((s.completedCount / totalBudget) * 100) : 0;
        
        let scoreClass = 'quality-low';
        if (s.qualityScore >= 70) scoreClass = 'quality-high';
        else if (s.qualityScore >= 40) scoreClass = 'quality-medium';
        
        html += `
            <tr>
                <td style="font-family: monospace; font-weight: 600;">${s.cidr}</td>
                <td style="font-family: monospace;">${s.capacity.toLocaleString()}</td>
                <td style="font-family: monospace;">${s.discoveryBudget}</td>
                <td style="font-family: monospace;">${s.validationBudget}</td>
                <td>
                    <div style="display: flex; align-items: center; gap: 0.5rem;">
                        <div class="progress-bar-container" style="margin-bottom: 0; width: 60px; height: 6px;">
                            <div class="progress-bar-fill" style="width: ${progressPercent}%;"></div>
                        </div>
                        <span style="font-family: monospace; font-size: 0.75rem;">${s.completedCount}/${totalBudget}</span>
                    </div>
                </td>
                <td style="font-family: monospace; font-weight: 600; color: var(--success);">${s.healthyCount}</td>
                <td><span class="quality-badge ${scoreClass}">${Math.round(s.qualityScore)}</span></td>
            </tr>
        `;
    });
    
    if (activeSubnetsList.length > displayLimit) {
        const extraCount = activeSubnetsList.length - displayLimit;
        html += `
            <tr>
                <td colspan="7" style="text-align: center; color: var(--text-secondary); font-size: 0.8rem; padding: 0.5rem;">
                    Showing top 15 of ${activeSubnetsList.length} active subnets (+${extraCount} more active subnets hidden)
                </td>
            </tr>
        `;
    } else if (activeSubnetsList.length === 0) {
        html = `<tr><td colspan="7" style="text-align: center; color: var(--text-secondary); padding: 1rem;">No subnets allocated yet.</td></tr>`;
    }
    
    tbody.innerHTML = html;
}

// Render top 10 candidates dashboard table
function renderTopCandidatesTable() {
    const tbody = document.getElementById('topCandidatesTableBody');
    if (!tbody) return;
    
    if (topCandidates.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-secondary); padding: 1rem;">No candidates discovered yet.</td></tr>`;
        return;
    }
    
    let html = '';
    topCandidates.slice(0, 10).forEach(item => {
        let scoreClass = 'quality-low';
        if (item.score >= 70) scoreClass = 'quality-high';
        else if (item.score >= 40) scoreClass = 'quality-medium';
        
        html += `
            <tr>
                <td style="font-family: monospace; font-weight: 600; cursor: pointer; text-decoration: underline dotted;" onclick="copySingleIpText('${item.ip}')" title="Click to copy IP">${item.ip}</td>
                <td><span class="slider-val" style="background: var(--bg-tertiary); color: var(--text-primary); border-radius: 4px; padding: 0.1rem 0.3rem;">${item.port}</span></td>
                <td style="font-family: monospace;">${item.latency} ms</td>
                <td style="font-family: monospace;">${Math.round(item.stability * 100)}%</td>
                <td style="font-family: monospace;">${Math.round(item.jitter)} ms</td>
                <td><span class="quality-badge ${scoreClass}">${Math.round(item.score)}</span></td>
                <td style="font-family: monospace; font-size: 0.75rem; color: var(--text-secondary);">${item.subnetCidr}</td>
            </tr>
        `;
    });
    tbody.innerHTML = html;
}

// Update phase indicators, progress bar, action, and remaining time
function updateScanStatus(currentAction, activePhase = null, phaseProgress = 0, phaseCountStr = "") {
    const actionEl = document.getElementById('statCurrentAction');
    if (actionEl) {
        actionEl.textContent = currentAction;
    }
    
    if (completedPingsCount > 0 && scanActive) {
        const elapsed = Date.now() - scanStartTime;
        const msPerPing = elapsed / completedPingsCount;
        const remainingPings = Math.max(0, totalPingsExpected - completedPingsCount);
        const estMs = remainingPings * msPerPing;
        const timeEl = document.getElementById('statRemainingTime');
        if (timeEl) {
            timeEl.textContent = formatTime(estMs);
        }
    }
    
    if (activePhase) {
        const phases = ['discovery', 'validation', 'deep'];
        phases.forEach(p => {
            const card = document.getElementById(`phaseCard_${p}`);
            const badge = document.getElementById(`phaseBadge_${p}`);
            const fill = document.getElementById(`phaseProgressFill_${p}`);
            const count = document.getElementById(`phaseCount_${p}`);
            const percent = document.getElementById(`phasePercent_${p}`);
            
            if (!card || !badge || !fill) return;
            
            if (p === activePhase) {
                if (phaseCountStr === "Skipped") {
                    card.classList.remove('active', 'completed');
                    badge.className = 'phase-badge badge-skipped';
                    badge.textContent = 'Skipped';
                } else {
                    card.classList.add('active');
                    card.classList.remove('completed');
                    badge.className = 'phase-badge badge-active';
                    badge.textContent = 'Active';
                }
                fill.style.width = `${phaseProgress}%`;
                if (count) count.textContent = phaseCountStr;
                if (percent) percent.textContent = `${Math.round(phaseProgress)}%`;
            } else if (phases.indexOf(p) < phases.indexOf(activePhase)) {
                card.classList.remove('active');
                card.classList.add('completed');
                badge.className = 'phase-badge badge-completed';
                badge.textContent = 'Done';
                fill.style.width = '100%';
                if (percent) percent.textContent = '100%';
            } else {
                card.classList.remove('active', 'completed');
                badge.className = 'phase-badge badge-pending';
                badge.textContent = 'Pending';
                fill.style.width = '0%';
                if (percent) percent.textContent = '0%';
            }
        });
    }
}

// Compute subnet Quality Score
function recalculateSubnetScore(subnet, timeout) {
    if (subnet.attempts === 0) {
        subnet.qualityScore = 0;
        return;
    }
    
    const successes = subnet.successes;
    const attempts = subnet.attempts;
    const successRate = successes / attempts;
    
    if (successes === 0) {
        subnet.avgLatency = null;
        subnet.qualityScore = 0;
        return;
    }
    
    const avgLatency = subnet.latencies.reduce((a, b) => a + b, 0) / successes;
    subnet.avgLatency = Math.round(avgLatency);
    
    let totalStability = 0;
    let totalJitter = 0;
    let responsiveCount = 0;
    
    subnet.responsiveCandidates.forEach(cand => {
        totalStability += cand.stability;
        totalJitter += cand.jitter;
        responsiveCount++;
    });
    
    const latencyScore = getLatencyScore(avgLatency, timeout);
    if (responsiveCount === 0) {
        subnet.qualityScore = successRate * (0.5 * latencyScore + 0.5) * 100;
        return;
    }
    
    const avgStability = totalStability / responsiveCount;
    const avgJitter = totalJitter / responsiveCount;
    const jitterScore = getJitterScore(avgJitter);
    
    subnet.qualityScore = successRate * (
        0.5 * latencyScore + 
        0.3 * avgStability + 
        0.2 * jitterScore
    ) * 100;
}

// Compute single candidate score
function recalculateCandidateScore(ip, port, subnet, timeout) {
    const key = `${ip}:${port}`;
    const cand = subnet.responsiveCandidates.get(key);
    if (!cand) return;
    
    const successRate = cand.successes / cand.attempts;
    const avgLatency = cand.latencies.reduce((a, b) => a + b, 0) / cand.successes;
    const latencyScore = getLatencyScore(avgLatency, timeout);
    const jitterScore = getJitterScore(cand.jitter);
    
    const score = successRate * (
        0.5 * latencyScore + 
        0.3 * cand.stability + 
        0.2 * jitterScore
    ) * 100;
    
    cand.score = score;
    
    const existingIndex = topCandidates.findIndex(item => item.ip === ip && item.port === port);
    const candidateData = {
        ip: ip,
        port: port,
        latency: Math.round(avgLatency),
        stability: cand.stability,
        jitter: cand.jitter,
        score: score,
        subnetCidr: subnet.cidr
    };
    
    if (existingIndex > -1) {
        topCandidates[existingIndex] = candidateData;
    } else {
        topCandidates.push(candidateData);
    }
    
    topCandidates.sort((a, b) => b.score - a.score);
}

// Redesigned main scanning algorithm
async function startScanning() {
    if (scanActive) return;
    
    scanResults = [];
    activeControllers = [];
    topCandidates = [];
    parsedSubnets = [];
    completedPingsCount = 0;
    
    document.getElementById('scanResultsTableBody').innerHTML = '';
    document.getElementById('scanResultsSection').style.display = 'none';
    
    const logDiv = document.getElementById('scannerLog');
    if (logDiv) {
        logDiv.style.display = 'block';
        logDiv.innerHTML = '<div>[System] Preparing scan...</div>';
    }
    
    const provider = document.getElementById('scanProvider').value;
    const threadCount = parseInt(document.getElementById('scanThreads').value) || 50;
    const timeout = parseInt(document.getElementById('scanTimeout').value) || 1500;
    const sampleSize = parseInt(document.getElementById('scanSampleSize').value) || 200;
    const minLatency = parseInt(document.getElementById('scanMinLatency')?.value) || 0;
    const testCount = parseInt(document.getElementById('scanTestCount')?.value) || 1;
    
    let ranges = [];
    if (provider === 'custom') {
        const customText = document.getElementById('scanCustomCidr').value.trim();
        if (!customText) {
            showWarning("Please enter custom CIDR ranges.");
            return;
        }
        ranges = customText.split('\n').filter(r => r.trim() !== '');
    } else {
        const checkboxes = document.querySelectorAll('#providerRangesContainer input[type="checkbox"]');
        checkboxes.forEach(cb => {
            if (cb.checked) {
                ranges.push(cb.value);
            }
        });
    }
    
    if (ranges.length === 0) {
        showWarning("Please select or enter at least one IP range to scan.");
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
    
    // Calculate total capacity across all ranges to dynamically partition them
    let totalCidrCapacity = 0;
    ranges.forEach(r => {
        const parts = r.trim().split('/');
        const mask = parts.length === 2 ? parseInt(parts[1], 10) : 32;
        if (!isNaN(mask) && mask >= 0 && mask <= 32) {
            totalCidrCapacity += Math.pow(2, 32 - mask);
        }
    });
    
    let targetCapacity = 1024; // Default target capacity
    if (totalCidrCapacity > 0 && sampleSize > 0) {
        // Aim for about sampleSize * 1.5 subnets
        const idealNumSubnets = sampleSize * 1.5;
        const idealCapacity = totalCidrCapacity / idealNumSubnets;
        const powerOf2 = Math.round(Math.log2(idealCapacity));
        targetCapacity = Math.pow(2, Math.max(8, Math.min(13, powerOf2))); // cap capacity between 256 (2^8) and 8192 (2^13)
    }
    
    if (logDiv) {
        logDiv.innerHTML += `<div>[System] Dynamically partitioned subnet capacity target: ${targetCapacity} hosts</div>`;
        logDiv.scrollTop = logDiv.scrollHeight;
    }

    // Parse and split CIDR ranges
    ranges.forEach(r => {
        const subblocks = splitCIDRBlockIntoSubnets(r, targetCapacity);
        subblocks.forEach(parsed => {
            parsedSubnets.push({
                ...parsed,
                discoveryBudget: 0,
                validationBudget: 0,
                completedCount: 0,
                healthyCount: 0,
                avgLatency: null,
                qualityScore: 0,
                latencies: [],
                successes: 0,
                attempts: 0,
                sampledOffsets: new Set(),
                responsiveCandidates: new Map()
            });
        });
    });
    
    if (parsedSubnets.length === 0) {
        showWarning("No valid IP subnets could be parsed. Check your CIDR configurations.");
        return;
    }
    
    scanActive = true;
    document.getElementById('startScanBtn').disabled = true;
    document.getElementById('stopScanBtn').disabled = false;
    document.getElementById('progressPanel').style.display = 'block';
    
    renderSubnetsTable();
    renderTopCandidatesTable();
    
    scanStartTime = Date.now();
    
    // 1. Allocate Discovery Budgets (30% of total budget)
    let discoveryBudgetTotal = Math.max(parsedSubnets.length * 2, Math.round(sampleSize * 0.3));
    const totalCapacity = parsedSubnets.reduce((sum, s) => sum + s.capacity, 0);
    discoveryBudgetTotal = Math.min(discoveryBudgetTotal, totalCapacity);
    
    const discoveryAllocations = distributeBudget(parsedSubnets, discoveryBudgetTotal);
    parsedSubnets.forEach(s => {
        s.discoveryBudget = discoveryAllocations.get(s) || 0;
    });
    
    // Calculate total validation budget
    let validationBudgetTotal = Math.max(0, sampleSize - discoveryBudgetTotal);
    if (discoveryBudgetTotal + validationBudgetTotal > totalCapacity) {
        validationBudgetTotal = totalCapacity - discoveryBudgetTotal;
    }
    
    totalPingsExpected = discoveryBudgetTotal + (validationBudgetTotal * testCount);
    document.getElementById('statTotal').textContent = discoveryBudgetTotal + validationBudgetTotal;
    
    renderSubnetsTable();
    
    // ==========================================
    // PHASE 1: DISCOVERY
    // ==========================================
    if (logDiv) {
        logDiv.innerHTML += `<div>[System] Phase 1: Discovery Phase started (${discoveryBudgetTotal} samples)...</div>`;
        logDiv.scrollTop = logDiv.scrollHeight;
    }
    
    const discoveryCandidates = [];
    parsedSubnets.forEach(s => {
        if (s.discoveryBudget > 0) {
            const offsets = sampleOffsets(s.capacity, s.discoveryBudget);
            offsets.forEach(offset => {
                s.sampledOffsets.add(offset);
                const ip = getIpFromOffset(s.startNum, offset);
                const port = selectedPorts[Math.floor(Math.random() * selectedPorts.length)];
                discoveryCandidates.push({ ip, port, subnet: s, offset });
            });
        }
    });
    
    shuffleArray(discoveryCandidates);
    
    let currentIndex = 0;
    let uiUpdateTimeout = 0;
    
    function triggerUIUpdate() {
        if (Date.now() - uiUpdateTimeout > 100) {
            renderSubnetsTable();
            renderTopCandidatesTable();
            uiUpdateTimeout = Date.now();
        }
    }
    
    async function runDiscoveryWorker() {
        while (currentIndex < discoveryCandidates.length && scanActive) {
            const current = discoveryCandidates[currentIndex++];
            if (!current) break;
            
            const subnet = current.subnet;
            const res = await testIpConnection(current.ip, current.port, timeout);
            const duration = res.duration;
            let latency = null;
            
            completedPingsCount++;
            subnet.attempts++;
            subnet.completedCount++;
            
            if (res.success) {
                latency = duration;
            } else if (res.error !== 'timeout' && res.error !== 'inactive' && duration !== null) {
                if (duration >= minLatency) {
                    latency = duration;
                }
            }
            
            const scannedCount = parsedSubnets.reduce((sum, s) => sum + s.completedCount, 0);
            const healthyCount = parsedSubnets.reduce((sum, s) => sum + s.healthyCount, 0);
            
            document.getElementById('statScanned').textContent = scannedCount;
            document.getElementById('statHealthy').textContent = healthyCount;
            
            const phaseProgress = (scannedCount / discoveryBudgetTotal) * 100;
            updateScanStatus(
                `Scouting ${current.ip}:${current.port}`, 
                'discovery', 
                phaseProgress, 
                `${scannedCount}/${discoveryBudgetTotal}`
            );
            
            if (latency !== null) {
                subnet.successes++;
                subnet.latencies.push(latency);
                subnet.healthyCount++;
                
                subnet.responsiveCandidates.set(`${current.ip}:${current.port}`, {
                    ip: current.ip,
                    port: current.port,
                    latencies: [latency],
                    successes: 1,
                    attempts: 1,
                    stability: 1.0,
                    jitter: 0,
                    score: 0
                });
                
                recalculateCandidateScore(current.ip, current.port, subnet, timeout);
                
                if (logDiv) {
                    logDiv.innerHTML += `<div style="color: var(--success);">[✓] Scouting Responsive: ${current.ip}:${current.port} (${latency}ms)</div>`;
                    logDiv.scrollTop = logDiv.scrollHeight;
                }
            } else {
                if (logDiv && res.error === 'timeout') {
                } else if (logDiv && duration !== null && duration < minLatency) {
                    logDiv.innerHTML += `<div style="color: var(--text-muted); opacity: 0.6;">[x] Filtered: ${current.ip}:${current.port} (${duration}ms) - below minLatency (${minLatency}ms)</div>`;
                    logDiv.scrollTop = logDiv.scrollHeight;
                }
            }
            
            recalculateSubnetScore(subnet, timeout);
            triggerUIUpdate();
        }
    }
    
    if (discoveryCandidates.length > 0 && scanActive) {
        const actualThreads = Math.min(threadCount, discoveryCandidates.length);
        const workers = [];
        for (let i = 0; i < actualThreads; i++) {
            workers.push((async () => {
                await new Promise(r => setTimeout(r, i * 20));
                await runDiscoveryWorker();
            })());
        }
        await Promise.all(workers);
    }
    
    parsedSubnets.forEach(s => recalculateSubnetScore(s, timeout));
    renderSubnetsTable();
    renderTopCandidatesTable();
    
    if (!scanActive) {
        finalizeScan();
        return;
    }
    
    // ==========================================
    // PHASE 2: VALIDATION & ADAPTIVE ALLOCATION
    // ==========================================
    if (logDiv) {
        logDiv.innerHTML += `<div>[System] Phase 2: Adaptive Validation started...</div>`;
        logDiv.scrollTop = logDiv.scrollHeight;
    }
    
    const explorationBudget = Math.round(validationBudgetTotal * 0.15);
    const proportionalBudget = validationBudgetTotal - explorationBudget;
    
    const totalScore = parsedSubnets.reduce((sum, s) => sum + s.qualityScore, 0);
    const proportionalAllocations = new Map();
    
    parsedSubnets.forEach(s => {
        let share = 0;
        if (totalScore > 0) {
            share = Math.floor(proportionalBudget * (s.qualityScore / totalScore));
        } else {
            share = Math.floor(proportionalBudget / parsedSubnets.length);
        }
        proportionalAllocations.set(s, share);
    });
    
    const explorationAllocations = new Map();
    parsedSubnets.forEach(s => {
        const share = Math.floor(explorationBudget / parsedSubnets.length);
        explorationAllocations.set(s, share);
    });
    
    const combinedBudgets = parsedSubnets.map(s => {
        const propShare = proportionalAllocations.get(s) || 0;
        const explShare = explorationAllocations.get(s) || 0;
        return {
            subnet: s,
            targetBudget: propShare + explShare
        };
    });
    
    const targetBudgetsMap = new Map();
    combinedBudgets.forEach(item => {
        targetBudgetsMap.set(item.subnet, item.targetBudget);
    });
    
    const validationAllocations = distributeProportionalBudget(parsedSubnets, targetBudgetsMap);
    
    parsedSubnets.forEach(s => {
        s.validationBudget = validationAllocations.get(s) || 0;
    });
    
    const actualValidationBudget = parsedSubnets.reduce((sum, s) => sum + s.validationBudget, 0);
    totalPingsExpected = completedPingsCount + (actualValidationBudget * testCount);
    
    renderSubnetsTable();
    
    const validationCandidates = [];
    parsedSubnets.forEach(s => {
        if (s.validationBudget > 0) {
            let generated = 0;
            let attempts = 0;
            const maxAttempts = s.validationBudget * 50;
            
            while (generated < s.validationBudget && attempts < maxAttempts) {
                attempts++;
                const randVal = Math.floor(Math.random() * s.capacity);
                if (!s.sampledOffsets.has(randVal)) {
                    s.sampledOffsets.add(randVal);
                    const ip = getIpFromOffset(s.startNum, randVal);
                    const port = selectedPorts[Math.floor(Math.random() * selectedPorts.length)];
                    validationCandidates.push({ ip, port, subnet: s, offset: randVal });
                    generated++;
                }
            }
            
            if (generated < s.validationBudget) {
                const remainingAlloc = s.validationBudget - generated;
                for (let i = 0; i < remainingAlloc; i++) {
                    const randVal = Math.floor(Math.random() * s.capacity);
                    const ip = getIpFromOffset(s.startNum, randVal);
                    const port = selectedPorts[Math.floor(Math.random() * selectedPorts.length)];
                    validationCandidates.push({ ip, port, subnet: s, offset: randVal });
                }
            }
        }
    });
    
    shuffleArray(validationCandidates);
    
    let valIndex = 0;
    let valScannedCount = 0;
    
    async function runValidationWorker() {
        while (valIndex < validationCandidates.length && scanActive) {
            const current = validationCandidates[valIndex++];
            if (!current) break;
            
            const subnet = current.subnet;
            const latencies = [];
            let successes = 0;
            
            for (let t = 0; t < testCount; t++) {
                if (!scanActive) break;
                
                const res = await testIpConnection(current.ip, current.port, timeout);
                const duration = res.duration;
                completedPingsCount++;
                
                let isSuccess = false;
                if (res.success) {
                    isSuccess = true;
                } else if (res.error !== 'timeout' && res.error !== 'inactive' && duration !== null) {
                    if (duration >= minLatency) {
                        isSuccess = true;
                    }
                }
                
                if (isSuccess) {
                    successes++;
                    latencies.push(duration);
                    subnet.latencies.push(duration);
                }
                
                triggerUIUpdate();
            }
            
            valScannedCount++;
            subnet.attempts += testCount;
            subnet.completedCount += subnet.validationBudget > 0 ? 1 : 0;
            
            const globalScanned = discoveryBudgetTotal + valScannedCount;
            const healthyCount = parsedSubnets.reduce((sum, s) => sum + s.healthyCount, 0);
            
            document.getElementById('statScanned').textContent = globalScanned;
            document.getElementById('statHealthy').textContent = healthyCount;
            
            const phaseProgress = (valScannedCount / actualValidationBudget) * 100;
            updateScanStatus(
                `Verifying ${current.ip}:${current.port}`, 
                'validation', 
                phaseProgress, 
                `${valScannedCount}/${actualValidationBudget}`
            );
            
            if (successes > 0) {
                subnet.healthyCount++;
                
                const avg = Math.round(latencies.reduce((a, b) => a + b, 0) / latencies.length);
                let jitter = 0;
                if (latencies.length > 1) {
                    let diffSum = 0;
                    for (let i = 0; i < latencies.length - 1; i++) {
                        diffSum += Math.abs(latencies[i+1] - latencies[i]);
                    }
                    jitter = diffSum / (latencies.length - 1);
                }
                
                let stdDev = 0;
                if (latencies.length > 0) {
                    const variance = latencies.reduce((sum, val) => sum + Math.pow(val - avg, 2), 0) / latencies.length;
                    stdDev = Math.sqrt(variance);
                }
                const stability = avg > 0 ? 1 - Math.min(1, stdDev / avg) : 0;
                
                subnet.responsiveCandidates.set(`${current.ip}:${current.port}`, {
                    ip: current.ip,
                    port: current.port,
                    latencies: latencies,
                    successes: successes,
                    attempts: testCount,
                    stability: stability,
                    jitter: jitter,
                    score: 0
                });
                
                recalculateCandidateScore(current.ip, current.port, subnet, timeout);
                
                if (logDiv) {
                    logDiv.innerHTML += `<div style="color: var(--success);">[✓] Validation Responsive: ${current.ip}:${current.port} (RTT: ${avg}ms, Jitter: ${Math.round(jitter)}ms, Stability: ${Math.round(stability * 100)}%)</div>`;
                    logDiv.scrollTop = logDiv.scrollHeight;
                }
            }
            
            recalculateSubnetScore(subnet, timeout);
            triggerUIUpdate();
        }
    }
    
    if (validationCandidates.length > 0 && scanActive) {
        const actualThreads = Math.min(threadCount, validationCandidates.length);
        const workers = [];
        for (let i = 0; i < actualThreads; i++) {
            workers.push((async () => {
                await new Promise(r => setTimeout(r, i * 20));
                await runValidationWorker();
            })());
        }
        await Promise.all(workers);
    }
    
    // ==========================================
    // PHASE 3: DEEP SCAN & FINAL RANKING
    // ==========================================
    if (scanActive) {
        const actualDeepCandidates = topCandidates.slice(0, 10);
        const deepTestCount = Math.max(5, testCount * 2);
        
        if (actualDeepCandidates.length > 0) {
            if (logDiv) {
                logDiv.innerHTML += `<div>[System] Phase 3: Deep Scan started on top ${actualDeepCandidates.length} candidates (${deepTestCount} pings each)...</div>`;
                logDiv.scrollTop = logDiv.scrollHeight;
            }
            
            totalPingsExpected = completedPingsCount + (actualDeepCandidates.length * deepTestCount);
            
            let deepIndex = 0;
            let deepScannedCount = 0;
            
            async function runDeepWorker() {
                while (deepIndex < actualDeepCandidates.length && scanActive) {
                    const current = actualDeepCandidates[deepIndex++];
                    if (!current) break;
                    
                    const subnet = parsedSubnets.find(s => s.cidr === current.subnetCidr);
                    if (!subnet) continue;
                    
                    const candKey = `${current.ip}:${current.port}`;
                    const cand = subnet.responsiveCandidates.get(candKey);
                    if (!cand) continue;
                    
                    const latencies = [];
                    let successes = 0;
                    
                    for (let t = 0; t < deepTestCount; t++) {
                        if (!scanActive) break;
                        
                        const res = await testIpConnection(current.ip, current.port, timeout);
                        completedPingsCount++;
                        
                        let isSuccess = false;
                        if (res.success) {
                            isSuccess = true;
                        } else if (res.error !== 'timeout' && res.error !== 'inactive' && res.duration !== null) {
                            if (res.duration >= minLatency) {
                                isSuccess = true;
                            }
                        }
                        
                        if (isSuccess) {
                            successes++;
                            latencies.push(res.duration);
                            subnet.latencies.push(res.duration);
                            cand.latencies.push(res.duration);
                        }
                        
                        triggerUIUpdate();
                    }
                    
                    deepScannedCount++;
                    subnet.attempts += deepTestCount;
                    subnet.successes += successes;
                    cand.attempts += deepTestCount;
                    cand.successes += successes;
                    
                    const phaseProgress = (deepScannedCount / actualDeepCandidates.length) * 100;
                    updateScanStatus(
                        `Deep probing ${current.ip}:${current.port}`, 
                        'deep', 
                        phaseProgress, 
                        `${deepScannedCount}/${actualDeepCandidates.length}`
                    );
                    
                    if (successes > 0) {
                        const allLats = cand.latencies;
                        const avg = Math.round(allLats.reduce((a, b) => a + b, 0) / allLats.length);
                        let jitter = 0;
                        if (allLats.length > 1) {
                            let diffSum = 0;
                            for (let i = 0; i < allLats.length - 1; i++) {
                                diffSum += Math.abs(allLats[i+1] - allLats[i]);
                            }
                            jitter = diffSum / (allLats.length - 1);
                        }
                        
                        let stdDev = 0;
                        if (allLats.length > 0) {
                            const variance = allLats.reduce((sum, val) => sum + Math.pow(val - avg, 2), 0) / allLats.length;
                            stdDev = Math.sqrt(variance);
                        }
                        const stability = avg > 0 ? 1 - Math.min(1, stdDev / avg) : 0;
                        
                        cand.stability = stability;
                        cand.jitter = jitter;
                        
                        recalculateCandidateScore(current.ip, current.port, subnet, timeout);
                        
                        if (logDiv) {
                            logDiv.innerHTML += `<div style="color: var(--accent-color);">[✓] Deep scan result: ${current.ip}:${current.port} (Avg: ${avg}ms, Jitter: ${Math.round(jitter)}ms, Stability: ${Math.round(stability * 100)}%)</div>`;
                            logDiv.scrollTop = logDiv.scrollHeight;
                        }
                    }
                    
                    recalculateSubnetScore(subnet, timeout);
                    triggerUIUpdate();
                }
            }
            
            const deepThreads = Math.min(3, actualDeepCandidates.length);
            const workers = [];
            for (let i = 0; i < deepThreads; i++) {
                workers.push(runDeepWorker());
            }
            await Promise.all(workers);
            
            parsedSubnets.forEach(s => {
                recalculateSubnetScore(s, timeout);
                for (const key of s.responsiveCandidates.keys()) {
                    recalculateCandidateScore(key.split(':')[0], parseInt(key.split(':')[1]), s, timeout);
                }
            });
            
            scanResults = [...topCandidates].sort((a, b) => b.score - a.score);
            renderResultsTable();
            
            updateScanStatus('Scan completed successfully!', 'deep', 100, "Completed");
        } else {
            if (logDiv) {
                logDiv.innerHTML += `<div>[System] Phase 3: Skipped (no healthy candidates found)</div>`;
                logDiv.scrollTop = logDiv.scrollHeight;
            }
            
            parsedSubnets.forEach(s => {
                recalculateSubnetScore(s, timeout);
            });
            
            scanResults = [...topCandidates].sort((a, b) => b.score - a.score);
            renderResultsTable();
            
            updateScanStatus('No candidates to deep scan.', 'deep', 0, "Skipped");
        }
    }
    
    finalizeScan();
    
    function finalizeScan() {
        scanActive = false;
        document.getElementById('startScanBtn').disabled = false;
        document.getElementById('stopScanBtn').disabled = true;
        document.getElementById('statRemainingTime').textContent = "00:00";
        
        const healthyCount = parsedSubnets.reduce((sum, s) => sum + s.healthyCount, 0);
        
        if (scanResults.length > 0) {
            showSuccess(`Scan complete. Found ${scanResults.length} working configurations.`);
        } else {
            showError("Scan completed, but no responsive IPs were found. Please check your connection parameters or increase the timeout.");
        }
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
    
    updateScanStatus('Scan stopped by user.', 'deep', 100, "Stopped");
    showWarning("Scan stopped. Results gathered so far are displayed below.");
}

function testIpConnection(ip, port, timeout) {
    return new Promise((resolve) => {
        if (!scanActive) {
            resolve({ success: false, duration: null, error: 'inactive' });
            return;
        }
        
        let controller;
        let timeoutId;
        
        try {
            controller = new AbortController();
            activeControllers.push(controller);
            
            timeoutId = setTimeout(() => {
                try {
                    controller.abort();
                } catch (e) {}
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
                resolve({ success: true, duration, error: null });
            })
            .catch(err => {
                const duration = Math.round(performance.now() - startTime);
                clearTimeout(timeoutId);
                removeController(controller);
                
                if (err && err.name === 'AbortError') {
                    resolve({ success: false, duration: null, error: 'timeout' });
                } else {
                    resolve({ success: false, duration, error: (err && err.message) || 'NetworkError' });
                }
            });
        } catch (err) {
            if (timeoutId) clearTimeout(timeoutId);
            if (controller) removeController(controller);
            resolve({ success: false, duration: null, error: err.message || 'SyncError' });
        }
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
                <td style="font-family: monospace; font-weight: 600; cursor: pointer; text-decoration: underline dotted;" onclick="copySingleIpText('${item.ip}')" title="Click to copy IP">${item.ip}</td>
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

function copySingleIpText(ip) {
    copyTextToClipboard(ip, () => showSuccess(`Copied IP ${ip} to clipboard.`));
}
window.copySingleIpText = copySingleIpText;

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

function toggleNamingFields() {
    const style = document.getElementById('configNameStyle').value;
    const prefixGroup = document.getElementById('configPrefixGroup');
    if (!prefixGroup) return;

    if (style === 'keep') {
        prefixGroup.style.display = 'none';
    } else {
        prefixGroup.style.display = 'block';
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
                generatedOutput += replaceIPAndPortInConfig(config.trim(), currentIp, null, count + 1);
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
            generatedOutput += replaceIPAndPortInConfig(config.trim(), parsedIp, endpoint.port, count + 1);
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

                generatedOutput += replaceIPAndPortInConfig(baseConfig.trim(), ipPart, portPart, count + 1);
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
        generatedOutput += replaceIPAndPortInConfig(config.trim(), spoofIp, spoofPort, count + 1);
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

function replaceIPAndPortInConfig(inputConfig, ipOrAddress, newPort = null, index = 1) {
    let configType = detectConfigType(inputConfig);
    let addressStr = typeof ipOrAddress === 'string' ? ipOrAddress : ipOrAddress.toString();
    let result = '';

    const nameStyle = document.getElementById('configNameStyle')?.value || 'keep';
    const namePrefix = document.getElementById('configNamePrefix')?.value.trim() || '';

    let newName = '';
    if (nameStyle === 'fixed') {
        newName = namePrefix;
    } else if (nameStyle === 'numeric') {
        newName = `${namePrefix}${index}`;
    } else if (nameStyle === 'random') {
        const rand = Math.random().toString(36).substring(2, 7);
        newName = `${namePrefix}${rand}`;
    }

    if (configType === 'vmess') {
        let vmessConfig = JSON.parse(Base64.decode(inputConfig.replace('vmess://', '')));
        vmessConfig.add = addressStr;
        if (newPort) vmessConfig.port = parseInt(newPort);
        if (nameStyle !== 'keep') {
            vmessConfig.ps = newName;
        }
        result = `vmess://${Base64.encode(JSON.stringify(vmessConfig))}\n`;
    } else if (configType === 'vless') {
        if (addressStr.includes(':') && !addressStr.startsWith('[')) {
            addressStr = `[${addressStr}]`;
        }
        const match = inputConfig.match(/^(vless:\/\/[^@]+)@([^:]+):(\d+)(.*)$/);
        if (match) {
            const [_, start, domain, port, end] = match;
            let updatedEnd = end;
            if (nameStyle !== 'keep') {
                const hashIndex = end.indexOf('#');
                if (hashIndex !== -1) {
                    updatedEnd = end.substring(0, hashIndex) + '#' + newName;
                } else {
                    updatedEnd = end + '#' + newName;
                }
            }
            result = `${start}@${addressStr}:${newPort || port}${updatedEnd}\n`;
        } else {
            result = inputConfig + '\n';
        }
    } else if (configType === 'wireguard') {
        const regex = /^(wireguard:\/\/[^@]+@)[^:]+:(\d+)(.*)$/;
        result = inputConfig.replace(regex, (m, p1, p2, p3) => {
            let updatedP3 = p3;
            if (nameStyle !== 'keep') {
                const hashIndex = p3.indexOf('#');
                if (hashIndex !== -1) {
                    updatedP3 = p3.substring(0, hashIndex) + '#' + newName;
                } else {
                    updatedP3 = p3 + '#' + newName;
                }
            }
            return `${p1}${addressStr}:${newPort || p2}${updatedP3}\n`;
        });
    } else if (configType === 'trojan') {
        const regex = /^(trojan:\/\/[^@]+@)[^:]+:(\d+)(.*)$/;
        result = inputConfig.replace(regex, (m, p1, p2, p3) => {
            let updatedP3 = p3;
            if (nameStyle !== 'keep') {
                const hashIndex = p3.indexOf('#');
                if (hashIndex !== -1) {
                    updatedP3 = p3.substring(0, hashIndex) + '#' + newName;
                } else {
                    updatedP3 = p3 + '#' + newName;
                }
            }
            return `${p1}${addressStr}:${newPort || p2}${updatedP3}\n`;
        });
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
onScanProviderChange();
toggleInputFields();
toggleNamingFields();
updateOutputCountValue();
updateScanSampleCount();
