// TInSOW - Dashboard Frontend Logic

document.addEventListener('DOMContentLoaded', () => {
    // Application State
    const state = {
        config: {
            gemini_configured: false,
            otx_configured: false,
            model: 'gemini-1.5-flash'
        },
        currentAnalysis: null,
        history: [],
        repoItems: [],
        stats: {
            totalAnalyzed: 0,
            highRisk: 0,
            siemRules: 0,
            soarPlaybooks: 0
        }
    };

    // DOM Elements
    const sections = {
        dashboard: document.getElementById('sec-dashboard'),
        analyzer: document.getElementById('sec-analyzer'),
        exporter: document.getElementById('sec-exporter'),
        settings: document.getElementById('sec-settings')
    };

    const navItems = {
        dashboard: document.getElementById('nav-dashboard'),
        analyzer: document.getElementById('nav-analyzer'),
        exporter: document.getElementById('nav-exporter'),
        settings: document.getElementById('nav-settings')
    };

    const pageTitle = document.getElementById('page-title');
    const pageSubtitle = document.getElementById('page-subtitle');

    // Sidebar status lights
    const statusGeminiDot = document.getElementById('status-gemini-dot');
    const statusGeminiText = document.getElementById('status-gemini-text');
    const statusOtxDot = document.getElementById('status-otx-dot');
    const statusOtxText = document.getElementById('status-otx-text');

    // -------------------------------------------------------------
    // 1. NAVIGATION & ROUTING
    // -------------------------------------------------------------
    function handleNavigation() {
        const hash = window.location.hash || '#dashboard';
        
        // Update active nav link
        Object.keys(navItems).forEach(key => {
            const item = navItems[key];
            if (item.getAttribute('href') === hash) {
                item.classList.add('active');
            } else {
                item.classList.remove('active');
            }
        });

        // Show/hide sections
        Object.keys(sections).forEach(key => {
            const section = sections[key];
            if (`#${key}` === hash) {
                section.classList.add('active');
            } else {
                section.classList.remove('active');
            }
        });

        // Update headers based on view
        if (hash === '#dashboard') {
            pageTitle.innerText = "Dashboard Overview";
            pageSubtitle.innerText = "Track threat intelligence feeds, parse context, and generate detections.";
            loadDashboardData();
        } else if (hash === '#analyzer') {
            pageTitle.innerText = "Intel Analyzer";
            pageSubtitle.innerText = "Query CVE database, lookup OTX reputation, or parse raw threat data using Gemini.";
        } else if (hash === '#exporter') {
            pageTitle.innerText = "Rules & Playbooks Repository";
            pageSubtitle.innerText = "View, search, and download generated SIEM rules and SOAR playbooks.";
            loadRepositoryData();
        } else if (hash === '#settings') {
            pageTitle.innerText = "System Settings";
            pageSubtitle.innerText = "Configure API integrations for Google Gemini AI and AlienVault OTX.";
            loadConfigSettings();
        }
    }

    window.addEventListener('hashchange', handleNavigation);
    // Initial routing
    handleNavigation();

    // -------------------------------------------------------------
    // 2. NOTIFICATION TOAST SYSTEM
    // -------------------------------------------------------------
    function showToast(message, type = 'info') {
        const container = document.getElementById('toast-container');
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        
        let icon = '<i class="fa-solid fa-circle-info toast-icon"></i>';
        if (type === 'success') icon = '<i class="fa-solid fa-circle-check toast-icon"></i>';
        if (type === 'error') icon = '<i class="fa-solid fa-circle-exclamation toast-icon"></i>';

        toast.innerHTML = `
            ${icon}
            <div class="toast-message">${message}</div>
            <button class="toast-close"><i class="fa-solid fa-xmark"></i></button>
        `;
        
        container.appendChild(toast);

        // Bind close button
        toast.querySelector('.toast-close').addEventListener('click', () => {
            toast.classList.add('hide');
            setTimeout(() => toast.remove(), 300);
        });

        // Auto remove
        setTimeout(() => {
            if (toast.parentNode) {
                toast.classList.add('hide');
                setTimeout(() => toast.remove(), 300);
            }
        }, 5000);
    }

    // -------------------------------------------------------------
    // 3. SETTINGS & INITIAL CONFIG LOAD
    // -------------------------------------------------------------
    // Toggle Password Visibility
    document.querySelectorAll('.btn-toggle-password').forEach(btn => {
        btn.addEventListener('click', () => {
            const targetId = btn.getAttribute('data-target');
            const input = document.getElementById(targetId);
            const icon = btn.querySelector('i');
            
            if (input.type === 'password') {
                input.type = 'text';
                icon.className = 'fa-regular fa-eye-slash';
            } else {
                input.type = 'password';
                icon.className = 'fa-regular fa-eye';
            }
        });
    });

    async function loadConfigSettings() {
        try {
            const response = await fetch('/api/config');
            const data = await response.json();
            
            state.config = data;
            
            document.getElementById('settings-gemini-key').value = data.gemini_configured ? '••••••••••••••••••••••••' : '';
            document.getElementById('settings-gemini-model').value = data.model || 'gemini-1.5-flash';
            document.getElementById('settings-otx-key').value = data.otx_configured ? '••••••••••••••••••••••••' : '';
            
            updateStatusIndicators();
        } catch (error) {
            console.error('Error fetching configuration:', error);
            showToast('Failed to load system configuration.', 'error');
        }
    }

    function updateStatusIndicators() {
        if (state.config.gemini_configured) {
            statusGeminiDot.className = 'pulse-dot green';
            statusGeminiText.innerText = 'Connected';
            statusGeminiText.style.color = '#39ff14';
        } else {
            statusGeminiDot.className = 'pulse-dot red';
            statusGeminiText.innerText = 'Unconfigured';
            statusGeminiText.style.color = '#ff3131';
        }

        if (state.config.otx_configured) {
            statusOtxDot.className = 'pulse-dot green';
            statusOtxText.innerText = 'Active';
            statusOtxText.style.color = '#39ff14';
        } else {
            statusOtxDot.className = 'pulse-dot gray';
            statusOtxText.innerText = 'Offline';
            statusOtxText.style.color = '#64748b';
        }
    }

    // Save configuration settings
    const settingsForm = document.getElementById('settings-form');
    settingsForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const geminiKey = document.getElementById('settings-gemini-key').value.trim();
        const model = document.getElementById('settings-gemini-model').value;
        const otxKey = document.getElementById('settings-otx-key').value.trim();
        
        const payload = { model };
        
        // Only send keys if changed (i.e. not the placeholder bullet string)
        if (geminiKey && geminiKey !== '••••••••••••••••••••••••') {
            payload.gemini_api_key = geminiKey;
        }
        if (otxKey && otxKey !== '••••••••••••••••••••••••') {
            payload.otx_api_key = otxKey;
        }
        
        try {
            const response = await fetch('/api/config', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            const data = await response.json();
            
            state.config = data;
            updateStatusIndicators();
            showToast('System configuration saved successfully.', 'success');
            loadConfigSettings(); // Reload to reset input states
        } catch (error) {
            console.error('Error saving config:', error);
            showToast('Failed to save settings.', 'error');
        }
    });

    // Test Connections
    const btnTestSettings = document.getElementById('btn-test-settings');
    btnTestSettings.addEventListener('click', async () => {
        btnTestSettings.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Testing...';
        btnTestSettings.disabled = true;
        
        try {
            const response = await fetch('/api/test-connections', { method: 'POST' });
            const data = await response.json();
            
            if (data.gemini_ok) {
                showToast(`Gemini API connection OK (Using ${data.gemini_model})`, 'success');
            } else {
                showToast(`Gemini API failed: ${data.gemini_error || 'Invalid API Key'}`, 'error');
            }
            
            if (data.otx_ok) {
                showToast('OTX API connection OK', 'success');
            } else if (state.config.otx_configured) {
                showToast(`OTX API failed: ${data.otx_error || 'Invalid key'}`, 'error');
            }
            
            // Reload configuration states
            loadConfigSettings();
        } catch (error) {
            console.error('Test connections failed:', error);
            showToast('Network error testing configuration.', 'error');
        } finally {
            btnTestSettings.innerHTML = '<i class="fa-solid fa-circle-check"></i> Test Connections';
            btnTestSettings.disabled = false;
        }
    });

    // Load configuration at startup
    loadConfigSettings();

    // -------------------------------------------------------------
    // 4. TAB CONTROLS (Analyzer View and Results View)
    // -------------------------------------------------------------
    // Input Tabs
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const tabContainer = btn.parentElement;
            const tabContentId = btn.getAttribute('data-tab');
            
            // Remove active classes
            tabContainer.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            const analyzerBody = tabContainer.closest('.panel').querySelector('.panel-body');
            analyzerBody.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            
            // Add active classes
            btn.classList.add('active');
            document.getElementById(tabContentId).classList.add('active');
        });
    });

    // Results View Tabs
    document.querySelectorAll('.res-tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const nav = btn.parentElement;
            const targetId = btn.getAttribute('data-res-tab');
            
            nav.querySelectorAll('.res-tab-btn').forEach(b => b.classList.remove('active'));
            const resultsContainer = nav.parentElement;
            resultsContainer.querySelectorAll('.res-tab-content').forEach(c => c.classList.remove('active'));
            
            btn.classList.add('active');
            document.getElementById(targetId).classList.add('active');
        });
    });

    // -------------------------------------------------------------
    // 5. THREAT ANALYZER LOGIC & MOCK TERMINAL
    // -------------------------------------------------------------
    const loaderConsole = document.getElementById('loader-console-output');
    const loaderProgress = document.getElementById('loader-progress-fill');
    
    function resetTerminalConsole() {
        loaderConsole.innerHTML = '';
        loaderProgress.style.width = '0%';
    }

    function addConsoleLine(text, status = 'OK') {
        const line = document.createElement('p');
        line.className = 'console-line';
        
        let statusTag = '';
        if (status === 'OK') statusTag = '<span class="c-green">[OK]</span>';
        else if (status === 'INFO') statusTag = '<span class="c-cyan">[INFO]</span>';
        else if (status === 'WARN') statusTag = '<span class="c-yellow">[WARN]</span>';
        else if (status === 'ERR') statusTag = '<span class="c-red">[ERROR]</span>';
        
        line.innerHTML = `${statusTag} ${text}`;
        loaderConsole.appendChild(line);
        loaderConsole.scrollTop = loaderConsole.scrollHeight;
    }

    function setTerminalProgress(percent) {
        loaderProgress.style.width = `${percent}%`;
    }

    // Core analysis flow trigger
    async function runAnalysis(endpoint, payload) {
        if (!state.config.gemini_configured) {
            showToast('Gemini API is not configured. Please add an API key in Settings first.', 'error');
            window.location.hash = '#settings';
            return;
        }

        const loader = document.getElementById('analyzer-loader');
        const resultsEl = document.getElementById('analysis-results');
        
        // UI resets
        resultsEl.classList.add('hidden');
        loader.classList.remove('hidden');
        resetTerminalConsole();
        
        addConsoleLine('TInSOW Core parser starting...', 'INFO');
        setTerminalProgress(10);
        
        // Start mock logs while backend runs
        let progress = 10;
        const mockLogInterval = setInterval(() => {
            if (progress < 85) {
                progress += Math.floor(Math.random() * 5) + 2;
                setTerminalProgress(progress);
                
                const logs = [
                    'Establishing secure session with intelligence feeds...',
                    'Querying database for vulnerability intelligence mappings...',
                    'Calling AlienVault OTX indicator feeds...',
                    'Acquiring threat indicators and actor correlations...',
                    'Packaging contextual parameters for Gemini model...',
                    'Initializing Gemini Generative AI pipeline...',
                    'Invoking Gemini parser with structured schema definitions...',
                    'Parsing vulnerability severity & contextual details...',
                    'Mapping technical behaviors to MITRE ATT&CK Framework...',
                    'Mapping tactic stages: Initial Access, Execution, Persistence...',
                    'Applying contextual risk score algorithm...',
                    'Synthesizing Sigma and Elastic security rules...',
                    'Assembling SOAR remediation and isolation playbooks...'
                ];
                
                const log = logs[Math.floor(Math.random() * logs.length)];
                addConsoleLine(log, Math.random() > 0.85 ? 'INFO' : 'OK');
            }
        }, 1200);

        try {
            addConsoleLine('Sending query payload to backend API...', 'INFO');
            
            const response = await fetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            clearInterval(mockLogInterval);

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.detail || 'Analysis backend error occurred.');
            }

            const data = await response.json();
            
            setTerminalProgress(95);
            addConsoleLine('AI Response parsed successfully. Finalizing structural UI assets...', 'INFO');
            
            setTimeout(() => {
                setTerminalProgress(100);
                loader.classList.add('hidden');
                displayAnalysisResults(data);
                showToast('Threat analysis and rule generation complete.', 'success');
            }, 600);

        } catch (error) {
            clearInterval(mockLogInterval);
            console.error('Analysis error:', error);
            addConsoleLine(`Fatal exception during parser run: ${error.message}`, 'ERR');
            setTerminalProgress(0);
            showToast(`Analysis failed: ${error.message}`, 'error');
            
            // Add a failure button to clear loading screen
            const btnClear = document.createElement('button');
            btnClear.className = 'btn btn-secondary btn-sm';
            btnClear.style.marginTop = '1rem';
            btnClear.innerText = 'Clear Error Terminal';
            btnClear.onclick = () => loader.classList.add('hidden');
            loaderConsole.appendChild(btnClear);
        }
    }

    // Click Handlers for Search & Analyze triggers
    document.getElementById('btn-analyze-cve').addEventListener('click', () => {
        const cveInput = document.getElementById('cve-input').value.trim();
        if (!cveInput) {
            showToast('Please enter a valid CVE ID (e.g. CVE-2024-3094).', 'error');
            return;
        }
        runAnalysis('/api/analyze/cve', { cve_id: cveInput });
    });

    document.getElementById('btn-analyze-otx').addEventListener('click', () => {
        const otxType = document.getElementById('otx-type').value;
        const otxInput = document.getElementById('otx-input').value.trim();
        if (!otxInput) {
            showToast('Please enter an indicator value to search.', 'error');
            return;
        }
        runAnalysis('/api/analyze/otx', { indicator_type: otxType, indicator_value: otxInput });
    });

    document.getElementById('btn-analyze-raw').addEventListener('click', () => {
        const rawInput = document.getElementById('raw-input').value.trim();
        if (!rawInput) {
            showToast('Please paste raw intelligence text to parse.', 'error');
            return;
        }
        runAnalysis('/api/analyze/raw', { text: rawInput });
    });

    // -------------------------------------------------------------
    // 6. RENDER ANALYSIS RESULTS VIEW
    // -------------------------------------------------------------
    function displayAnalysisResults(data) {
        state.currentAnalysis = data;
        const resultsEl = document.getElementById('analysis-results');
        
        // 1. General Summary details
        document.getElementById('result-threat-title').innerText = data.threat_name;
        document.getElementById('result-threat-type').innerText = data.threat_name.toUpperCase().startsWith('CVE') ? 'CVE Vulnerability Analysis' : 'Indicator & Log Context';
        
        const affectedText = data.affected_systems.length > 0 ? `Affected: ${data.affected_systems.join(', ')}` : 'Affected Systems: Contextual determination ongoing';
        document.getElementById('result-affected-summary').innerText = affectedText;
        
        // Risk score display (dial progress animation)
        const riskScore = parseInt(data.risk_score) || 0;
        document.getElementById('result-risk-score').innerText = riskScore;
        
        const scoreFill = document.getElementById('risk-score-fill');
        scoreFill.style.strokeDasharray = `${riskScore}, 100`;
        
        // Color dial based on risk level
        if (riskScore >= 70) {
            scoreFill.style.stroke = 'var(--red)';
            scoreFill.style.filter = 'drop-shadow(0 0 5px var(--red-glow))';
        } else if (riskScore >= 40) {
            scoreFill.style.stroke = 'var(--yellow)';
            scoreFill.style.filter = 'drop-shadow(0 0 5px var(--yellow-glow))';
        } else {
            scoreFill.style.stroke = 'var(--green)';
            scoreFill.style.filter = 'drop-shadow(0 0 5px var(--green-glow))';
        }

        // 2. General Tab Analysis Details
        document.getElementById('result-summary').innerText = data.summary;
        document.getElementById('result-tech-details').innerText = data.technical_details;
        document.getElementById('result-risk-justification').innerText = data.risk_justification;
        
        // Affected systems tags
        const tagsContainer = document.getElementById('result-affected-tags');
        tagsContainer.innerHTML = '';
        if (data.affected_systems.length > 0) {
            data.affected_systems.forEach(sys => {
                const tag = document.createElement('span');
                tag.className = 'system-tag';
                tag.innerText = sys;
                tagsContainer.appendChild(tag);
            });
        } else {
            tagsContainer.innerHTML = '<span class="text-muted">No specific system tags identified</span>';
        }

        // 3. MITRE ATT&CK Mapping
        const mitreContainer = document.getElementById('result-mitre-timeline');
        mitreContainer.innerHTML = '';
        if (data.mitre_attack && data.mitre_attack.length > 0) {
            data.mitre_attack.forEach(tech => {
                const block = document.createElement('div');
                block.className = 'mitre-block';
                block.innerHTML = `
                    <div class="mitre-header">
                        <span class="mitre-tactic">${tech.tactic}</span>
                        <span class="mitre-tech-badge">${tech.technique_id}</span>
                        <span class="mitre-tech-name">${tech.technique_name}</span>
                    </div>
                    <p class="mitre-desc">${tech.justification}</p>
                `;
                mitreContainer.appendChild(block);
            });
        } else {
            mitreContainer.innerHTML = `
                <div class="empty-state">
                    <i class="fa-solid fa-triangle-exclamation"></i>
                    <p>No MITRE ATT&CK techniques mapped to this threat.</p>
                </div>
            `;
        }

        // 4. Extracted IOCs Table
        const iocBody = document.getElementById('result-ioc-table-body');
        iocBody.innerHTML = '';
        if (data.indicators && data.indicators.length > 0) {
            data.indicators.forEach(ioc => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td><span class="ioc-type-badge">${ioc.type}</span></td>
                    <td><span class="ioc-value">${escapeHtml(ioc.value)}</span></td>
                    <td>${escapeHtml(ioc.description)}</td>
                    <td>
                        <button class="btn btn-secondary btn-sm btn-search-ioc" data-type="${ioc.type}" data-val="${ioc.value}">
                            <i class="fa-solid fa-magnifying-glass"></i> Pivot Search
                        </button>
                    </td>
                `;
                iocBody.appendChild(tr);
            });

            // Bind pivot search buttons
            iocBody.querySelectorAll('.btn-search-ioc').forEach(btn => {
                btn.addEventListener('click', () => {
                    const type = btn.getAttribute('data-type');
                    const val = btn.getAttribute('data-val');
                    
                    // Select OTX tab and populate inputs
                    document.querySelector('.tab-btn[data-tab="otx-tab"]').click();
                    document.getElementById('otx-type').value = mapIocTypeToOtx(type);
                    document.getElementById('otx-input').value = val;
                    
                    // Redirect to analyzer section if not visible
                    window.location.hash = '#analyzer';
                    
                    showToast(`Indicator loaded: Searching ${val}...`, 'info');
                });
            });
        } else {
            iocBody.innerHTML = `
                <tr>
                    <td colspan="4" class="text-center text-muted" style="padding: 2rem;">No indicators of compromise extracted.</td>
                </tr>
            `;
        }

        // 5. SIEM Rules & SOAR Playbooks Selectors Setup
        setupRulePlaybookSelectors(data);

        // Show the results
        resultsEl.classList.remove('hidden');
        resultsEl.scrollIntoView({ behavior: 'smooth' });
    }

    function setupRulePlaybookSelectors(data) {
        // SIEM Select
        const siemSelect = document.getElementById('siem-selector');
        siemSelect.innerHTML = '';
        data.siem_rules.forEach((rule, idx) => {
            const opt = document.createElement('option');
            opt.value = idx;
            opt.innerText = rule.platform;
            siemSelect.appendChild(opt);
        });

        // SOAR Select
        const soarSelect = document.getElementById('soar-selector');
        soarSelect.innerHTML = '';
        data.soar_playbooks.forEach((play, idx) => {
            const opt = document.createElement('option');
            opt.value = idx;
            opt.innerText = play.platform;
            soarSelect.appendChild(opt);
        });

        // Bind Change Events
        siemSelect.onchange = () => updateSiemDisplay(data.siem_rules[siemSelect.value]);
        soarSelect.onchange = () => updateSoarDisplay(data.soar_playbooks[soarSelect.value]);

        // Trigger first rendering
        if (data.siem_rules.length > 0) updateSiemDisplay(data.siem_rules[0]);
        if (data.soar_playbooks.length > 0) updateSoarDisplay(data.soar_playbooks[0]);
    }

    function updateSiemDisplay(rule) {
        if (!rule) return;
        document.getElementById('siem-expl').innerText = rule.explanation;
        const codeBox = document.getElementById('siem-code-box');
        codeBox.textContent = rule.content;
    }

    function updateSoarDisplay(playbook) {
        if (!playbook) return;
        document.getElementById('soar-expl').innerText = playbook.explanation;
        const codeBox = document.getElementById('soar-code-box');
        codeBox.textContent = playbook.content;
    }

    // Helper functions
    function escapeHtml(string) {
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        return String(string).replace(/[&<>"']/g, function(m) { return map[m]; });
    }

    function mapIocTypeToOtx(type) {
        const upper = type.toUpperCase();
        if (upper.includes('IP')) return 'IPv4';
        if (upper.includes('DOMAIN')) return 'domain';
        if (upper.includes('HASH')) return 'file';
        if (upper.includes('URL')) return 'url';
        return 'hostname';
    }

    // -------------------------------------------------------------
    // 7. ARTIFACT DOWLOAD AND COPY CAPABILITIES
    // -------------------------------------------------------------
    // Copy Code Box Listener
    document.querySelectorAll('.btn-copy-code').forEach(btn => {
        btn.addEventListener('click', () => {
            const targetId = btn.getAttribute('data-target');
            const codeEl = document.getElementById(targetId);
            
            navigator.clipboard.writeText(codeEl.textContent).then(() => {
                btn.innerHTML = '<i class="fa-solid fa-check"></i> Copied';
                btn.classList.add('copied');
                showToast('Code copied to clipboard.', 'success');
                
                setTimeout(() => {
                    btn.innerHTML = '<i class="fa-regular fa-copy"></i>';
                    btn.classList.remove('copied');
                }, 2000);
            }).catch(err => {
                console.error('Failed to copy: ', err);
                showToast('Copy failed.', 'error');
            });
        });
    });

    // Download Handler
    document.getElementById('btn-download-siem').addEventListener('click', () => {
        const data = state.currentAnalysis;
        if (!data) return;
        
        const selVal = document.getElementById('siem-selector').value;
        const rule = data.siem_rules[selVal];
        if (!rule) return;
        
        const ext = getFileExtension(rule.platform);
        downloadFile(rule.content, `${rule.name}_siem_${rule.platform.toLowerCase()}.${ext}`);
    });

    document.getElementById('btn-download-soar').addEventListener('click', () => {
        const data = state.currentAnalysis;
        if (!data) return;
        
        const selVal = document.getElementById('soar-selector').value;
        const playbook = data.soar_playbooks[selVal];
        if (!playbook) return;
        
        const ext = getFileExtension(playbook.platform);
        downloadFile(playbook.content, `${playbook.name}_soar_${playbook.platform.toLowerCase().replace(' ', '_')}.${ext}`);
    });

    function getFileExtension(platform) {
        const plat = platform.toLowerCase();
        if (plat.includes('sigma') || plat.includes('yaml') || plat.includes('workflow') || plat.includes('shuffle')) return 'yaml';
        if (plat.includes('json') || plat.includes('elastic') || plat.includes('eql')) return 'json';
        if (plat.includes('python')) return 'py';
        return 'txt';
    }

    function downloadFile(content, filename) {
        const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        showToast(`Downloaded ${filename}`, 'success');
    }

    // -------------------------------------------------------------
    // 8. DASHBOARD OVERVIEW DATA & CVE FEED FETCH
    // -------------------------------------------------------------
    async function loadDashboardData() {
        try {
            // Fetch configuration to update sidebar lights
            const confResponse = await fetch('/api/config');
            state.config = await confResponse.json();
            updateStatusIndicators();

            // Fetch summary stats
            const statsResponse = await fetch('/api/stats');
            const statsData = await statsResponse.json();
            
            state.stats = statsData;
            document.getElementById('stat-total-analyzed').innerText = statsData.total_analyzed;
            document.getElementById('stat-high-risk').innerText = statsData.high_risk;
            document.getElementById('stat-siem-rules').innerText = statsData.siem_rules;
            document.getElementById('stat-soar-playbooks').innerText = statsData.soar_playbooks;

            // Fetch analyzed threats history
            const historyResponse = await fetch('/api/history');
            const historyData = await historyResponse.json();
            
            state.history = historyData;
            renderHistoryList(historyData);

            // Fetch recent CVE feeds
            loadCveFeed();
        } catch (error) {
            console.error('Error loading dashboard stats:', error);
        }
    }

    function renderHistoryList(historyItems) {
        const container = document.getElementById('analyzed-history-list');
        container.innerHTML = '';
        
        if (!historyItems || historyItems.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <i class="fa-solid fa-folder-open"></i>
                    <p>No threat intelligence analyzed yet.</p>
                    <button class="btn btn-primary btn-sm btn-go-analyze">Analyze First Threat</button>
                </div>
            `;
            container.querySelector('.btn-go-analyze').onclick = () => {
                window.location.hash = '#analyzer';
            };
            return;
        }

        historyItems.forEach(item => {
            const card = document.createElement('div');
            card.className = 'history-item';
            
            const riskBadge = getRiskBadgeHtml(item.risk_score);
            const dateFormatted = new Date(item.timestamp).toLocaleString();

            card.innerHTML = `
                <div class="history-meta">
                    <span class="history-title">${item.threat_name}</span>
                    <span class="feed-desc">${item.summary}</span>
                    <div class="feed-submeta">
                        <span><i class="fa-regular fa-clock"></i> ${dateFormatted}</span>
                        <span><i class="fa-solid fa-tags"></i> IOCs: ${item.ioc_count}</span>
                    </div>
                </div>
                <div>
                    ${riskBadge}
                </div>
            `;
            
            card.style.cursor = 'pointer';
            card.addEventListener('click', async () => {
                // Get detailed run
                try {
                    showToast(`Loading run detail for ${item.threat_name}...`, 'info');
                    const response = await fetch(`/api/history/${item.id}`);
                    const detailedData = await response.json();
                    
                    // Switch to analyzer and render results
                    window.location.hash = '#analyzer';
                    displayAnalysisResults(detailedData);
                } catch (error) {
                    showToast('Failed to load analysis run detail.', 'error');
                }
            });

            container.appendChild(card);
        });
    }

    function getRiskBadgeHtml(score) {
        if (score >= 70) return `<span class="badge badge-danger">${score} Critical</span>`;
        if (score >= 40) return `<span class="badge badge-warning">${score} Medium</span>`;
        return `<span class="badge badge-success">${score} Low</span>`;
    }

    async function loadCveFeed() {
        const listEl = document.getElementById('recent-cve-list');
        listEl.innerHTML = `
            <div class="feed-loading">
                <i class="fa-solid fa-circle-notch fa-spin"></i> Loading recent feeds...
            </div>
        `;
        
        try {
            const response = await fetch('/api/cve-feed');
            const data = await response.json();
            
            listEl.innerHTML = '';
            if (data.length === 0) {
                listEl.innerHTML = '<div class="feed-loading">No recent vulnerabilities found in feed.</div>';
                return;
            }

            data.forEach(cve => {
                const card = document.createElement('div');
                card.className = 'feed-item';
                
                card.innerHTML = `
                    <div class="feed-meta">
                        <span class="feed-title text-cyan">${cve.id}</span>
                        <p class="feed-desc" title="${escapeHtml(cve.description)}">${escapeHtml(cve.description)}</p>
                        <div class="feed-submeta">
                            <span><i class="fa-regular fa-calendar-days"></i> Published: ${cve.published_date || 'N/A'}</span>
                            ${cve.cvss ? `<span><i class="fa-solid fa-shield-virus"></i> CVSS: ${cve.cvss}</span>` : ''}
                        </div>
                    </div>
                    <button class="btn btn-primary btn-sm btn-feed-analyze" data-id="${cve.id}">
                        <i class="fa-solid fa-wand-magic-sparkles"></i> Analyze
                    </button>
                `;
                
                card.querySelector('.btn-feed-analyze').addEventListener('click', (e) => {
                    e.stopPropagation();
                    // Load and run analysis
                    window.location.hash = '#analyzer';
                    document.querySelector('.tab-btn[data-tab="cve-tab"]').click();
                    document.getElementById('cve-input').value = cve.id;
                    runAnalysis('/api/analyze/cve', { cve_id: cve.id });
                });

                listEl.appendChild(card);
            });
        } catch (error) {
            console.error('Failed to load CVE feed:', error);
            listEl.innerHTML = '<div class="feed-loading text-danger"><i class="fa-solid fa-triangle-exclamation"></i> Error loading public feed. Check server configuration.</div>';
        }
    }

    document.getElementById('btn-refresh-feed').addEventListener('click', loadCveFeed);

    // -------------------------------------------------------------
    // 9. CENTRAL REPOSITORY / EXPORTER PAGE
    // -------------------------------------------------------------
    async function loadRepositoryData() {
        const grid = document.getElementById('repo-items-grid');
        grid.innerHTML = `
            <div class="feed-loading" style="grid-column: 1 / -1;">
                <i class="fa-solid fa-circle-notch fa-spin"></i> Loading artifacts...
            </div>
        `;
        
        try {
            const response = await fetch('/api/artifacts');
            const data = await response.json();
            
            state.repoItems = data;
            renderRepositoryGrid(data);
        } catch (error) {
            console.error('Failed to load artifacts:', error);
            grid.innerHTML = '<div class="empty-state"><p>Error loading central repository.</p></div>';
        }
    }

    function renderRepositoryGrid(items) {
        const grid = document.getElementById('repo-items-grid');
        grid.innerHTML = '';
        
        const filterVal = document.getElementById('filter-type').value;
        const searchVal = document.getElementById('repo-search').value.toLowerCase().trim();
        
        const filtered = items.filter(item => {
            // Type filter
            if (filterVal === 'siem' && item.artifact_type !== 'siem') return false;
            if (filterVal === 'soar' && item.artifact_type !== 'soar') return false;
            
            // Search filter
            if (searchVal) {
                const name = item.name.toLowerCase();
                const platform = item.platform.toLowerCase();
                const threat = item.threat_name.toLowerCase();
                const desc = item.explanation.toLowerCase();
                
                return name.includes(searchVal) || 
                       platform.includes(searchVal) || 
                       threat.includes(searchVal) || 
                       desc.includes(searchVal);
            }
            return true;
        });

        if (filtered.length === 0) {
            grid.innerHTML = `
                <div class="empty-state" style="grid-column: 1 / -1;">
                    <i class="fa-solid fa-box-open"></i>
                    <p>No detection artifacts match the filters.</p>
                </div>
            `;
            return;
        }

        filtered.forEach(item => {
            const card = document.createElement('div');
            card.className = 'repo-card';
            
            const isSiem = item.artifact_type === 'siem';
            const iconClass = isSiem ? 'fa-solid fa-shield-halved text-cyan' : 'fa-solid fa-square-play text-purple';
            const typeLabel = isSiem ? 'SIEM Rule' : 'SOAR Playbook';
            
            card.innerHTML = `
                <div class="repo-card-header">
                    <div>
                        <span class="summary-tag" style="color: ${isSiem ? 'var(--cyan)' : 'var(--purple)'}">${typeLabel} (${item.platform})</span>
                        <h4 class="repo-card-title">${item.name}</h4>
                    </div>
                    <i class="${iconClass}" style="font-size: 1.25rem;"></i>
                </div>
                <p class="repo-card-desc">${item.explanation}</p>
                <div class="repo-card-meta">
                    <span>Threat: <strong>${item.threat_name}</strong></span>
                </div>
                <div class="repo-card-footer">
                    <button class="btn btn-secondary btn-sm btn-repo-copy" data-idx="${item.id}">
                        <i class="fa-regular fa-copy"></i> Copy Code
                    </button>
                    <button class="btn btn-primary btn-sm btn-repo-dl" data-idx="${item.id}">
                        <i class="fa-solid fa-download"></i> Download
                    </button>
                </div>
            `;

            // Bind actions
            card.querySelector('.btn-repo-copy').addEventListener('click', () => {
                navigator.clipboard.writeText(item.content).then(() => {
                    showToast(`${item.platform} artifact copied.`, 'success');
                });
            });

            card.querySelector('.btn-repo-dl').addEventListener('click', () => {
                const ext = getFileExtension(item.platform);
                downloadFile(item.content, `${item.name.toLowerCase().replace(/[^a-z0-9]/g, '_')}.${ext}`);
            });

            grid.appendChild(card);
        });
    }

    // Repository page search & filter bindings
    document.getElementById('repo-search').addEventListener('input', () => {
        renderRepositoryGrid(state.repoItems);
    });
    
    document.getElementById('filter-type').addEventListener('change', () => {
        renderRepositoryGrid(state.repoItems);
    });

    // Trigger dashboard data fetching on initial page load
    loadDashboardData();
});
