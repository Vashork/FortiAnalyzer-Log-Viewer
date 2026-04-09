// ========================
// falv2 — client script (clean)
// ========================

// ---- Navigation ----
document.querySelectorAll('.nav-tab').forEach(tab => {
    tab.addEventListener('click', () => {
        document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        tab.classList.add('active');
        document.getElementById('tab-' + tab.dataset.tab).classList.add('active');
        if (tab.dataset.tab === 'results') loadResults();
        if (tab.dataset.tab === 'history') loadHistory();
        if (tab.dataset.tab === 'settings') loadSettings();
    });
});

// ---- Form toggles ----
document.querySelectorAll('input[name="time_mode"]').forEach(r => {
    r.addEventListener('change', () => {
        document.getElementById('exact-dates').classList.toggle('hidden', r.value !== 'exact');
    });
});
document.querySelectorAll('input[name="analysis_mode"]').forEach(r => {
    r.addEventListener('change', () => {
        document.getElementById('policyid-section').classList.toggle('hidden', r.value !== 'policyid');
        document.getElementById('direction-section').classList.toggle('hidden', r.value === 'policyid');
    });
});
document.getElementById('proto_enabled').addEventListener('change', e => {
    document.getElementById('ports').disabled = !e.target.checked;
});

// ---- Target hosts ----
function addTargetRow(ip, mask) {
    ip = ip || '';
    mask = mask || '/32';
    const list = document.getElementById('targets-list');
    const row = document.createElement('div');
    row.className = 'target-row';
    row.innerHTML = '<input type="text" class="target-ip" value="' + ip + '" placeholder="192.168.1.1">' +
        '<input type="text" class="target-mask" value="' + mask + '" placeholder="/32" style="width:80px">' +
        '<button type="button" class="btn-remove" onclick="this.parentElement.remove()">✕</button>';
    list.appendChild(row);
}
document.getElementById('add-target-btn').addEventListener('click', () => addTargetRow());

// Checkbox: use machines.txt
document.getElementById('use_machines_file').addEventListener('change', e => {
    const manual = document.getElementById('manual-targets');
    if (e.target.checked) {
        manual.style.display = 'none';
        loadMachinesFile();
    } else {
        document.getElementById('targets-list').innerHTML = '';
        manual.style.display = 'block';
    }
});

async function loadMachinesFile() {
    try {
        const resp = await fetch('/api/resources/machines');
        const data = await resp.json();
        const list = document.getElementById('targets-list');
        list.innerHTML = '';
        if (data.ips && data.ips.length > 0) {
            data.ips.forEach(ip => addTargetRow(ip, '/32'));
            document.getElementById('manual-targets').style.display = 'none';
        }
    } catch (err) { console.error(err); }
}

// Default: empty list, manual input visible
document.getElementById('manual-targets').style.display = 'block';

// ---- Run analysis ----
document.getElementById('run-btn').addEventListener('click', runAnalysis);
document.getElementById('stop-btn').addEventListener('click', stopAnalysis);

async function runAnalysis() {
    const btn = document.getElementById('run-btn');
    btn.disabled = true;
    document.getElementById('idle-panel').classList.add('hidden');
    document.getElementById('result-panel').classList.add('hidden');
    document.getElementById('progress-panel').classList.remove('hidden');
    const plog = document.getElementById('progress-log');
    plog.textContent = '';

    const timeMode = document.querySelector('input[name="time_mode"]:checked').value;
    const analysisMode = document.querySelector('input[name="analysis_mode"]:checked').value;
    const direction = document.querySelector('input[name="direction"]:checked').value;
    const useMachines = document.getElementById('use_machines_file').checked;

    const targets = [];
    if (!useMachines) {
        document.querySelectorAll('.target-row').forEach(row => {
            const ip = row.querySelector('.target-ip').value.trim();
            const mask = row.querySelector('.target-mask').value.trim();
            if (ip) targets.push({ ip: ip, mask: mask });
        });
    }

    const payload = {
        time_mode: timeMode,
        time_value: timeMode === 'days' ? +document.getElementById('time_days').value : +document.getElementById('time_hours').value,
        start_time: document.getElementById('start_time').value || null,
        end_time: document.getElementById('end_time').value || null,
        analysis_mode: analysisMode,
        direction: direction,
        exclude_internal: document.getElementById('exclude_internal').checked,
        use_machines_file: useMachines,
        targets: targets,
        policyid: analysisMode === 'policyid' ? (+document.getElementById('policyid').value || null) : null,
        proto_enabled: document.getElementById('proto_enabled').checked,
        ports: document.getElementById('ports').value,
        smart_action: document.getElementById('smart_action').value,
        columns: {
            connections: document.getElementById('col_connections').checked,
            action: document.getElementById('col_action').checked,
            policyid: document.getElementById('col_policyid').checked,
            app: document.getElementById('col_app').checked,
            srcintf: document.getElementById('col_srcintf').checked,
            dstintf: document.getElementById('col_dstintf').checked,
            policyname: document.getElementById('col_policyname').checked,
            devname: document.getElementById('col_devname').checked,
            smart_action: document.getElementById('col_smart_action').checked,
        },
        output_format: document.querySelector('input[name="output_format"]:checked').value,
    };

    try {
        const response = await fetch('/api/analyze/stream', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buf = '';
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            buf += decoder.decode(value, { stream: true });
            const lines = buf.split('\n');
            buf = lines.pop() || '';
            for (const line of lines) {
                if (!line.startsWith('data: ')) continue;
                try { handleEvent(JSON.parse(line.slice(6)), plog); } catch (e) {}
            }
        }
    } catch (err) { plog.textContent += '\n❌ ' + err.message; }
    finally { btn.disabled = false; }
}

function handleEvent(ev, plog) {
    if (ev.type === 'progress') {
        plog.textContent += ev.message + '\n';
        plog.scrollTop = plog.scrollHeight;
    } else if (ev.type === 'done') {
        document.getElementById('progress-panel').classList.add('hidden');
        document.getElementById('result-panel').classList.remove('hidden');

        const texts = ev.result.texts || {};
        const perIp = texts.per_ip || null;
        const tabsContainer = document.getElementById('result-tabs');
        tabsContainer.innerHTML = '';
        const rc = document.getElementById('result-content');

        // Worker grid
        if (perIp && Object.keys(perIp).length > 0) {
            const grid = document.createElement('div');
            grid.className = 'worker-grid';
            grid.id = 'worker-grid';
            Object.keys(perIp).forEach(ip => {
                const ipText = Object.values(perIp[ip]).join('\n\n---\n\n');
                const card = document.createElement('div');
                card.className = 'worker-card';
                card.innerHTML = '<div class="worker-card-header">\uD83D\uDDA5 ' + ip + '</div><pre class="worker-card-content">' + escHtml(ipText) + '</pre>';
                grid.appendChild(card);
            });
            rc.innerHTML = '';
            rc.appendChild(grid);

            // "Workers" tab button
            const wbtn = document.createElement('button');
            wbtn.className = 'result-tab-btn active';
            wbtn.textContent = '\uD83D\uDDA5 Воркеры';
            wbtn.onclick = () => {
                document.querySelectorAll('.result-tab-btn').forEach(b => b.classList.remove('active'));
                wbtn.classList.add('active');
                rc.innerHTML = '';
                rc.appendChild(grid);
            };
            tabsContainer.appendChild(wbtn);
        }

        // Direction/file tabs
        const dirKeys = Object.keys(texts).filter(k => k !== 'per_ip');
        dirKeys.forEach((dir, i) => {
            const btn = document.createElement('button');
            btn.className = 'result-tab-btn';
            const label = dir.endsWith('.csv') ? dir.replace('.csv', '') : dir.replace('.txt', '');
            btn.textContent = '\uD83D\uDCC4 ' + label.charAt(0).toUpperCase() + label.slice(1);
            btn.onclick = () => {
                document.querySelectorAll('.result-tab-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                rc.textContent = texts[dir];
            };
            tabsContainer.appendChild(btn);
        });

        // Default: show first direction tab if no worker grid
        if (!perIp && dirKeys.length > 0) {
            rc.textContent = texts[dirKeys[0]];
        }
    } else if (ev.type === 'error') {
        document.getElementById('progress-panel').classList.add('hidden');
        document.getElementById('result-panel').classList.remove('hidden');
        document.getElementById('result-content').textContent = ev.message;
    }
}

function escHtml(s) {
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
}

function stopAnalysis() {
    document.getElementById('run-btn').disabled = false;
    document.getElementById('progress-panel').classList.add('hidden');
    document.getElementById('idle-panel').classList.remove('hidden');
}

// Copy
document.getElementById('copy-btn').addEventListener('click', () => {
    const txt = document.getElementById('result-content').textContent;
    navigator.clipboard.writeText(txt).then(() => {
        const b = document.getElementById('copy-btn');
        b.textContent = '\u2705 Скопировано!';
        setTimeout(() => b.textContent = '\uD83D\uDCCB Копировать', 2000);
    });
});

// Download
document.getElementById('download-btn').addEventListener('click', () => {
    const rc = document.getElementById('result-content');
    const hasGrid = rc.querySelector('.worker-grid');
    if (hasGrid) {
        const cards = rc.querySelectorAll('.worker-card-content');
        const all = Array.from(cards).map(c => c.textContent);
        dl(all.join('\n\n=== SEPARATOR ===\n\n'), 'result', 'txt');
        return;
    }
    const activeTab = document.querySelector('.result-tab-btn.active');
    let ext = 'txt';
    if (activeTab && activeTab.textContent.toLowerCase().includes('csv')) ext = 'csv';
    dl(rc.textContent, 'result', ext);
});

function dl(text, name, ext) {
    const blob = new Blob([text], { type: ext === 'csv' ? 'text/csv' : 'text/plain' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = name + '_' + new Date().toISOString().slice(0, 19).replace(/[:]/g, '-') + '.' + ext;
    a.click();
    URL.revokeObjectURL(a.href);
}

// ---- Results page ----
async function loadResults() {
    try {
        const resp = await fetch('/api/results');
        const data = await resp.json();
        const tbody = document.getElementById('results-tbody');
        const empty = document.getElementById('results-empty');
        const table = document.getElementById('results-table');
        tbody.innerHTML = '';
        if (!data.files || data.files.length === 0) {
            table.classList.add('hidden'); empty.classList.remove('hidden'); return;
        }
        table.classList.remove('hidden'); empty.classList.add('hidden');
        data.files.forEach(f => {
            const tr = document.createElement('tr');
            tr.innerHTML = '<td>' + f.name + '</td><td>' + f.modified + '</td><td>' + fmtSize(f.size) + '</td><td><button class="btn-small" onclick="viewResult(\'' + f.path + '\')">\uD83D\uDCD6 Открыть</button> <button class="btn-small" onclick="dlResult(\'' + f.path + '\')">\uD83D\uDCE5 Скачать</button></td>';
            tbody.appendChild(tr);
        });
    } catch (err) { console.error(err); }
}
async function viewResult(p) {
    try {
        const d = await (await fetch('/api/results/' + p)).json();
        document.getElementById('result-content').textContent = d.content;
        document.querySelector('[data-tab="analyze"]').click();
        document.getElementById('idle-panel').classList.add('hidden');
        document.getElementById('progress-panel').classList.add('hidden');
        document.getElementById('result-panel').classList.remove('hidden');
    } catch (err) { alert(err.message); }
}
function dlResult(p) { window.open('/api/results/download/' + p, '_blank'); }
function fmtSize(b) { return b < 1024 ? b + ' B' : b < 1048576 ? (b / 1024).toFixed(1) + ' KB' : (b / 1048576).toFixed(1) + ' MB'; }
document.getElementById('open-folder-btn').addEventListener('click', () => window.open('/api/results', '_blank'));

// ---- History page ----
async function loadHistory() {
    try {
        const data = await (await fetch('/api/history')).json();
        const tbody = document.getElementById('history-tbody');
        const empty = document.getElementById('history-empty');
        const table = document.getElementById('history-table');
        tbody.innerHTML = '';
        if (!data.entries || data.entries.length === 0) {
            table.classList.add('hidden'); empty.classList.remove('hidden'); return;
        }
        table.classList.remove('hidden'); empty.classList.add('hidden');
        const dirMap = { inbound: '\u0412\u0445\u043E\u0434\u044F\u0449\u0438\u0439', outbound: '\u0418\u0441\u0445\u043E\u0434\u044F\u0449\u0438\u0439', all: '\u041E\u0431\u0430' };
        data.entries.forEach(e => {
            let type = 'Direction', dir = '';
            if (e.has_policy) { type = 'PolicyID'; dir = 'Policy #' + (e.policyid || '\u2014'); }
            else if (e.has_inbound && e.has_outbound) { type = 'Both'; dir = 'Inbound + Outbound'; }
            else if (e.has_inbound) { type = 'Inbound'; dir = '\u0412\u0445\u043E\u0434\u044F\u0449\u0438\u0439'; }
            else if (e.has_outbound) { type = 'Outbound'; dir = '\u0418\u0441\u0445\u043E\u0434\u044F\u0449\u0438\u0439'; }
            if (e.direction) dir = dirMap[e.direction] || e.direction;
            const excl = e.exclude_used ? '\u2705 \u0414\u0430' : '\u2014';
            const tf = e.cmd && e.cmd.includes('machines') ? 'machines.txt' : '\u0420\u0443\u0447\u043D\u043E\u0439 \u0432\u0432\u043E\u0434';
            const sum = e.summary_lines && e.summary_lines.length ? e.summary_lines.join('<br>') : '\u2014';
            const tr = document.createElement('tr');
            tr.innerHTML = '<td>' + e.timestamp + '</td><td><span class="type-badge">' + type + '</span></td><td>' + dir + '</td><td>' + e.time_range + '</td><td>' + tf + '</td><td>' + excl + '</td><td>' + e.smart_action + '</td><td class="cmd-cell">' + (e.file || '\u2014') + '</td><td>' + sum + '</td>';
            tbody.appendChild(tr);
        });
    } catch (err) { console.error(err); }
}

// ---- Settings page ----
async function loadSettings() {
    try {
        const d = await (await fetch('/api/settings')).json();
        document.getElementById('set_faz_url').value = d.faz_url || '';
        document.getElementById('set_faz_username').value = d.faz_username || '';
        document.getElementById('set_faz_password').value = '';
        document.getElementById('set_batch_size').value = d.batch_size || 100;
        document.getElementById('set_results_dir').value = d.results_dir || 'results';
        document.getElementById('set_max_task_hours').value = d.max_task_hours || 1;
        document.getElementById('set_max_matched_logs').value = d.max_matched_logs || 200000;
        document.getElementById('set_max_workers').value = d.max_workers || 1;
    } catch (err) { console.error(err); }
}
document.getElementById('settings-form').addEventListener('submit', async e => {
    e.preventDefault();
    const p = {
        faz_url: document.getElementById('set_faz_url').value,
        faz_username: document.getElementById('set_faz_username').value,
        batch_size: +document.getElementById('set_batch_size').value,
        results_dir: document.getElementById('set_results_dir').value,
        max_task_hours: +document.getElementById('set_max_task_hours').value,
        max_matched_logs: +document.getElementById('set_max_matched_logs').value,
        max_workers: +document.getElementById('set_max_workers').value,
    };
    const pwd = document.getElementById('set_faz_password').value;
    if (pwd) p.faz_password = pwd;
    try {
        const r = await (await fetch('/api/settings', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(p) })).json();
        const s = document.getElementById('settings-status');
        s.textContent = '\u2705 \u0421\u043E\u0445\u0440\u0430\u043D\u0435\u043D\u043E (' + r.updated + ')';
        s.style.color = 'green';
        setTimeout(() => s.textContent = '', 3000);
    } catch (err) {
        const s = document.getElementById('settings-status');
        s.textContent = '\u274C \u041E\u0448\u0438\u0431\u043A\u0430'; s.style.color = 'red';
    }
});
