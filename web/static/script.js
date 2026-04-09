// ========================
// falv2 — Client Script (v4)
// ========================

// ---- Sidebar nav ----
document.querySelectorAll('.sidebar-link').forEach(link => {
    link.addEventListener('click', () => {
        document.querySelectorAll('.sidebar-link').forEach(l => l.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        link.classList.add('active');
        document.getElementById('tab-' + link.dataset.tab).classList.add('active');
        if (link.dataset.tab === 'results') loadResults();
        if (link.dataset.tab === 'settings') loadSettings();
    });
});

// ---- Form toggles ----
document.getElementById('time_mode_select').addEventListener('change', function() {
    const isExact = this.value === 'exact';
    document.getElementById('exact_from').classList.toggle('hidden', !isExact);
    document.getElementById('exact_to').classList.toggle('hidden', !isExact);
    document.getElementById('time_value_row').classList.toggle('hidden', isExact);
});

document.getElementById('analysis_mode_select').addEventListener('change', function() {
    const isPolicy = this.value === 'policyid';
    document.getElementById('policyid_row').classList.toggle('hidden', !isPolicy);
    document.getElementById('direction_row').classList.toggle('hidden', isPolicy);
});

document.getElementById('proto_enabled').addEventListener('change', e => {
    document.getElementById('ports').disabled = !e.target.checked;
});

// ---- Hosts ----
function addTargetRow(ip, mask) {
    ip = ip || '';
    mask = mask || '/32';
    const list = document.getElementById('targets-list');
    const row = document.createElement('div');
    row.className = 'target-row';
    row.innerHTML = '<input type="text" class="form-input target-ip" value="' + ip + '" placeholder="IP">' +
        '<input type="text" class="form-input target-mask" value="' + mask + '" placeholder="/32">' +
        '<button type="button" class="btn-remove" onclick="this.parentElement.remove()">✕</button>';
    list.appendChild(row);
}
document.getElementById('add-target-btn').addEventListener('click', () => addTargetRow());

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

document.getElementById('manual-targets').style.display = 'block';

// ---- Run ----
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

    const timeMode = document.getElementById('time_mode_select').value;
    const analysisMode = document.getElementById('analysis_mode_select').value;
    const direction = document.getElementById('direction_select').value;
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
        time_value: timeMode === 'days' ? +document.getElementById('time_hours').value : +document.getElementById('time_hours').value,
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
        output_format: document.getElementById('output_format_select').value,
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
    finally {
        btn.disabled = false;
        loadMainHistory();
    }
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

        if (perIp && Object.keys(perIp).length > 0) {
            const grid = document.createElement('div');
            grid.className = 'worker-grid';
            Object.keys(perIp).forEach(ip => {
                const ipText = Object.values(perIp[ip]).join('\n\n---\n\n');
                const card = document.createElement('div');
                card.className = 'worker-card';
                card.innerHTML = '<div class="worker-card-header">🖥 ' + escHtml(ip) + '</div><pre class="worker-card-content">' + escHtml(ipText) + '</pre>';
                grid.appendChild(card);
            });
            rc.innerHTML = '';
            rc.appendChild(grid);

            const wbtn = document.createElement('button');
            wbtn.className = 'result-tab-btn active';
            wbtn.textContent = '🖥 Воркеры';
            wbtn.onclick = () => {
                document.querySelectorAll('.result-tab-btn').forEach(b => b.classList.remove('active'));
                wbtn.classList.add('active');
                rc.innerHTML = '';
                rc.appendChild(grid);
            };
            tabsContainer.appendChild(wbtn);
        }

        const dirKeys = Object.keys(texts).filter(k => k !== 'per_ip');
        dirKeys.forEach(dir => {
            const btn = document.createElement('button');
            btn.className = 'result-tab-btn';
            const label = dir.endsWith('.csv') ? dir.replace('.csv', '') : dir.replace('.txt', '');
            btn.textContent = '📄 ' + label.charAt(0).toUpperCase() + label.slice(1);
            btn.onclick = () => {
                document.querySelectorAll('.result-tab-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                rc.textContent = texts[dir];
            };
            tabsContainer.appendChild(btn);
        });

        if (!perIp && dirKeys.length > 0) rc.textContent = texts[dirKeys[0]];
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

document.getElementById('copy-btn').addEventListener('click', () => {
    navigator.clipboard.writeText(document.getElementById('result-content').textContent).then(() => {
        const b = document.getElementById('copy-btn');
        b.textContent = '✅ Скопировано!';
        setTimeout(() => b.textContent = '📋 Копировать', 2000);
    });
});

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

// ---- Results ----
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
            tr.innerHTML = '<td>' + f.name + '</td><td>' + f.modified + '</td><td>' + fmtSize(f.size) + '</td><td><button class="btn-small" onclick="viewResult(\'' + f.path + '\')">📖</button> <button class="btn-small" onclick="dlResult(\'' + f.path + '\')">📥</button></td>';
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

// ---- Main page history ----
async function loadMainHistory() {
    try {
        const data = await (await fetch('/api/history')).json();
        const tbody = document.getElementById('main-history-tbody');
        const empty = document.getElementById('main-history-empty');
        const table = document.getElementById('main-history-table');
        tbody.innerHTML = '';
        if (!data.entries || data.entries.length === 0) {
            table.classList.add('hidden'); empty.classList.remove('hidden'); return;
        }
        table.classList.remove('hidden'); empty.classList.add('hidden');
        const dirMap = { inbound: 'Вх.', outbound: 'Исх.', all: 'Оба' };
        const last = data.entries.slice(0, 10);
        last.forEach(e => {
            let type = 'Dir', dir = '';
            if (e.has_policy) { type = 'Pol'; dir = '#' + (e.policyid || '—'); }
            else if (e.has_inbound && e.has_outbound) { type = 'Both'; dir = 'In+Out'; }
            else if (e.has_inbound) { type = 'In'; dir = 'Вх.'; }
            else if (e.has_outbound) { type = 'Out'; dir = 'Исх.'; }
            if (e.direction) dir = dirMap[e.direction] || e.direction;
            const sum = e.summary_lines && e.summary_lines.length ? e.summary_lines.join(' · ') : '—';
            const tr = document.createElement('tr');
            tr.innerHTML = '<td style="font-size:0.78rem">' + e.timestamp + '</td><td><span class="type-badge">' + type + '</span></td><td>' + dir + '</td><td style="font-size:0.75rem">' + e.time_range + '</td><td>' + sum + '</td>';
            tbody.appendChild(tr);
        });
    } catch (err) { console.error(err); }
}

// ---- Settings ----
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

document.getElementById('save-settings-btn').addEventListener('click', async () => {
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
        s.textContent = '✅ Сохранено (' + r.updated + ')';
        s.style.color = '#22c55e';
        setTimeout(() => s.textContent = '', 3000);
    } catch (err) {
        const s = document.getElementById('settings-status');
        s.textContent = '❌ Ошибка'; s.style.color = '#ef4444';
    }
});

// Load history on startup
loadMainHistory();
