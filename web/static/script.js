// ========================
// falv2 — Client Script (v8)
// ========================

// ---- Глобальное состояние терминалов ----
let _terminalPool = [];
let _activeTerminals = {}; // "ip:direction" -> slot
let _currentRequestId = null; // для отмены анализа
let _pendingBroadcastMessages = [];
let _savedUseMachinesFile = true;
let _wasPolicyMode = false;

const AGGREGATION_FIELDS = ['remote_ip', 'srcip', 'dstip', 'port', 'proto', 'policyid'];
const AGGREGATION_DEFAULTS = {
    direction: { remote_ip: true, srcip: false, dstip: false, port: true, proto: true, policyid: false },
    policyid: { remote_ip: false, srcip: true, dstip: true, port: true, proto: true, policyid: true },
};
const AGGREGATION_VISIBLE_FIELDS = {
    direction: ['remote_ip', 'port', 'proto'],
    policyid: ['srcip', 'dstip', 'port', 'proto', 'policyid'],
};

function normalizeDateTimeLocal(value) {
    if (!value) return null;
    const normalized = value.trim().replace('T', ' ');
    return normalized.length === 16 ? normalized + ':00' : normalized;
}

function parsePolicyIds(value) {
    return (value || '')
        .split(',')
        .map(v => v.trim())
        .filter(Boolean)
        .map(v => parseInt(v, 10))
        .filter(v => Number.isInteger(v) && v > 0);
}

function toDateTimeLocalValue(value) {
    if (!value) return '';
    return value.replace(' ', 'T').slice(0, 19);
}

function syncTargetVisibility() {
    const isPolicy = document.getElementById('analysis_mode_select').value === 'policyid';
    const useMachinesCheckbox = document.getElementById('use_machines_file');
    const manual = document.getElementById('manual-targets');
    const addBtn = document.getElementById('add-target-btn');
    const targetsList = document.getElementById('targets-list');
    const toggleRow = useMachinesCheckbox.closest('.form-row');
    const toggleLabel = toggleRow ? toggleRow.querySelector('.toggle-switch') : null;

    if (isPolicy) {
        if (!_wasPolicyMode) {
            _savedUseMachinesFile = useMachinesCheckbox.checked;
        }
        _wasPolicyMode = true;
        useMachinesCheckbox.checked = false;
        useMachinesCheckbox.disabled = true;
        if (toggleRow) toggleRow.style.opacity = '0.55';
        if (toggleLabel) toggleLabel.style.pointerEvents = 'none';
        targetsList.innerHTML = '';
        manual.style.display = 'none';
        addBtn.style.display = 'none';
        return;
    }

    if (_wasPolicyMode) {
        useMachinesCheckbox.checked = _savedUseMachinesFile;
    }
    _wasPolicyMode = false;
    useMachinesCheckbox.disabled = false;
    if (toggleRow) toggleRow.style.opacity = '';
    if (toggleLabel) toggleLabel.style.pointerEvents = '';
    addBtn.style.display = '';
    manual.style.display = useMachinesCheckbox.checked ? 'none' : 'block';
}

function getAggregationMode() {
    return document.getElementById('analysis_mode_select').value === 'policyid' ? 'policyid' : 'direction';
}

function setAggregationDefaults(mode) {
    const defaults = AGGREGATION_DEFAULTS[mode] || AGGREGATION_DEFAULTS.direction;
    AGGREGATION_FIELDS.forEach(field => {
        const input = document.getElementById('agg_' + field);
        if (input) input.checked = !!defaults[field];
    });
}

function syncAggregationControls(resetDefaults) {
    const mode = getAggregationMode();
    const visible = new Set(AGGREGATION_VISIBLE_FIELDS[mode] || []);
    if (resetDefaults) setAggregationDefaults(mode);

    AGGREGATION_FIELDS.forEach(field => {
        const input = document.getElementById('agg_' + field);
        if (!input) return;
        const label = input.closest('.checkbox-label');
        if (label) label.classList.toggle('hidden', !visible.has(field));
    });

    const remoteLabel = document.getElementById('agg_remote_ip_label');
    if (remoteLabel) {
        const direction = document.getElementById('direction_select').value;
        if (direction === 'inbound') {
            remoteLabel.textContent = 'Remote IP (Srcip)';
        } else if (direction === 'outbound') {
            remoteLabel.textContent = 'Remote IP (Dstip)';
        } else {
            remoteLabel.textContent = 'Remote IP (Srcip/Dstip)';
        }
    }
}

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
    syncTargetVisibility();
    syncAggregationControls(true);
});

document.getElementById('direction_select').addEventListener('change', () => {
    syncAggregationControls(false);
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
    if (e.target.checked) {
        loadMachinesFile();
    } else {
        document.getElementById('targets-list').innerHTML = '';
    }
    syncTargetVisibility();
});

async function loadMachinesFile() {
    try {
        const resp = await fetch('/api/resources/machines');
        const data = await resp.json();
        const list = document.getElementById('targets-list');
        list.innerHTML = '';
        if (data.ips && data.ips.length > 0) {
            data.ips.forEach(ip => addTargetRow(ip, '/32'));
        }
        syncTargetVisibility();
    } catch (err) { console.error(err); }
}

syncTargetVisibility();
syncAggregationControls(true);

// ---- Run ----
document.getElementById('run-btn').addEventListener('click', runAnalysis);
document.getElementById('stop-btn').addEventListener('click', stopAnalysis);

async function runAnalysis() {
    const btn = document.getElementById('run-btn');
    btn.disabled = true;
    document.getElementById('idle-panel').classList.add('hidden');
    document.getElementById('result-panel').classList.add('hidden');
    document.getElementById('progress-panel').classList.remove('hidden');

    // Очистка контейнера терминалов
    const container = document.getElementById('worker-terminals');
    container.innerHTML = '';
    container.className = 'worker-terminals-grid';

    // Собираем список IP для initial grid sizing
    const timeMode = document.getElementById('time_mode_select').value;
    const analysisMode = document.getElementById('analysis_mode_select').value;
    const useMachines = document.getElementById('use_machines_file').checked;
    const direction = document.getElementById('direction_select').value;
    const workers = getWorkerCount();

    let targetIps = [];
    if (!useMachines) {
        document.querySelectorAll('.target-row').forEach(row => {
            const ip = row.querySelector('.target-ip').value.trim();
            const mask = row.querySelector('.target-mask').value.trim() || '/32';
            if (ip) targetIps.push({ ip: ip, mask: mask });
        });
    } else {
        try {
            const resp = await fetch('/api/resources/machines');
            const data = await resp.json();
            targetIps = data.ips || [];
        } catch (e) {}
        if (document.getElementById('exclude_internal').checked) {
            try {
                const intResp = await fetch('/api/resources/internal');
                if (intResp.ok) {
                    const intData = await intResp.json();
                    const excludeSet = new Set(intData.ips || []);
                    targetIps = targetIps.filter(ip => !excludeSet.has(ip));
                }
            } catch (e) {}
        }
    }

    const directions = analysisMode === 'policyid' ? ['policy'] :
                       direction === 'all' ? ['inbound', 'outbound'] : [direction];
    const parsedPolicyIds = parsePolicyIds(document.getElementById('policyid').value);

    // Определяем layout сетки: слоты = воркеры (максимум 4)
    const activeSlots = Math.min(workers, 4);
    setupTerminalGrid(container, activeSlots);

    // Создаём пул терминалов (максимум workers штук)
    _terminalPool = [];
    _activeTerminals = {};
    _pendingBroadcastMessages = [];

    for (let i = 0; i < activeSlots; i++) {
        _terminalPool.push({ el: null, ip: null, direction: null, terminal: null, free: true, status: null });
    }

    const payload = {
        time_mode: timeMode,
        time_value: +document.getElementById('time_hours').value,
        start_time: normalizeDateTimeLocal(document.getElementById('start_time').value),
        end_time: normalizeDateTimeLocal(document.getElementById('end_time').value),
        analysis_mode: analysisMode,
        direction: direction,
        exclude_internal: document.getElementById('exclude_internal').checked,
        use_machines_file: useMachines,
        targets: useMachines ? [] : targetIps,
        policyid: analysisMode === 'policyid' && parsedPolicyIds.length ? parsedPolicyIds[0] : null,
        policyids: analysisMode === 'policyid' ? parsedPolicyIds : null,
        proto_enabled: document.getElementById('proto_enabled').checked,
        ports: document.getElementById('ports').value,
        smart_action: document.getElementById('smart_action').value,
        columns: {
            connections: document.getElementById('col_connections').checked,
            action: document.getElementById('col_action').checked,
            policyid: document.getElementById('col_policyid').checked,
            app: document.getElementById('col_app').checked,
            srcport: document.getElementById('col_srcport').checked,
            srcintf: document.getElementById('col_srcintf').checked,
            dstintf: document.getElementById('col_dstintf').checked,
            policyname: document.getElementById('col_policyname').checked,
            devname: document.getElementById('col_devname').checked,
            smart_action: document.getElementById('col_smart_action').checked,
        },
        aggregation: {
            remote_ip: document.getElementById('agg_remote_ip').checked,
            srcip: document.getElementById('agg_srcip').checked,
            dstip: document.getElementById('agg_dstip').checked,
            port: document.getElementById('agg_port').checked,
            proto: document.getElementById('agg_proto').checked,
            policyid: document.getElementById('agg_policyid').checked,
        },
        workers: workers,
        output_format: document.getElementById('output_format_select').value,
    };

    try {
        const response = await fetch('/api/analyze/stream', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        if (!response.ok) {
            let errText = 'Request failed';
            try {
                const errJson = await response.json();
                if (errJson.detail) {
                    errText = typeof errJson.detail === 'string'
                        ? errJson.detail
                        : JSON.stringify(errJson.detail, null, 2);
                } else {
                    errText = JSON.stringify(errJson, null, 2);
                }
            } catch (e) {
                errText = await response.text();
            }
            throw new Error(errText || ('HTTP ' + response.status));
        }
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
                try { handleEvent(JSON.parse(line.slice(6))); } catch (e) { console.warn('SSE parse error', e); }
            }
        }
    } catch (err) {
        Object.values(_activeTerminals).forEach(s => {
            if (s.terminal) s.terminal.log.textContent += '\n❌ ' + err.message;
        });
        if (Object.keys(_activeTerminals).length === 0) {
            container.innerHTML = '<div class="worker-terminal"><pre class="worker-terminal-log">❌ ' + escHtml(err.message) + '</pre></div>';
        }
    }
    finally {
        btn.disabled = false;
        _currentRequestId = null;
        loadMainHistory();
    }
}

function getWorkerCount() {
    return parseInt(document.getElementById('set_max_workers')?.value || '2', 10) || 2;
}

// ---- Глобальные функции управления терминалами ----
function acquireTerminal(ip, direction) {
    // 1) Ищем свободный слот
    let slot = _terminalPool.find(s => s.free);
    if (slot) {
        return activateSlot(slot, ip, direction);
    }

    // 2) Ищем completed (worker_done) слот — переиспользуем самый старый
    const completedSlot = _terminalPool.find(s => s.status === 'done');
    if (completedSlot) {
        // Удаляем старый терминал и создаём новый
        releaseTerminal(completedSlot);
        return activateSlot(completedSlot, ip, direction);
    }

    // 3) Все заняты и работают — берём первый (крайняя мера)
    const anySlot = _terminalPool[0];
    if (anySlot) {
        releaseTerminal(anySlot);
        return activateSlot(anySlot, ip, direction);
    }

    return null;
}

function activateSlot(slot, ip, direction) {
    const label = arguments[3] || `${ip} [${direction}]`;
    const slotKey = arguments[4] || ip;
    slot.free = false;
    slot.ip = ip;
    slot.direction = direction;
    slot.slotKey = slotKey;
    slot.status = 'running';
    const key = slotKey;
    const term = createTerminal(document.getElementById('worker-terminals'), '🖥', label);
    slot.el = term.el;
    slot.terminal = term;
    _activeTerminals[key] = slot;
    if (_pendingBroadcastMessages.length > 0) {
        _pendingBroadcastMessages.forEach(message => appendToTerminal(slot, message));
    }
    return slot;
}

function releaseTerminal(slot) {
    if (slot && slot.el) {
        slot.el.remove();
        slot.el = null;
        slot.terminal = null;
    }
    slot.free = true;
    slot.ip = null;
    slot.direction = null;
    slot.slotKey = null;
    slot.status = null;
    Object.keys(_activeTerminals).forEach(k => {
        if (_activeTerminals[k] === slot) delete _activeTerminals[k];
    });
}

function resetTerminals() {
    _terminalPool.forEach(s => {
        if (s.el) s.el.remove();
        s.el = null;
        s.terminal = null;
        s.free = true;
        s.ip = null;
        s.direction = null;
        s.slotKey = null;
        s.status = null;
    });
    _activeTerminals = {};
    document.getElementById('worker-terminals').innerHTML = '';
    _pendingBroadcastMessages = [];
}

function appendToTerminal(slot, message, status) {
    if (!slot || !slot.terminal) return;
    slot.terminal.log.textContent += message + '\n';
    slot.terminal.log.scrollTop = slot.terminal.log.scrollHeight;
    if (status) slot.terminal.setStatus(status);
}

function getEventSlotKey(ev) {
    return ev.slot_key || ev.ip || ev.worker_id || ev.label || null;
}

function findSlotForEvent(ev) {
    const slotKey = getEventSlotKey(ev);
    if (slotKey && _activeTerminals[slotKey]) {
        return _activeTerminals[slotKey];
    }
    if (slotKey) {
        return Object.values(_activeTerminals).find(s => s.slotKey === slotKey || s.ip === slotKey);
    }
    return null;
}

// ---- Создание терминала воркера ----
function createTerminal(container, icon, label) {
    const el = document.createElement('div');
    el.className = 'worker-terminal';
    el.innerHTML = '<div class="worker-terminal-header"><span class="status-dot"></span>' +
        '<span class="terminal-label">' + icon + ' ' + escHtml(label) + '</span></div>' +
        '<pre class="worker-terminal-log"></pre>';
    container.appendChild(el);
    return {
        el: el,
        log: el.querySelector('.worker-terminal-log'),
        dot: el.querySelector('.status-dot'),
        label: el.querySelector('.terminal-label'),
        setStatus: function(status) {
            this.dot.className = 'status-dot' + (status ? ' ' + status : '');
        }
    };
}

// ---- Динамическая сетка терминалов ----
function setupTerminalGrid(container, workerCount) {
    const availWidth = document.querySelector('.analyze-right').clientWidth - 36;
    const availHeight = window.innerHeight - 220; // минус header + карточки

    let cols, rows;
    if (workerCount <= 1) {
        cols = 1; rows = 1;
    } else if (workerCount === 2) {
        cols = 2; rows = 1;
    } else if (workerCount <= 4) {
        cols = 2; rows = 2;
    } else if (workerCount <= 6) {
        cols = 3; rows = 2;
    } else {
        cols = Math.min(4, Math.max(2, Math.ceil(Math.sqrt(workerCount * (availWidth / (availHeight * 0.5))))));
        rows = Math.ceil(workerCount / cols);
    }

    // Ограничиваем высоту чтобы терминалы не вылезали за экран
    const termHeight = Math.max(100, Math.floor((availHeight - (rows - 1) * 10) / rows));

    container.style.gridTemplateColumns = `repeat(${cols}, 1fr)`;
    container.style.gridTemplateRows = `repeat(${rows}, minmax(${termHeight}px, 1fr))`;
}

// ---- Обработка SSE событий с маршрутизацией по IP ----
function handleEvent(ev) {
    if (ev.type === 'request_id') {
        _currentRequestId = ev.request_id;
        return;
    }
    if (ev.type === 'job_started') {
        const slots = Object.values(_activeTerminals);
        if (slots.length === 0) {
            _pendingBroadcastMessages.push(ev.message);
        } else {
            slots.forEach(s => appendToTerminal(s, ev.message));
        }
    } else if (ev.type === 'worker_started' || ev.type === 'worker_start') {
        const slotKey = getEventSlotKey(ev) || ev.ip;
        const direction = ev.direction || 'worker';
        const label = ev.label || `${ev.ip} [${direction}]`;
        const slot = acquireTerminal(slotKey, direction, label, slotKey);
        if (slot && slot.terminal) {
            slot.terminal.setStatus('running');
            if (ev.message) appendToTerminal(slot, ev.message, 'running');
        }
    } else if (ev.type === 'worker_finished' || ev.type === 'worker_done') {
        const slot = findSlotForEvent(ev) || _activeTerminals[(ev.ip || '') + ':' + (ev.direction || '')];
        if (slot && slot.terminal) {
            slot.status = 'done';
            if (ev.message) appendToTerminal(slot, ev.message);
            slot.terminal.setStatus('done');
        }
    } else if (ev.type === 'message' || ev.type === 'progress' || ev.type === 'segment_started' ||
               ev.type === 'fetch_progress' || ev.type === 'aggregation_started' ||
               ev.type === 'report_started' || ev.type === 'logout_started' || ev.type === 'logout_finished') {
        const slot = findSlotForEvent(ev);
        if (slot) {
            appendToTerminal(slot, ev.message, 'running');
        } else if (ev.ip || ev.slot_key || ev.worker_id || ev.label) {
            _pendingBroadcastMessages.push(ev.message);
        } else {
            const slots = Object.values(_activeTerminals);
            if (slots.length === 0) {
                _pendingBroadcastMessages.push(ev.message);
            } else {
                slots.forEach(s => appendToTerminal(s, ev.message));
            }
        }
    } else if (ev.type === 'direction') {
        const slot = findSlotForEvent(ev);
        if (slot && slot.terminal) {
            slot.terminal.log.textContent += ev.message + '\n';
            slot.terminal.log.scrollTop = slot.terminal.log.scrollHeight;
        }
    } else if (ev.type === 'done') {
        _currentRequestId = null;
        Object.values(_activeTerminals).forEach(s => {
            if (s.terminal) s.terminal.setStatus('done');
        });

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
            let label = dir;
            if (label.endsWith('.csv')) {
                label = label.replace('.csv', '') + ' (CSV)';
            } else if (label.endsWith('.txt')) {
                label = label.replace('.txt', '') + ' (TXT)';
            }
            btn.textContent = '📄 ' + label.charAt(0).toUpperCase() + label.slice(1);
            btn.onclick = () => {
                document.querySelectorAll('.result-tab-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                rc.textContent = texts[dir];
            };
            tabsContainer.appendChild(btn);
        });

        if (!perIp && dirKeys.length > 0) rc.textContent = texts[dirKeys[0]];
    } else if (ev.type === 'cancelled') {
        _currentRequestId = null;
        Object.values(_activeTerminals).forEach(s => {
            if (s.terminal) {
                appendToTerminal(s, '\n⏹ ' + ev.message, 'done');
                s.terminal.setStatus('done');
            }
        });
        if (Object.keys(_activeTerminals).length === 0) {
            const container = document.getElementById('worker-terminals');
            container.innerHTML = '<div class="worker-terminal"><div class="worker-terminal-header"><span class="status-dot"></span><span class="terminal-label">Остановлено</span></div><pre class="worker-terminal-log">' + escHtml(ev.message) + '</pre></div>';
        }
        document.getElementById('progress-panel').classList.add('hidden');
        document.getElementById('idle-panel').classList.remove('hidden');
    } else if (ev.type === 'error') {
        _currentRequestId = null;
        Object.values(_activeTerminals).forEach(s => {
            if (s.terminal) {
                appendToTerminal(s, '\n❌ ' + ev.message, 'error');
            }
        });
        if (Object.keys(_activeTerminals).length === 0) {
            _pendingBroadcastMessages.push('❌ ' + ev.message);
            const container = document.getElementById('worker-terminals');
            container.innerHTML = '<div class="worker-terminal"><div class="worker-terminal-header"><span class="status-dot error"></span><span class="terminal-label">Ошибка</span></div><pre class="worker-terminal-log">' + escHtml(ev.message) + '</pre></div>';
        }
        document.getElementById('progress-panel').classList.add('hidden');
        document.getElementById('result-panel').classList.remove('hidden');
        document.getElementById('result-content').textContent = ev.message;
    } else if (ev.type === 'timeout') {
        const slots = Object.values(_activeTerminals);
        if (slots.length > 0) {
            slots.forEach(s => appendToTerminal(s, '… still running, waiting for next update'));
        }
    }
}

function escHtml(s) {
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
}

function stopAnalysis() {
    // Отправляем запрос на отмену
    if (_currentRequestId) {
        fetch('/api/analyze/cancel/' + _currentRequestId, { method: 'POST' }).catch(() => {});
        _currentRequestId = null;
    }
    document.getElementById('run-btn').disabled = false;
    document.getElementById('progress-panel').classList.add('hidden');
    document.getElementById('idle-panel').classList.remove('hidden');
    resetTerminals();
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
        resetTerminals();
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
            
            // Добавляем класс для кликабельности
            tr.classList.add('history-clickable-row');
            
            if (e.state) {
                // Новый формат — полное состояние
                tr.setAttribute('data-state', JSON.stringify(e.state));
                tr.addEventListener('click', () => restoreFormState(e.state));
            } else {
                // Старый формат — fallback по CMD
                tr.title = 'Нажмите, чтобы восстановить параметры (частично)';
                tr.addEventListener('click', () => {
                    restoreFormStateFromCmd(e.cmd, e.time_range, e.smart_action, e.has_policy, e.has_inbound, e.has_outbound, e.direction, e.policyid);
                });
            }
            
            tbody.appendChild(tr);
        });
    } catch (err) { console.error(err); }
}

// ---- Restore form state from history ----
function restoreFormState(state) {
    if (!state) return;
    
    // Время
    if (state.time_mode) {
        document.getElementById('time_mode_select').value = state.time_mode;
        const isExact = state.time_mode === 'exact';
        document.getElementById('exact_from').classList.toggle('hidden', !isExact);
        document.getElementById('exact_to').classList.toggle('hidden', !isExact);
        document.getElementById('time_value_row').classList.toggle('hidden', isExact);
    }
    if (state.time_value !== undefined) {
        document.getElementById('time_hours').value = state.time_value;
    }
    if (state.start_time) {
        document.getElementById('start_time').value = toDateTimeLocalValue(state.start_time);
    }
    if (state.end_time) {
        document.getElementById('end_time').value = toDateTimeLocalValue(state.end_time);
    }
    
    // Режим анализа
    if (state.analysis_mode) {
        document.getElementById('analysis_mode_select').value = state.analysis_mode;
        const isPolicy = state.analysis_mode === 'policyid';
        document.getElementById('policyid_row').classList.toggle('hidden', !isPolicy);
        document.getElementById('direction_row').classList.toggle('hidden', isPolicy);
    }
    if (state.direction) {
        document.getElementById('direction_select').value = state.direction;
    }
    if (state.policyid !== undefined && state.policyid !== null) {
        document.getElementById('policyid').value = Array.isArray(state.policyids) && state.policyids.length
            ? state.policyids.join(',')
            : state.policyid;
    } else if (Array.isArray(state.policyids) && state.policyids.length) {
        document.getElementById('policyid').value = state.policyids.join(',');
    }
    
    // Формат
    if (state.output_format) {
        document.getElementById('output_format_select').value = state.output_format;
    }
    
    // Smart Action
    if (state.smart_action) {
        document.getElementById('smart_action').value = state.smart_action;
    }
    
    // Хосты
    if (state.use_machines_file !== undefined) {
        const machinesCheckbox = document.getElementById('use_machines_file');
        machinesCheckbox.checked = state.use_machines_file;
        if (state.use_machines_file) {
            loadMachinesFile();
        } else {
            document.getElementById('targets-list').innerHTML = '';
            // Восстанавливаем targets
            if (state.targets && state.targets.length > 0) {
                state.targets.forEach(t => addTargetRow(t.ip, t.mask || '/32'));
            }
        }
    }
    
    // Исключить внутренние IP
    if (state.exclude_internal !== undefined) {
        document.getElementById('exclude_internal').checked = state.exclude_internal;
    }
    
    // Порты
    if (state.proto_enabled !== undefined) {
        document.getElementById('proto_enabled').checked = state.proto_enabled;
        document.getElementById('ports').disabled = !state.proto_enabled;
    }
    if (state.ports) {
        document.getElementById('ports').value = state.ports;
    }
    
    // Колонки
    if (state.columns) {
        const columnMap = {
            connections: 'col_connections',
            action: 'col_action',
            policyid: 'col_policyid',
            app: 'col_app',
            srcport: 'col_srcport',
            srcintf: 'col_srcintf',
            dstintf: 'col_dstintf',
            policyname: 'col_policyname',
            devname: 'col_devname',
            smart_action: 'col_smart_action',
        };
        Object.entries(state.columns).forEach(([key, value]) => {
            const checkboxId = columnMap[key];
            if (checkboxId) {
                document.getElementById(checkboxId).checked = value;
            }
        });
    }

    if (state.aggregation) {
        const aggregationMap = {
            remote_ip: 'agg_remote_ip',
            srcip: 'agg_srcip',
            dstip: 'agg_dstip',
            port: 'agg_port',
            proto: 'agg_proto',
            policyid: 'agg_policyid',
        };
        Object.entries(state.aggregation).forEach(([key, value]) => {
            const checkboxId = aggregationMap[key];
            if (checkboxId) {
                document.getElementById(checkboxId).checked = value;
            }
        });
    } else {
        setAggregationDefaults(getAggregationMode());
    }
    
    // Визуальная обратная связь — подсветим строку на мгновение
    const tbody = document.getElementById('main-history-tbody');
    const rows = tbody.querySelectorAll('tr');
    rows.forEach(row => {
        if (row.getAttribute('data-state') === JSON.stringify(state)) {
            row.style.background = 'rgba(59, 130, 246, 0.2)';
            setTimeout(() => {
                row.style.background = '';
            }, 800);
        }
    });

    syncTargetVisibility();
    syncAggregationControls(false);
}

// ---- Restore partial form state from CMD line (fallback for old history entries) ----
function restoreFormStateFromCmd(cmd, timeRange, smartAction, hasPolicy, hasInbound, hasOutbound, direction, policyid) {
    // Время — пытаемся извлечь из timeRange
    if (timeRange) {
        // Формат: "2026-04-09 09:58:13 → 2026-04-09 15:58:13"
        const parts = timeRange.split('→').map(s => s.trim());
        if (parts.length === 2) {
            document.getElementById('time_mode_select').value = 'exact';
            document.getElementById('exact_from').classList.remove('hidden');
            document.getElementById('exact_to').classList.remove('hidden');
            document.getElementById('time_value_row').classList.add('hidden');
            // Преобразуем "2026-04-09 09:58:13" → "2026-04-09T09:58:13"
            document.getElementById('start_time').value = parts[0].replace(' ', 'T');
            document.getElementById('end_time').value = parts[1].replace(' ', 'T');
        }
    }
    
    // Режим и направление
    if (hasPolicy && policyid) {
        document.getElementById('analysis_mode_select').value = 'policyid';
        document.getElementById('policyid_row').classList.remove('hidden');
        document.getElementById('direction_row').classList.add('hidden');
        document.getElementById('policyid').value = policyid;
    } else if (direction) {
        document.getElementById('analysis_mode_select').value = 'direction';
        document.getElementById('policyid_row').classList.add('hidden');
        document.getElementById('direction_row').classList.remove('hidden');
        document.getElementById('direction_select').value = direction;
    } else if (hasInbound && hasOutbound) {
        document.getElementById('analysis_mode_select').value = 'direction';
        document.getElementById('direction_select').value = 'all';
    } else if (hasInbound) {
        document.getElementById('analysis_mode_select').value = 'direction';
        document.getElementById('direction_select').value = 'inbound';
    } else if (hasOutbound) {
        document.getElementById('analysis_mode_select').value = 'direction';
        document.getElementById('direction_select').value = 'outbound';
    }
    
    // Smart Action
    if (smartAction) {
        document.getElementById('smart_action').value = smartAction;
    }
    
    // Парсим direction из CMD если есть
    if (cmd && cmd.includes('direction=')) {
        const dirMatch = cmd.match(/direction=(inbound|outbound|all)/);
        if (dirMatch) {
            document.getElementById('analysis_mode_select').value = 'direction';
            document.getElementById('direction_select').value = dirMatch[1];
        }
    }
    if (cmd && cmd.includes('policyid=')) {
        const polMatch = cmd.match(/policyid=(\d+)/);
        if (polMatch) {
            document.getElementById('analysis_mode_select').value = 'policyid';
            document.getElementById('policyid').value = polMatch[1];
        }
    }

    syncTargetVisibility();
    syncAggregationControls(true);
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
        document.getElementById('set_split_mode').value = d.session_split_mode || 'ip';
        document.getElementById('set_disable_reverse_dns').checked = !!d.disable_reverse_dns;
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
        session_split_mode: document.getElementById('set_split_mode').value,
        disable_reverse_dns: document.getElementById('set_disable_reverse_dns').checked,
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
