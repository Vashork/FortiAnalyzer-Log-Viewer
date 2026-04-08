// ========================
// НАВИГАЦИЯ ПО ВКЛАДКАМ
// ========================

document.querySelectorAll('.nav-tab').forEach(tab => {
    tab.addEventListener('click', () => {
        document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        tab.classList.add('active');
        document.getElementById('tab-' + tab.dataset.tab).classList.add('active');

        // Загрузка данных при переключении
        if (tab.dataset.tab === 'results') loadResults();
        if (tab.dataset.tab === 'history') loadHistory();
        if (tab.dataset.tab === 'settings') loadSettings();
    });
});

// ========================
// АНАЛИЗ — ЛОГИКА ФОРМЫ
// ========================

// Переключение режима времени
document.querySelectorAll('input[name="time_mode"]').forEach(radio => {
    radio.addEventListener('change', () => {
        const exactDates = document.getElementById('exact-dates');
        if (radio.value === 'exact' && radio.checked) {
            exactDates.classList.remove('hidden');
        } else {
            exactDates.classList.add('hidden');
        }
    });
});

// Переключение режима анализа
document.querySelectorAll('input[name="analysis_mode"]').forEach(radio => {
    radio.addEventListener('change', () => {
        const isPolicy = radio.value === 'policyid' && radio.checked;
        document.getElementById('policyid-section').classList.toggle('hidden', !isPolicy);
        document.getElementById('direction-section').classList.toggle('hidden', isPolicy);
    });
});

// Чекбокс портов
document.getElementById('proto_enabled').addEventListener('change', (e) => {
    document.getElementById('ports').disabled = !e.target.checked;
});

// ========================
// ЦЕЛЕВЫЕ ХОСТЫ
// ========================

let targetCount = 0;

function addTargetRow(ip = '', mask = '/32') {
    targetCount++;
    const list = document.getElementById('targets-list');
    const row = document.createElement('div');
    row.className = 'target-row';
    row.innerHTML = `
        <input type="text" class="target-ip" value="${ip}" placeholder="192.168.1.1 или 10.0.0.0">
        <input type="text" class="target-mask" value="${mask}" placeholder="/32, /24, /16..." style="width:80px">
        <button type="button" class="btn-remove" onclick="this.parentElement.remove()">✕</button>
    `;
    list.appendChild(row);
}

document.getElementById('add-target-btn').addEventListener('click', () => addTargetRow());

// Стартовые хосты (из machines.txt по умолчанию)
addTargetRow();

// Чекбокс "Использовать machines.txt"
document.getElementById('use_machines_file').addEventListener('change', (e) => {
    const manual = document.getElementById('manual-targets');
    if (e.target.checked) {
        manual.style.display = 'none';
        loadMachinesFile();
    } else {
        // Очищаем список, показываем ручной ввод с одной пустой строкой
        document.getElementById('targets-list').innerHTML = '';
        manual.style.display = 'block';
        addTargetRow();
    }
});

// Загрузка machines.txt
async function loadMachinesFile() {
    try {
        const resp = await fetch('/api/resources/machines');
        const data = await resp.json();
        const list = document.getElementById('targets-list');
        list.innerHTML = '';
        if (data.ips && data.ips.length > 0) {
            data.ips.forEach(ip => addTargetRow(ip, '/32'));
        }
    } catch (err) {
        console.error('Failed to load machines.txt:', err);
    }
}

// Загружаем machines.txt при старте
loadMachinesFile();

// ========================
// ЗАПУСК АНАЛИЗА
// ========================

let eventSource = null;
let currentResultTexts = {};
let currentResultFiles = [];

document.getElementById('run-btn').addEventListener('click', runAnalysis);
document.getElementById('stop-btn').addEventListener('click', stopAnalysis);

async function runAnalysis() {
    const btn = document.getElementById('run-btn');
    btn.disabled = true;

    // Показываем прогресс
    document.getElementById('idle-panel').classList.add('hidden');
    document.getElementById('result-panel').classList.add('hidden');
    document.getElementById('progress-panel').classList.remove('hidden');
    const progressLog = document.getElementById('progress-log');
    progressLog.textContent = '';

    // Собираем данные
    const timeMode = document.querySelector('input[name="time_mode"]:checked').value;
    const analysisMode = document.querySelector('input[name="analysis_mode"]:checked').value;
    const direction = document.querySelector('input[name="direction"]:checked').value;

    // Цели
    const useMachinesFile = document.getElementById('use_machines_file').checked;
    const targets = [];
    if (!useMachinesFile) {
        document.querySelectorAll('.target-row').forEach(row => {
            const ip = row.querySelector('.target-ip').value.trim();
            const mask = row.querySelector('.target-mask').value.trim();
            if (ip) targets.push({ ip, mask });
        });
    }

    const payload = {
        time_mode: timeMode,
        time_value: timeMode === 'days'
            ? parseInt(document.getElementById('time_days').value)
            : parseInt(document.getElementById('time_hours').value),
        start_time: document.getElementById('start_time').value || null,
        end_time: document.getElementById('end_time').value || null,
        analysis_mode: analysisMode,
        direction: direction,
        exclude_internal: document.getElementById('exclude_internal').checked,
        use_machines_file: useMachinesFile,
        targets: targets,
        policyid: analysisMode === 'policyid'
            ? parseInt(document.getElementById('policyid').value) || null
            : null,
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
        let buffer = '';

        while (true) {
            const { done, value } = await reader.read();
            if (done) break;

            buffer += decoder.decode(value, { stream: true });
            const lines = buffer.split('\n');
            buffer = lines.pop() || '';

            for (const line of lines) {
                if (!line.startsWith('data: ')) continue;
                try {
                    const event = JSON.parse(line.slice(6));
                    handleProgressEvent(event, progressLog);
                } catch (e) { /* skip */ }
            }
        }
    } catch (err) {
        progressLog.textContent += `\n❌ Ошибка: ${err.message}`;
    } finally {
        btn.disabled = false;
    }
}

function handleProgressEvent(event, progressLog) {
    if (event.type === 'progress') {
        progressLog.textContent += event.message + '\n';
        progressLog.scrollTop = progressLog.scrollHeight;
    } else if (event.type === 'done') {
        document.getElementById('progress-panel').classList.add('hidden');
        document.getElementById('result-panel').classList.remove('hidden');

        currentResultTexts = event.result.texts || {};
        currentResultFiles = event.result.files || [];

        // Если есть тексты — показываем вкладки
        const tabsContainer = document.getElementById('result-tabs');
        tabsContainer.innerHTML = '';

        const resultContent = document.getElementById('result-content');

        if (event.result.texts) {
            const directions = Object.keys(event.result.texts);
            if (directions.length > 1) {
                directions.forEach((dir, i) => {
                    const btn = document.createElement('button');
                    btn.className = 'result-tab-btn' + (i === 0 ? ' active' : '');
                    btn.textContent = dir.charAt(0).toUpperCase() + dir.slice(1);
                    btn.onclick = () => {
                        document.querySelectorAll('.result-tab-btn').forEach(b => b.classList.remove('active'));
                        btn.classList.add('active');
                        resultContent.textContent = event.result.texts[dir];
                    };
                    tabsContainer.appendChild(btn);
                });
                resultContent.textContent = event.result.texts[directions[0]];
            } else if (directions.length === 1) {
                resultContent.textContent = event.result.texts[directions[0]];
            }
        } else if (event.result.text) {
            resultContent.textContent = event.result.text;
        }
    } else if (event.type === 'error') {
        document.getElementById('progress-panel').classList.add('hidden');
        document.getElementById('result-panel').classList.remove('hidden');
        document.getElementById('result-content').textContent = event.message;
    }
}

function stopAnalysis() {
    if (eventSource) {
        eventSource.close();
        eventSource = null;
    }
    document.getElementById('run-btn').disabled = false;
    document.getElementById('progress-panel').classList.add('hidden');
    document.getElementById('idle-panel').classList.remove('hidden');
}

// Копирование и скачивание
document.getElementById('copy-btn').addEventListener('click', () => {
    const text = document.getElementById('result-content').textContent;
    navigator.clipboard.writeText(text).then(() => {
        const btn = document.getElementById('copy-btn');
        btn.textContent = '✅ Скопировано!';
        setTimeout(() => btn.textContent = '📋 Копировать', 2000);
    });
});

document.getElementById('download-btn').addEventListener('click', () => {
    const text = document.getElementById('result-content').textContent;
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'result_' + new Date().toISOString().slice(0, 19).replace(/[:]/g, '-') + '.txt';
    a.click();
    URL.revokeObjectURL(url);
});

// ========================
// РЕЗУЛЬТАТЫ
// ========================

async function loadResults() {
    try {
        const resp = await fetch('/api/results');
        const data = await resp.json();
        const tbody = document.getElementById('results-tbody');
        const empty = document.getElementById('results-empty');
        const table = document.getElementById('results-table');

        tbody.innerHTML = '';

        if (!data.files || data.files.length === 0) {
            table.classList.add('hidden');
            empty.classList.remove('hidden');
            return;
        }

        table.classList.remove('hidden');
        empty.classList.add('hidden');

        data.files.forEach(file => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${file.name}</td>
                <td>${file.modified}</td>
                <td>${formatSize(file.size)}</td>
                <td>
                    <button class="btn-small" onclick="viewResult('${file.path}')">📖 Открыть</button>
                    <button class="btn-small" onclick="downloadResult('${file.path}')">📥 Скачать</button>
                </td>
            `;
            tbody.appendChild(tr);
        });
    } catch (err) {
        console.error('Failed to load results:', err);
    }
}

async function viewResult(path) {
    try {
        const resp = await fetch(`/api/results/${path}`);
        const data = await resp.json();
        // Показываем в модальном окне или переключаемся
        document.getElementById('result-content').textContent = data.content;
        // Переключаемся на вкладку анализа для просмотра
        document.querySelector('[data-tab="analyze"]').click();
        document.getElementById('idle-panel').classList.add('hidden');
        document.getElementById('progress-panel').classList.add('hidden');
        document.getElementById('result-panel').classList.remove('hidden');
    } catch (err) {
        alert('Ошибка загрузки: ' + err.message);
    }
}

function downloadResult(path) {
    window.open(`/api/results/download/${path}`, '_blank');
}

function formatSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

document.getElementById('open-folder-btn').addEventListener('click', () => {
    // Открываем в новой вкладке (браузер покажет JSON или скачает)
    window.open('/api/results', '_blank');
});

// ========================
// ИСТОРИЯ
// ========================

async function loadHistory() {
    try {
        const resp = await fetch('/api/history');
        const data = await resp.json();
        const tbody = document.getElementById('history-tbody');
        const empty = document.getElementById('history-empty');
        const table = document.getElementById('history-table');

        tbody.innerHTML = '';

        if (!data.entries || data.entries.length === 0) {
            table.classList.add('hidden');
            empty.classList.remove('hidden');
            return;
        }

        table.classList.remove('hidden');
        empty.classList.add('hidden');

        data.entries.forEach(entry => {
            let type = 'Direction';
            let direction = '';
            if (entry.has_policy) {
                type = 'PolicyID';
                direction = `Policy #${entry.policyid || '—'}`;
            } else if (entry.has_inbound && entry.has_outbound) {
                type = 'Both';
                direction = 'Inbound + Outbound';
            } else if (entry.has_inbound) {
                type = 'Inbound';
                direction = 'Входящий';
            } else if (entry.has_outbound) {
                type = 'Outbound';
                direction = 'Исходящий';
            }

            if (entry.direction) {
                const dirMap = { inbound: 'Входящий', outbound: 'Исходящий', all: 'Оба' };
                direction = dirMap[entry.direction] || entry.direction;
            }

            const excludeIcon = entry.exclude_used ? '✅ Да' : '—';
            const targetFile = entry.cmd.includes('machines') ? 'machines.txt' : 'Ручной ввод';
            const summary = entry.summary_lines.length > 0 ? entry.summary_lines.join('<br>') : '—';

            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${entry.timestamp}</td>
                <td><span class="type-badge">${type}</span></td>
                <td>${direction}</td>
                <td>${entry.time_range}</td>
                <td>${targetFile}</td>
                <td>${excludeIcon}</td>
                <td>${entry.smart_action}</td>
                <td class="cmd-cell">${entry.file || '—'}</td>
                <td>${summary}</td>
            `;
            tbody.appendChild(tr);
        });
    } catch (err) {
        console.error('Failed to load history:', err);
    }
}

// ========================
// НАСТРОЙКИ
// ========================

async function loadSettings() {
    try {
        const resp = await fetch('/api/settings');
        const data = await resp.json();

        document.getElementById('set_faz_url').value = data.faz_url || '';
        document.getElementById('set_faz_username').value = data.faz_username || '';
        document.getElementById('set_faz_password').value = '';
        document.getElementById('set_batch_size').value = data.batch_size || 100;
        document.getElementById('set_results_dir').value = data.results_dir || 'results';
        document.getElementById('set_max_task_hours').value = data.max_task_hours || 1;
        document.getElementById('set_max_matched_logs').value = data.max_matched_logs || 200000;
        document.getElementById('set_max_workers').value = data.max_workers || 1;
    } catch (err) {
        console.error('Failed to load settings:', err);
    }
}

document.getElementById('settings-form').addEventListener('submit', async (e) => {
    e.preventDefault();

    const payload = {
        faz_url: document.getElementById('set_faz_url').value,
        faz_username: document.getElementById('set_faz_username').value,
        batch_size: parseInt(document.getElementById('set_batch_size').value),
        results_dir: document.getElementById('set_results_dir').value,
        max_task_hours: parseInt(document.getElementById('set_max_task_hours').value),
        max_matched_logs: parseInt(document.getElementById('set_max_matched_logs').value),
        max_workers: parseInt(document.getElementById('set_max_workers').value),
    };

    const pwd = document.getElementById('set_faz_password').value;
    if (pwd) payload.faz_password = pwd;

    try {
        const resp = await fetch('/api/settings', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const result = await resp.json();

        const status = document.getElementById('settings-status');
        status.textContent = `✅ Сохранено (${result.updated} параметров)`;
        status.style.color = 'green';
        setTimeout(() => status.textContent = '', 3000);
    } catch (err) {
        const status = document.getElementById('settings-status');
        status.textContent = '❌ Ошибка сохранения';
        status.style.color = 'red';
    }
});
