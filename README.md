FortiAnalyzer Log Viewer
Утилита для анализа логов FortiAnalyzer (v7.6.x) через JSON-RPC API.
Инструмент предназначен для сетевых инженеров и администраторов, которым необходимо:
анализировать сетевой трафик по IP-адресам, VLAN и policyid
работать с inbound / outbound направлениями
ограничивать временные окна анализа
получать агрегированные и человекочитаемые отчёты
безопасно обрабатывать большие объёмы логов
сохранять частичные результаты при прерывании выполнения

🚀 Установка
1. Клонирование проекта
   git clone <ваш-репозиторий>
   cd falogviewer

2. Создание виртуального окружения
   python -m venv .venv

Linux / macOS:
```bash
source .venv/bin/activate\
```

Windows:

```bash
 .venv\Scripts\activate
 ```

3. Установка зависимостей

```bash
pip install -r requirements.txt
```

🔧 Конфигурация

Создайте файл .env на основе .env.example.

Обязательные параметры
```
FORTIANALYZER_URL=https://faz.example.local/jsonrpc
FORTIANALYZER_USERNAME=admin
FORTIANALYZER_PASSWORD=secret

Опциональные параметры
DEFAULT_TIME_RANGE_HOURS=24
BATCH_SIZE=100
RESULTS_DIR=results
MAX_WORKERS=4
MAX_TASK_HOURS=6
MAX_MATCHED_LOGS_PER_TASK=50000
FILTER_MODE=faz
SMART_ACTION=all-accept
```
📌 Основные режимы запуска
Анализ машин из файла за последние 6 часов

```bash
python main.py --input machines.txt --hours 6
```
Анализ по VLAN (имя или ID)
```bash
python main.py --vlan SecVlan --days 1
```
или:

```bash
python main.py --vlan 2014
```
Анализ по CIDR или диапазону IP

```bash
python main.py --input 10.20.0.0/16 --workers 4 --direction outbound
```
Явный временной интервал
```bash
python main.py --workers 1 \
--direction outbound \
--start \"2025-12-01 09:00:00\" \
--end   \"2025-12-05 22:59:59\" \
--exclude internal_ips.txt
```
🆔 PolicyID режим (глобальный)
Анализ всех логов по конкретной firewall-политике без привязки к machines.txt.
```bash
python main.py --policyid 742 \
--start \"2025-12-22 12:00:00\" \
--end   \"2025-12-22 12:30:00\"
```
Особенности:
- поиск идёт глобально по policyid
- target IP необязателен
- агрегация по уникальной связке:
(srcip, dstip, port, proto, policyid)
- поддерживается безопасное прерывание (Ctrl+C)

📁 Формат файлов целей
machines.txt
```
10.20.7.93
10.20.8.88
orion.diasoft.ru
192.168.1.10-192.168.1.20
```

Поддерживаются:
-одиночные IP
-доменные имена (резолвятся в IP)
-диапазоны A-B
-CIDR-сети

vlans.txt
```
192.168.0.0/24   2014   SecVlan
10.20.0.0/16     100    Internal
```
Использование:
```bash
--vlan SecVlan
```
или
```bash
--vlan 2014
```
⚙️ Параметры командной строки
Временные диапазоны
За 12 часов:

```
--hours 12
```
За 2 дня:
```
--days 2
```
Явный интервал:
```bash
--start \"2025-11-10 08:00:00\" --end \"2025-11-10 18:00:00\"
```
Направление трафика
Только входящий:
```
--direction inbound
```
Только исходящий:
```
--direction outbound
```

Оба направления:
```
--direction all
```
Исключение IP
```
--exclude internal_ips.txt
```
Параллельная обработка
```
--workers 4
```
📤 Результаты
После каждого запуска формируются файлы:
- results/inbound_last.txt — последний inbound-анализ
- results/outbound_last.txt — последний outbound-анализ
- results/history.txt — история всех запусков

Пример history.txt
```
=== FortiAnalyzer Export — 2025-11-16 17:57 (UTC+3) ===
Inbound: 3 records
Outbound: 1241 records
=========================================================

--- INBOUND LOGS ---
...

--- OUTBOUND LOGS ---
...
```
```
📂 Структура проекта
falogviewer/
├── main.py                 # Точка входа
├── config.py               # Конфигурация и чтение .env
├── requirements.txt        # Зависимости
├── .env.example            # Шаблон конфигурации
├── machines.txt            # Список целей
├── vlans.txt               # VLAN-описания
├── results/
│   ├── inbound_last.txt
│   ├── outbound_last.txt
│   └── history.txt
├── analyzer/
│   └── log_analyzer.py     # Анализ логов
├── client/
│   └── faz_client.py       # FortiAnalyzer JSON-RPC клиент
└── utils/
├── network.py          # IP / VLAN / диапазоны
└── output.py           # Сохранение результатов
```
🔒 Безопасность
- Файл .env находится в .gitignore
- Никогда не коммитьте пароль FortiAnalyzer
- Если пароль попал в репозиторий — немедленно смените его

🛠 Требования
- Python 3.7+
- FortiAnalyzer v7.6.x
- Доступ к DNS
- Сетевой доступ к FortiAnalyzer JSON-RPC API

⚡ Советы по производительности
Увеличьте размер пачки:
```
BATCH_SIZE=500
```

Используйте несколько воркеров:
```
--workers 2-4
```
Сужайте окно анализа:
```
--hours 1
```
Используйте VLAN вместо длинных списков IP:
```
--vlan CorpNet
```