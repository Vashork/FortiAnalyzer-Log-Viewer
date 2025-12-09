# FortiAnalyzer Log Viewer

Утилита для анализа логов FortiAnalyzer v7.6.3 через JSON-RPC API.  
Позволяет собирать трафик по IP-адресам, VLAN-ам, диапазонам, CIDR-сетям, с поддержкой фильтрации направлений и временных окон.  
Результаты автоматически сохраняются в структурированные файлы, включая историю запусков.

---

## 🚀 Установка

### 1. Клонирование проекта
```bash
git clone <ваш-репозиторий>
cd falogviewer
```

### 2. Создание виртуального окружения
```bash
python -m venv .venv
```
Linux/macOS:
```bash
source .venv/bin/activate
```
Windows:
```bash
.venv\Scripts\activate
```
### 3. Установка зависимостей
```bash
pip install -r requirements.txt
```

## 🔧 Конфигурация

Создайте файл .env из шаблона .env.example.

Обязательные параметры:

FORTIANALYZER_URL — адрес JSON-RPC API FortiAnalyzer
FORTIANALYZER_USERNAME — пользователь
FORTIANALYZER_PASSWORD — пароль

Опциональные параметры:

DEFAULT_TIME_RANGE_HOURS — период по умолчанию (24 ч)
BATCH_SIZE — размер пачки логов (100+)
RESULTS_DIR — путь для результатов (по умолчанию: results/)
MAX_WORKERS — количество потоков обработки

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
Анализ по сети в CIDR
```bash
python main.py --input 10.20.0.0/16 --workers 4 --direction outbound
```
```
python main.py --workers 1  --direction outbound --start "2025-12-01 09:00:00" --end "2025-12-05 22:59:59" --exclude internal_ips
```

📁 Формат файлов целей
machines.txt
```bash
10.20.7.93
10.20.8.88
orion.diasoft.ru
192.168.1.10-192.168.1.20
```
Поддерживает:
- одиночные IP
- домены (резолвятся в IP)
- диапазоны A-B
- CIDR-сети

vlans.txt
```bash
192.168.0.0/24   2014   SecVlan
10.20.0.0/16     100    Internal
```
Используется параметром:
```bash
--vlan SecVlan
```
или
```bash
--vlan 2014
```

⚙️ Параметры командной строки
Временные диапазоны

Анализ за 12 часов:
```bash
--hours 12
```
Анализ за 2 дня:
```bash
--days 2
```
Явный временной интервал:
```bash
--start "2025-11-10 08:00:00" --end "2025-11-10 18:00:00"
```
Направление трафика
Только входящий:
```bash
--direction inbound
```
Только исходящий:
```bash
--direction outbound
```
Оба направления:
```bash
--direction all
```
Исключение IP
```bash
--exclude internal_ips.txt
```
Параллельная обработка
```bash
--workers 4
```
📤 Результаты
```bash
После каждого запуска формируются:
results/inbound_last.txt — последний входящий анализ
results/outbound_last.txt — последний исходящий анализ
results/history.txt — история всех запусков
Формат history.txt

=== FortiAnalyzer Export — 2025-11-16 17:57 (UTC+3) ===
Inbound: 3 records
Outbound: 1241 records
=========================================================

--- INBOUND LOGS ---
...лог...

--- OUTBOUND LOGS ---
...лог...
```
📂 Структура проекта
```bash
falogviewer/
├── main.py                 # Точка входа
├── config.py               # Конфигурация и чтение .env
├── requirements.txt        # Зависимости
├── .env.example            # Шаблон конфигурации
├── machines.txt            # Список целей (опционально)
├── vlans.txt               # VLAN-описания (опционально)
├── results/                # Результаты поиска
│   ├── inbound_last.txt
│   ├── outbound_last.txt
│   └── history.txt
├── analyzer/
│   └── log_analyzer.py     # Логика анализа логов
├── client/
│   └── faz_client.py       # FortiAnalyzer JSON-RPC клиент
└── utils/
├── network.py          # Парсинг IP, диапазонов, VLAN
└── output.py           # Запись результатов на диск
```
🔒 Безопасность

Файл .env находится в .gitignore
Никогда не коммитьте пароль FortiAnalyzer
Если файл уже попал в git — срочно смените пароль

🛠 Требования

Python 3.7+
FortiAnalyzer v7.6.3
Доступ к DNS
Сетевой доступ к FortiAnalyzer API

⚡ Советы по производительности

Увеличьте BATCH_SIZE в .env:
```bash
BATCH_SIZE=500
```
Используйте --workers 2-4 для ускорения

Сужайте окно анализа:
```bash
--hours 1
```
Используйте VLAN вместо длинных списков IP:
```bash
--vlan CorpNet
```