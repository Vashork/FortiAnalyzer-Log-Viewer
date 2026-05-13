# falv2 — FortiAnalyzer Log Viewer

Web-интерфейс и CLI для анализа логов FortiAnalyzer через JSON-RPC API.

## Возможности

- **Direction Mode** — анализ трафика по направлению (Inbound / Outbound / Оба)
- **PolicyID Mode** — анализ логов по конкретному policyid
- **Time-Split Mode** — автоматическое дробление временного интервала на сегменты с параллельной обработкой воркерами
- **Гибкий выбор целей** — файл `machines.txt` или ручной ввод IP/CIDR/подсетей
- **Исключение внутренних IP** — фильтрация по `internal_ips.txt`
- **Фильтрация по портам** — режим `--proto` с произвольным списком портов
- **Smart Action** — фильтрация по действию (`all`, `deny`, `all-accept`)
- **Настраиваемые колонки** — PolicyID, App, SrcIntf, DstIntf, Action и др.
- **Настраиваемая агрегация** — выбор полей группировки отчёта; по умолчанию сохранены прежние ключи агрегации.
- **Форматы вывода** — TXT, CSV или оба
- **Многопоточность** — параллельная обработка IP или временных сегментов
- **Отмена задач** — поиск-задачи на FAZ корректно отменяются при остановке анализа
- **История запросов** — полная детализация каждого запуска
- **Логирование** — все события сервера в `logs/web_server.log`

## Структура проекта

```
falogviewerv2/
├── web/                        # Web-интерфейс
│   ├── app.py                  # FastAPI сервер + API endpoints
│   ├── templates/index.html    # SPA интерфейс
│   └── static/
│       ├── style.css
│       └── script.js
├── analyzer/
│   ├── log_analyzer.py         # Агрегация и отчёты, фильтрация логов
│   └── time_range_analyzer.py  # Time-split режим: дробление времени, воркеры
├── client/
│   └── faz_client.py           # JSON-RPC клиент FortiAnalyzer
├── utils/
│   ├── network.py              # Загрузка IP, портов, разрешение имён
│   └── output.py               # Сохранение результатов
├── resources/                  # Входные данные
│   ├── machines.txt            # Целевые IP-адреса
│   ├── internal_ips.txt        # IP для исключения
│   └── ports.txt               # Порты для фильтра
├── logs/                       # Логи сервера
│   └── web_server.log
├── results/                    # Результаты анализа
├── config.py                   # Конфигурация + динамические геттеры
├── .env                        # Учётные данные FAZ
├── main.py                     # CLI версия
└── requirements.txt
```

## Установка

```bash
pip install -r requirements.txt
```

## Запуск Web-UI

```bash
python web/app.py
```

Откройте в браузере: **http://127.0.0.1:8500**

## Запуск CLI

```bash
python main.py --input machines.txt --direction outbound --days 1
python main.py --policyid 123 --start "2025-01-01 00:00:00" --end "2025-01-01 23:59:59"
```

## Конфигурация (.env)

| Переменная | По умолчанию | Описание |
|---|---|---|
| `FORTIANALYZER_URL` | — | JSON-RPC endpoint FortiAnalyzer |
| `FORTIANALYZER_USERNAME` | — | Логин |
| `FORTIANALYZER_PASSWORD` | — | Пароль |
| `BATCH_SIZE` | 100 | Размер батча при выгрузке логов |
| `EMPTY_BATCH_LIMIT` | 3 | Лимит повторных попыток при пустом батче |
| `MAX_WORKERS` | 1 | Число параллельных потоков |
| `SESSION_SPLIT_MODE` | ip | `ip` (по IP) / `time` (по времени) |
| `SMART_ACTION` | all | `all` / `deny` / `all-accept` |
| `FILTER_MODE` | faz | `faz` (на стороне FAZ) / `local` (в Python) |
| `MAX_TASK_HOURS` | 1 | Макс. длительность одного search-сегмента |
| `MAX_MATCHED_LOGS_PER_TASK` | 200000 | Лимит логов на task |
| `RESULTS_DIR` | results | Директория результатов |
| `COLUMN_POLICYID` | true | Колонка PolicyID в отчёте |
| `COLUMN_APP` | true | Колонка App |
| `COLUMN_SRCINTF` | true | Колонка SrcIntf |
| `COLUMN_DSTINTF` | true | Колонка DstIntf |
| `AGGREGATE_REMOTE_IP` | true | Поле Remote IP в ключе агрегации direction-режима |
| `AGGREGATE_SRCIP` | true | Поле SRC в ключе агрегации policyid-режима |
| `AGGREGATE_DSTIP` | true | Поле DST в ключе агрегации policyid-режима |
| `AGGREGATE_PORT` | true | Поле Port в ключе агрегации |
| `AGGREGATE_PROTO` | true | Поле Proto в ключе агрегации |
| `AGGREGATE_POLICYID` | true | Поле PolicyID в ключе агрегации policyid-режима |

## Формат files

### resources/machines.txt
```
#SRX
192.168.124.8
192.168.178.7
# CIDR
10.20.0.0/24
# Диапазон
192.168.1.10-192.168.1.20
```

### resources/internal_ips.txt
```
# IP для исключения
10.1.1.50
192.168.178.7
```

### resources/ports.txt
```
443
80
22
```

## API Endpoints (Web)

| Endpoint | Метод | Описание |
|---|---|---|
| `/` | GET | Главная страница |
| `/api/analyze/stream` | POST | SSE стрим анализа |
| `/api/analyze/cancel/{request_id}` | POST | Отмена текущего анализа |
| `/api/results` | GET | Список файлов результатов |
| `/api/results/{path}` | GET | Содержимое файла |
| `/api/results/download/{path}` | GET | Скачивание файла |
| `/api/resources/machines` | GET | Загрузка machines.txt |
| `/api/history` | GET | История запросов |
| `/api/settings` | GET | Текущие настройки |
| `/api/settings` | PUT | Обновление настроек |

## Лицензия

Внутренний проект Diasoft.
