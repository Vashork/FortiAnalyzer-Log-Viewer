# FortiAnalyzer Log Viewer

## Установка

1. Клонируйте репозиторий (если ещё не сделали)
```bash
git clone <ваш-репозиторий>
cd falogviewer
```

2. Создайте виртуальное окружение (рекомендуется)
```bash
python -m venv .venv
source .venv/bin/activate      # Linux/macOS
```
или
```bash
.venv\Scripts\activate         # Windows
```

3. Установите зависимости
```bash
pip install -r requirements.txt
```

### Настройте подключение к FortiAnalyzer
Создайте файл .env в корне проекта из шаблона .env.example

Обязательные параметры:
- `FORTIANALYZER_URL` - URL для подключения к FortiAnalyzer API
- `FORTIANALYZER_USERNAME` - имя пользователя для аутентификации
- `FORTIANALYZER_PASSWORD` - пароль для аутентификации

Опциональные параметры:
- `DEFAULT_TIME_RANGE_HOURS` - временной диапазон поиска по умолчанию в часах (по умолчанию: 24)
- `BATCH_SIZE` - размер пачки для получения данных (по умолчанию: 100)

### Описание параметров конфигурации

## Простой запуск из файла за последние 6 часов
```bash
python main.py machines.txt --hours 6
```

## Анализ всей сети по VLAN (имя или ID)
```bash
python main.py --vlan SecVlan --days 1
```

## CIDR-сеть + параллельная обработка
```bash
python main.py 10.20.0.0/16 --workers 4 --direction outbound
```

Результаты появятся в папке results/ — каждая машина в отдельном файле.

Примеры файлов
machines.txt
```bash
10.20.7.93
10.20.8.88
orion.diasoft.ru
192.168.1.10-192.168.1.20
```

vlans.txt (создайте, если используете --vlan)
```bash
Сеть            VLAN_ID   Имя
192.168.0.0/24   2014     SecVlan
10.20.0.0/16     100      Internal
```

⚙️ Основные параметры командной строки

Анализ за 12 часов
```bash
python main.py machines.txt --hours 12
```
Анализ за 2 дня
```bash
python main.py machines.txt --days 2
```
Только входящий трафик ( по отношению к IP из machines.txt )
```bash
--direction inbound
```
Только исходящий трафик ( по отношению к IP из machines.txt )
```bash
--direction outbound
```
Параллельно 4 машины
```bash
--workers 4
```
Поиск по VLAN
```bash
--vlan SecVlan
```
или
```bash
--vlan 2014
```
Точный период
```bash
--start 2025-11-10T08:00:00 --end 2025-11-10T18:00:00
```
Исключить IP
```bash
--exclude internal_ips.txt
```


📁 Структура проекта
falogviewer/
```bash
├── main.py              # Точкой входа приложения
├── .env.example         # Шаблон конфигурационного файла
├── .gitignore           # Исключения из Git-репозитория
├── machines.txt         # Список целей (опционально)
├── vlans.txt            # Справочник VLAN (опционально)
├── requirements.txt     # Справочник зависимости
├── config.py            # Загрузка и централизованное управление конфигурацией
├── results/             # Сюда сохраняются результаты
├── analyzer/            # Модули, отвечающие за анализ сетевого трафика
├── client/              # Реализует взаимодействие с внешним API
└── utils/               # вспомогательные утилиты: парсинг CIDR и диапазонов IP, работа с конфигурационными файлами (например, .env)
```

🔒 Безопасность
.env добавлен в .gitignore — убедитесь, что он не попал в историю Git.
Если .env был закоммичен — немедленно смените пароль в FortiAnalyzer.

🛠 Требования
Python 3.7+
Доступ к FortiAnalyzer v7.6.3 через JSON-RPC API
Сетевое подключение для DNS

💡 Советы по производительности
Увеличьте BATCH_SIZE до 500 или 1000 в .env → меньше HTTP-запросов.
Используйте --workers 2-4 → обработка нескольких машин параллельно.
Сужайте временной диапазон → --hours 1 вместо 24, если ищете свежие события.
Используйте VLAN-режим → не вводите вручную сотни IP.