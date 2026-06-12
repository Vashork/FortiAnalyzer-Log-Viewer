# Roadmap: performance and production hardening

Дата фиксации: 2026-06-11

Цель: подготовить FortiAnalyzer Log Viewer к более стабильной эксплуатации, ускорить тяжелые анализы и снизить риск OOM, не ломая текущую модель работы с FortiAnalyzer.

Рабочая ветка для доработок: `roadmap/performance-production-hardening`

## Важные ограничения и решения

1. Дробление задачи по IP и по времени сохраняем.

   Текущие режимы `SESSION_SPLIT_MODE=ip|time` считаются важной частью производительности. Их нельзя удалять или заменять одним универсальным режимом без обратной совместимости.

   План улучшения:
   - сохранить оба режима;
   - сделать их безопаснее по памяти;
   - добавить возможность группировать IP в batch-группы, чтобы уменьшить количество FAZ search tasks;
   - оставить ручную настройку `MAX_WORKERS`, `MAX_TASK_HOURS`, `BATCH_SIZE`.

2. TLS verify к FortiAnalyzer не включаем принудительно.

   На текущем FAZ может не быть корректного сертификата. Поэтому TLS verification надо заложить как функционал, но не включать так, чтобы это сломало существующую работу.

   План:
   - добавить настройки:
     - `FORTIANALYZER_TLS_VERIFY=false` по умолчанию для совместимости;
     - `FORTIANALYZER_CA_BUNDLE=/path/to/ca.pem` опционально;
   - если TLS verify выключен, показывать warning в логах/UI;
   - позже, когда сертификат на FAZ будет нормализован, можно переключить `FORTIANALYZER_TLS_VERIFY=true`.

3. Сначала делаем безопасные инфраструктурные изменения, потом оптимизацию алгоритмов.

   Нужны маленькие проверяемые шаги с тестами после каждого блока.

## Phase 1 — Production safety / guardrails

Приоритет: P0

### 1.1 Web API authentication

Проблема: Web UI/API сейчас можно запускать на `0.0.0.0`, но endpoints не защищены.

Что сделать:
- добавить простой режим авторизации через API token или Basic Auth;
- защитить `/api/analyze/*`, `/api/results/*`, `/api/history`, `/api/settings`;
- `/api/settings` считать admin-only;
- настройки auth вынести в `.env.example`.

Критерии готовности:
- без токена protected endpoints возвращают 401/403;
- с токеном работают как раньше;
- тесты FastAPI TestClient покрывают оба сценария.

### 1.2 Server-side validation and limits

Статус: DONE — 2026-06-12

Реализовано:
- `AnalysisRequest` получил `Literal`-ограничения для `time_mode`, `analysis_mode`, `direction`, `smart_action`, `output_format`;
- `SettingsUpdate` получил `Literal`-ограничения для `smart_action`, `session_split_mode`, `output_format`;
- добавлены server-side limits:
  - `MAX_WEB_WORKERS_LIMIT=32`;
  - `MAX_TIME_HOURS_LIMIT=8760`;
  - `MAX_TIME_DAYS_LIMIT=365`;
  - `MAX_POLICY_IDS_LIMIT=100`;
  - `MAX_TARGETS_LIMIT=1024`;
  - `MAX_EXPANDED_TARGETS_LIMIT=4096`;
- ports валидируются как comma-separated integers `1..65535`;
- Web targets не могут случайно развернуть огромную сеть вроде `/8`;
- CLI `load_machines()` / `parse_ip_range()` тоже защищены от слишком больших CIDR/ranges до фактического расширения;
- `.env.example` документирует новые validation limits.

Проверка:
- `PYTHONPATH=. pytest tests/test_web_validation.py tests/test_network_limits.py -q` → 8 passed;
- `PYTHONPATH=. pytest -q` → 26 passed;
- `PYTHONPATH=. python3 -m compileall main.py client analyzer web utils tests` → OK.

Контекст по Web auth:
- Web API authentication пока не реализуется по решению владельца;
- сервер уже запускается на `127.0.0.1:8500`, внешний доступ планируется через nginx/reverse proxy.

Проблема: workers, time range, ports, CIDR/ranges и policyids почти не ограничены сервером.

Что сделать:
- [x] добавить Pydantic `Literal`/validators для режимов;
- [x] ограничить `workers`, `time_value`, `batch_size`, число `policyids`;
- [x] валидировать ports как int 1..65535;
- [x] добавить лимит `MAX_TARGET_IPS` / `MAX_EXPANDED_TARGETS`;
- [x] не позволять случайно развернуть огромную сеть вроде `/8`.

Критерии готовности:
- [x] плохие входные данные возвращают HTTP 422/400 с понятной ошибкой;
- [x] CLI также получает защиту от слишком больших CIDR/ranges.

### 1.3 Real concurrency limiter for analysis jobs

Статус: DONE — 2026-06-12

Реализовано:
- старый `asyncio.Semaphore` заменен на `JobRegistry` с жестким лимитом активных jobs;
- лимит настраивается через `MAX_ACTIVE_ANALYSIS_JOBS=2`;
- job slot берется до запуска background thread и держится до завершения/ошибки/отмены либо закрытия SSE generator;
- cancel state хранится в registry, а не в отдельном `_cancel_flags` dict;
- `_progress_queues` очищается в `finally` SSE generator;
- endpoint cancel выставляет cancel flag через registry.

Политика disconnect:
- при закрытии SSE generator registry slot и progress queue очищаются;
- фактическая отмена FAZ анализа остается explicit через `/api/analyze/cancel/{request_id}`.

Проверка:
- `PYTHONPATH=. pytest tests/test_job_registry.py -q` → 3 passed;
- `PYTHONPATH=. pytest -q` → 29 passed;
- `PYTHONPATH=. python3 -m compileall main.py client analyzer web utils tests` → OK.

Проблема: текущий semaphore ограничивал только старт фонового thread, а не весь анализ.

Что сделать:
- [x] удерживать лимит до завершения SSE stream/job;
- [x] ввести job registry: `request_id`, queue, cancel flag/event, status, created_at;
- [x] cleanup делать в `finally`;
- [x] при disconnect SSE либо отменять job, либо явно оставлять running job по выбранной политике.

Критерии готовности:
- [x] реально нельзя запустить больше заданного количества активных анализов;
- [x] нет утечки `_progress_queues` / `_cancel_flags` после завершения/ошибки/отмены.

### 1.4 Safer CORS and results path

Статус: DONE — 2026-06-12

Реализовано:
- wildcard CORS заменен на allowlist из `WEB_CORS_ALLOW_ORIGINS`;
- wildcard `*` намеренно игнорируется при разборе CORS allowlist;
- default CORS allowlist ограничен локальными origins `http://127.0.0.1:8500,http://localhost:8500`;
- Web settings больше не принимает абсолютный `RESULTS_DIR`;
- Web settings отклоняет parent traversal вроде `../outside-results`;
- result endpoints дополнительно проверяют, что текущий results dir остается внутри project root;
- preview/read endpoint `/api/results/{file_path}` читает только первые `MAX_RESULT_PREVIEW_BYTES` байт и возвращает `truncated`, `size`, `preview_limit`.

Проверка:
- `PYTHONPATH=. pytest tests/test_web_guardrails.py -q` → 5 passed;
- `PYTHONPATH=. pytest -q` → 34 passed;
- `PYTHONPATH=. python3 -m compileall main.py client analyzer web utils tests` → OK.

Что сделать:
- [x] заменить wildcard CORS на allowlist из `.env`;
- [x] запретить опасные абсолютные `RESULTS_DIR` через Web settings;
- [x] разрешать results только внутри project-controlled директории;
- [x] добавить лимит размера для preview/read endpoint.

## Phase 2 — FortiAnalyzer client reliability and compatibility

Приоритет: P1

### 2.1 requests.Session and connection pooling

Статус: DONE — 2026-06-12

Реализовано:
- `FortiAnalyzerClient` использует один reusable `requests.Session` на экземпляр клиента;
- `HTTPAdapter(pool_connections, pool_maxsize)` монтируется для `https://` и `http://`;
- timeout по умолчанию стал tuple `(connect_timeout, read_timeout)`;
- session закрывается через `logout()` / `close()`;
- CLI/Web creation paths используют `FortiAnalyzerClient.from_env()`;
- worker-клиенты time-split наследуют transport settings от main client.

Проверка:
- `PYTHONPATH=. pytest tests/test_faz_client.py -q` → 6 passed;
- `PYTHONPATH=. pytest -q` → 15 passed;
- `PYTHONPATH=. python3 -m compileall main.py client analyzer web utils tests` → OK.

Проблема: каждый JSON-RPC request раньше шел через `requests.post`, без connection reuse.

Что сделать:
- [x] добавить `requests.Session` в `FortiAnalyzerClient`;
- [x] настроить `HTTPAdapter(pool_connections, pool_maxsize)`;
- [x] использовать timeout tuple `(connect_timeout, read_timeout)`;
- [x] закрывать session при logout/close.

Критерии готовности:
- [x] существующие тесты проходят;
- [x] добавить unit-test/mocked test на использование session;
- [x] поведение API не меняется.

### 2.2 Optional TLS verification support

Статус: DONE — 2026-06-12

Реализовано:
- добавлены env-настройки в `.env.example`:
  - `FORTIANALYZER_TLS_VERIFY=false`;
  - `FORTIANALYZER_CA_BUNDLE=`;
  - `FORTIANALYZER_POOL_CONNECTIONS=10`;
  - `FORTIANALYZER_POOL_MAXSIZE=10`;
  - `FORTIANALYZER_CONNECT_TIMEOUT=5`;
  - `FORTIANALYZER_READ_TIMEOUT=30`;
- default остается совместимым: TLS verify выключен, чтобы не сломать FAZ с self-signed сертификатом;
- если `FORTIANALYZER_TLS_VERIFY=true` и задан `FORTIANALYZER_CA_BUNDLE`, requests получает `verify=/path/to/ca.pem`;
- если `FORTIANALYZER_TLS_VERIFY=true` без CA bundle, requests получает `verify=True`;
- если verify выключен, клиент печатает предупреждение и отключает `InsecureRequestWarning`.

Что сделать:
- [x] добавить env:
  - `FORTIANALYZER_TLS_VERIFY=false` default;
  - `FORTIANALYZER_CA_BUNDLE=` optional;
- [x] передавать `verify=False|True|path` в requests;
- [x] если `verify=False`, логировать предупреждение, но не ломать запуск.

Важно: verify по умолчанию не включен до готовности сертификата на FAZ.

### 2.3 Better retry/backoff

Статус: DONE — 2026-06-12

Реализовано:
- `_post()` ретраит transient network ошибки `requests.ConnectionError` и `requests.Timeout`;
- `_post()` ретраит только явно transient HTTP statuses: `429`, `500`, `502`, `503`, `504`;
- HTTP auth/client ошибки вроде `401` не ретраятся и сразу пробрасываются наверх;
- retry-настройки читаются из env:
  - `FORTIANALYZER_RETRY_ATTEMPTS=3`;
  - `FORTIANALYZER_RETRY_BACKOFF_SECONDS=1`;
- retry-настройки наследуются worker-клиентами time-split через `transport_kwargs()`;
- retry-логи не содержат username/password/session token.

Проверка:
- `PYTHONPATH=. pytest tests/test_faz_client.py -q` → 9 passed;
- `PYTHONPATH=. pytest -q` → 18 passed;
- `PYTHONPATH=. python3 -m compileall main.py client analyzer web utils tests` → OK.

Что сделать:
- [x] добавить retry/backoff для transient ошибок FAZ/API;
- [x] не ретраить login/password ошибки;
- [x] логировать request retry context без секретов.

## Phase 3 — Performance and memory optimization

Приоритет: P1

### 3.1 Keep and optimize IP/time split modes

Статус: DONE — 2026-06-12

Реализовано:
- режимы `SESSION_SPLIT_MODE=ip|time` сохранены;
- direction time-split больше не возвращает raw logs из worker;
- новый `fetch_local_stats_for_segments()` агрегирует batches сразу внутри worker через `_iter_fetch_log_batches()`;
- `_run_worker_local_stats()` возвращает `(stats, total_logs)` по worker вместо списка всех logs;
- финальный этап merge объединяет local stats через `_merge_local_stats()`;
- legacy raw-log helper удален, в `time_range_analyzer.py` больше нет `all_logs.extend(...)` / `fetch_logs_for_segments` / `_run_worker_segments`;
- существующий policyid time-split streaming aggregation сохранен.

Проверка:
- `PYTHONPATH=. pytest tests/test_time_range_analyzer.py tests/test_faz_client.py tests/test_log_analyzer.py -q` → 17 passed;
- `PYTHONPATH=. pytest -q` → 36 passed;
- `PYTHONPATH=. python3 -m compileall main.py client analyzer web utils tests` → OK;
- grep по `analyzer/time_range_analyzer.py` для `all_logs.extend|fetch_logs_for_segments|_run_worker_segments\(` → 0 matches.

Сохраняем:
- [x] `SESSION_SPLIT_MODE=ip`;
- [x] `SESSION_SPLIT_MODE=time`.

Улучшения:
- [x] time-split direction mode агрегирует batch-логи сразу внутри worker;
- [x] worker возвращает stats, а не список всех сырых logs;
- [x] добавлен merge для local stats, аналогично `_merge_policy_stats`.

Критерии готовности:
- [x] нет `all_logs.extend(...)` на больших result paths там, где можно агрегировать batch-wise;
- [x] тесты подтверждают идентичный результат до/после на synthetic logs;
- [x] память не растет пропорционально всему объему raw logs.

### 3.2 IP group batching

Статус: DONE — 2026-06-12

Реализовано:
- добавлена настройка `TARGET_GROUP_SIZE=1` в `.env.example` и `config.py`;
- default `1` сохраняет старое поведение: один FAZ search task на один IP;
- `utils.batching.group_target_ips()` группирует targets в ordered batches;
- CLI direction mode теперь отправляет в `analyze_logs()` IP-группы, а не только одиночные IP;
- Web direction mode и Web time-split-by-IP queue теперь работают с IP-группами;
- результаты по-прежнему раскладываются по local IP через существующий `aggregate_by_local()` / report keys;
- progress/log messages показывают количество groups и `TARGET_GROUP_SIZE`.

Проверка:
- `PYTHONPATH=. pytest tests/test_ip_group_batching.py tests/test_log_analyzer.py tests/test_web_validation.py -q` → 14 passed;
- `PYTHONPATH=. pytest -q` → 39 passed;
- `PYTHONPATH=. python3 -m compileall main.py client analyzer web utils tests` → OK.

Идея: сохранить дробление по IP, но добавить группировку IP в один FAZ filter.

Проблема: один FAZ search task на каждый IP может быть слишком дорогим при сотнях IP.

Что сделать:
- [x] добавить `TARGET_GROUP_SIZE`, default 1 для полной совместимости;
- [x] если `TARGET_GROUP_SIZE > 1`, группировать IP по N адресов;
- [x] использовать уже существующую возможность `build_faz_filter(... target_ips=list ...)`;
- [x] `aggregate_by_local()` уже умеет раскладывать логи по local IP.

Критерии готовности:
- [x] `TARGET_GROUP_SIZE=1` ведет себя как текущая версия;
- [x] `TARGET_GROUP_SIZE=20/50` уменьшает число FAZ tasks;
- [x] отчеты по IP остаются прежними.

### 3.3 Reverse DNS optimization

Статус: DONE — 2026-06-12

Реализовано:
- reverse DNS flag читается один раз на запуск анализа в CLI/Web через `configure_reverse_dns(get_dynamic_reverse_dns_enabled())`;
- `resolve_hostname()` больше не вызывает `reload_env()` на каждый IP после request-scoped configuration;
- `socket.setdefaulttimeout()` удален из production path;
- PTR lookup выполняется через isolated future timeout, без изменения global socket timeout процесса;
- добавлен bounded bulk resolver `resolve_hostnames(ips, max_workers=None)`;
- direction/policy report builders предрезолвят hostname maps bulk-методом и используют shared cache;
- добавлены настройки `.env.example`: `REVERSE_DNS_TIMEOUT=0.3`, `REVERSE_DNS_WORKERS=16`, `REVERSE_DNS_CACHE_TTL_SECONDS=86400`, `REVERSE_DNS_CACHE_SIZE=10000`;
- добавлен `REVERSE_DNS_MAX_UNIQUE_IPS=1000`: для больших отчетов bulk PTR lookup автоматически пропускается, а hostname values остаются IP; `0` отключает этот auto-disable;
- Web settings update при изменении `DISABLE_REVERSE_DNS` очищает cache и сразу обновляет configured DNS state.

Проверка:
- `PYTHONPATH=. pytest tests/test_reverse_dns.py tests/test_log_analyzer.py tests/test_web_validation.py -q` → 17 passed;
- `PYTHONPATH=. pytest tests/test_reverse_dns.py -q` → 8 passed;
- `PYTHONPATH=. pytest -q` → 45 passed;
- `PYTHONPATH=. python3 -m compileall main.py client analyzer web utils tests` → OK;
- production grep по `setdefaulttimeout` → нет вызовов вне tests.

Проблема: PTR lookup в отчете может быть самым долгим финальным этапом.

Что сделать:
- [x] не вызывать `reload_env()` на каждый IP;
- [x] reverse DNS enabled читать один раз на анализ;
- [x] добавить bulk/threaded resolver с ограниченным concurrency;
- [x] добавить LRU/TTL cache;
- [x] заменить `socket.setdefaulttimeout()` на безопасный механизм без глобального timeout процесса;
- [x] для больших отчетов дать возможность автоматически отключать reverse DNS.

### 3.4 Aggregator memory optimization

Статус: DONE — 2026-06-12

Реализовано:
- local/policyid stats entries теперь создаются минимально: только `count`, без eager sets для всех возможных колонок;
- set-поля создаются lazy только если соответствующая колонка реально включена в report config;
- `remote_ips` больше не хранится при стандартной группировке по `remote_ip`, потому что unique remotes считаются из ключей группировки;
- если `AGGREGATE_REMOTE_IP=false`, `remote_ips` сохраняется как fallback для корректного `Total unique remotes`;
- добавлен cap `AGGREGATE_FIELD_VALUE_LIMIT=1000` для высококардинальных report-полей: `app`, `policyname`, `devname`, interfaces, actions, smart_actions, `srcports`;
- при превышении cap в отчете появляется marker `<truncated>`, чтобы формат оставался понятным и память не росла без лимита;
- тесты покрывают lazy stats, сохранение report format и cap высококардинальных полей.

Проверка:
- `PYTHONPATH=. pytest tests/test_log_analyzer.py::LogAnalyzerAggregationTests::test_local_stats_only_create_sets_for_enabled_columns_and_keep_report_format tests/test_log_analyzer.py::LogAnalyzerAggregationTests::test_policyid_stats_only_create_sets_for_enabled_columns_and_keep_report_format -q` → 2 passed;
- `PYTHONPATH=. pytest tests/test_log_analyzer.py::LogAnalyzerAggregationTests::test_high_cardinality_report_fields_are_capped -q` → 1 passed;
- `PYTHONPATH=. pytest tests/test_log_analyzer.py tests/test_time_range_analyzer.py -q` → 11 passed;
- `PYTHONPATH=. pytest -q` → 48 passed;
- `PYTHONPATH=. python3 -m compileall main.py client analyzer web utils tests` → OK.

Что сделать:
- [x] lazy-create sets только для включенных колонок;
- [x] cap на высококардинальные поля (`app`, `policyname`, `devname`, etc.);
- [x] не хранить `remote_ips` там, где unique можно получить из ключей группировки;
- [x] добавить тесты на сохранение формата отчета.

### 3.5 Progress throttling

Что сделать:
- не отправлять SSE/progress event на каждый мелкий batch, если событий слишком много;
- throttle по времени или проценту;
- queue maxsize/coalescing для progress events.

## Phase 4 — Results/history scalability

Приоритет: P1/P2

### 4.1 Unique run_id and result directories

Проблема: `inbound.txt`, `outbound.txt`, `policy_*.txt` могут перезаписываться.

Что сделать:
- создать `run_id` для каждого анализа;
- сохранять результаты в `results/<run_id>/...`;
- хранить metadata о run.

### 4.2 History storage

Что сделать:
- перейти с монолитного `history.txt` на JSONL или SQLite;
- хранить request, status, started_at, finished_at, duration, files, error;
- добавить пагинацию `/api/history?limit=&offset=`.

### 4.3 Results preview/download

Что сделать:
- API preview с лимитом строк/байт;
- полный результат отдавать через download endpoint;
- UI не должен вставлять огромные файлы целиком в DOM.

## Phase 5 — Architecture and maintainability

Приоритет: P2

### 5.1 Request-scoped config

Проблема: глобальные `config.COLUMNS_CONFIG`, `config.SMART_ACTION` могут конфликтовать между параллельными анализами.

Что сделать:
- ввести immutable `AnalysisConfig`;
- передавать настройки явно в analyzer/filter builder;
- убрать изменение module-level config из request path.

### 5.2 Remove client monkey-patching

Проблема: `_patch_faz_client_for_events()` подменяет методы клиента.

Что сделать:
- добавить event callbacks/hooks в `FortiAnalyzerClient`;
- либо сделать wrapper class.

### 5.3 Unified CLI/Web analysis service

Что сделать:
- выделить общий `AnalysisService`;
- CLI и Web должны использовать один orchestration layer.

### 5.4 Packaging and CI

Что сделать:
- добавить `pyproject.toml` или lock workflow;
- добавить ruff/pytest/pip-audit в CI;
- добавить Dockerfile или systemd пример;
- добавить `/healthz` и `/readyz`.

## Proposed first coding batch

На завтра начать с отдельной ветки от `master` или продолжить текущую ветку roadmap, если roadmap-коммит будет принят.

Рекомендуемый первый batch:

1. `FortiAnalyzerClient`:
   - `requests.Session`;
   - optional TLS verify env, default compatible/off;
   - tests/mocks.

2. Web safety:
   - Basic/API-token auth;
   - validation limits;
   - CORS allowlist.

3. Performance quick win:
   - reverse DNS env-read cleanup или отключение DNS для больших отчетов;
   - затем IP group batching.

После каждого batch:
- запуск `python -m pytest -q`;
- отдельный commit;
- затем push в отдельную ветку.

## Current verification snapshot

На момент аудита:

```bash
python -m pytest -q
# 9 passed
```

Проект небольшой и хорошо подходит для поэтапного рефакторинга: сначала guardrails, затем ускорение без удаления существующих режимов дробления.
