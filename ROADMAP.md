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

Проблема: workers, time range, ports, CIDR/ranges и policyids почти не ограничены сервером.

Что сделать:
- добавить Pydantic `Literal`/validators для режимов;
- ограничить `workers`, `time_value`, `batch_size`, число `policyids`;
- валидировать ports как int 1..65535;
- добавить лимит `MAX_TARGET_IPS` / `MAX_EXPANDED_TARGETS`;
- не позволять случайно развернуть огромную сеть вроде `/8`.

Критерии готовности:
- плохие входные данные возвращают HTTP 422/400 с понятной ошибкой;
- CLI также получает защиту от слишком больших CIDR/ranges.

### 1.3 Real concurrency limiter for analysis jobs

Проблема: текущий semaphore ограничивает только старт фонового thread, а не весь анализ.

Что сделать:
- удерживать лимит до завершения SSE stream/job;
- ввести job registry: `request_id`, queue, cancel flag/event, status, created_at;
- cleanup делать в `finally`;
- при disconnect SSE либо отменять job, либо явно оставлять running job по выбранной политике.

Критерии готовности:
- реально нельзя запустить больше заданного количества активных анализов;
- нет утечки `_progress_queues` / `_cancel_flags` после завершения/ошибки/отмены.

### 1.4 Safer CORS and results path

Что сделать:
- заменить wildcard CORS на allowlist из `.env`;
- запретить опасные абсолютные `RESULTS_DIR` через Web settings;
- разрешать results только внутри project-controlled директории;
- добавить лимит размера для preview/read endpoint.

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

Сохраняем:
- `SESSION_SPLIT_MODE=ip`;
- `SESSION_SPLIT_MODE=time`.

Улучшения:
- time-split direction mode должен агрегировать batch-логи сразу внутри worker;
- worker должен возвращать stats, а не список всех сырых logs;
- добавить merge для local stats, аналогично `_merge_policy_stats`.

Критерии готовности:
- нет `all_logs.extend(...)` на больших result paths там, где можно агрегировать batch-wise;
- тесты подтверждают идентичный результат до/после на synthetic logs;
- память не растет пропорционально всему объему raw logs.

### 3.2 IP group batching

Идея: сохранить дробление по IP, но добавить группировку IP в один FAZ filter.

Проблема: один FAZ search task на каждый IP может быть слишком дорогим при сотнях IP.

Что сделать:
- добавить `TARGET_GROUP_SIZE`, например default 1 для полной совместимости;
- если `TARGET_GROUP_SIZE > 1`, группировать IP по N адресов;
- использовать уже существующую возможность `build_faz_filter(... target_ips=list ...)`;
- `aggregate_by_local()` уже умеет раскладывать логи по local IP.

Критерии готовности:
- `TARGET_GROUP_SIZE=1` ведет себя как текущая версия;
- `TARGET_GROUP_SIZE=20/50` уменьшает число FAZ tasks;
- отчеты по IP остаются прежними.

### 3.3 Reverse DNS optimization

Проблема: PTR lookup в отчете может быть самым долгим финальным этапом.

Что сделать:
- не вызывать `reload_env()` на каждый IP;
- reverse DNS enabled читать один раз на анализ;
- добавить bulk/threaded resolver с ограниченным concurrency;
- добавить LRU/TTL cache;
- заменить `socket.setdefaulttimeout()` на безопасный механизм без глобального timeout процесса;
- для больших отчетов дать возможность автоматически отключать reverse DNS.

### 3.4 Aggregator memory optimization

Что сделать:
- lazy-create sets только для включенных колонок;
- cap на высококардинальные поля (`app`, `policyname`, `devname`, etc.);
- не хранить `remote_ips` там, где unique можно получить из ключей группировки;
- добавить тесты на сохранение формата отчета.

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
