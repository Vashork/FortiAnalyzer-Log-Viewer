# Codex Notes

## Контекст проекта

Проект: `FortiAnalyzer Log Viewer` / `falv2`.

Назначение:
- выгрузка и анализ traffic-логов FortiAnalyzer через JSON-RPC API;
- работа в CLI и через Web UI;
- поддержка поиска:
  - по IP и направлению трафика (`direction`);
  - по одному или нескольким `policyid` (`policyid`).

Текущая структура:
- `main.py` — CLI запуск анализа.
- `web/app.py` — FastAPI web UI, SSE-прогресс, история, настройки, результаты.
- `web/templates/index.html` — SPA-шаблон интерфейса.
- `web/static/script.js` — логика фронтенда, терминалы воркеров, история, настройки.
- `client/faz_client.py` — JSON-RPC клиент FortiAnalyzer.
- `analyzer/log_analyzer.py` — построение FAZ-фильтров, fetch, агрегация, отчёты.
- `analyzer/time_range_analyzer.py` — текущий time-split режим.
- `utils/network.py` — загрузка IP/портов, reverse DNS, hostname resolve.
- `utils/output.py` — сохранение результатов.
- `config.py` — `.env`, динамические настройки, геттеры.

## Пользовательская целевая логика

Есть 2 основных режима:
- `policyid` — поиск по одной или нескольким политикам;
- `direction` — поиск по IP и направлению трафика.

Есть настройка `max_workers`:
- одновременно не больше указанного числа воркеров.

Ожидаемое распределение задач:
- `ip split`:
  - если 3 IP и 3 воркера, каждый берёт по IP;
  - если 3 IP и 2 воркера, третий IP берёт первый освободившийся воркер.
- `time split`:
  - интервал режется на куски, например по 3 часа;
  - при нескольких IP воркеры должны сначала полностью обработать весь диапазон для текущего IP, и только потом переходить к следующему IP.

Прогресс должен идти:
- в консоль;
- в web UI;
- по завершении результат должен открываться в UI;
- история должна максимально полно восстанавливать форму запроса.

## Что уже известно про архитектуру

### CLI

`main.py` — старый/простой orchestration:
- `policyid` режим — один клиент FAZ, один проход;
- `direction` режим — `ThreadPoolExecutor`, один future на `(ip, direction)`.

CLI сейчас полезен как reference логики, но основной центр тяжести проекта уже в web-слое.

### Web UI

После большого рефактора слой стал разделён так:
- `web/app.py` — тонкая FastAPI/SSE оболочка;
- `web/analysis_scheduler.py` — orchestration, planning, scheduling, сохранение результатов, генерация progress events;
- `web/static/script.js` — терминалы воркеров, история, настройки, отображение typed SSE events.

`web/app.py` больше не держит в себе основной scheduler.

### FAZ client

`client/faz_client.py` умеет:
- `login()`
- `logout()`
- `create_search_task()`
- `wait_for_task_completion()`
- `fetch_logs()`
- `cancel_search_task()`
- `cancel_all_tasks()`

Важно:
- клиент трекает `_active_tasks`;
- перед `logout()` отменяет оставшиеся search tasks;
- теперь умеет нормализовать ответы FAZ, когда `result` приходит не только как `dict`, но и как `list[dict]`.

## Что было сломано и уже исправлено

### Ранние найденные баги

1. `POST /api/analyze/stream` возвращал `422`, а фронтенд не показывал текст ошибки.
2. В `policyid` режиме web UI не показывал прогресс:
   - в обычном policy режиме не создавался терминал воркера;
   - в `policyid + time-split` имена воркеров не совпадали между backend и frontend.
3. Web UI создавал отдельный терминал `System` для общих сообщений, из-за чего вместо второго IP пользователь видел `System`.
4. SSE-обёртка `fetch_logs` в `web/app.py` была слабее, чем основной `FortiAnalyzerClient.fetch_logs`, и могла зависать после первого батча или на пустом хвосте.
5. Завершённые task id оставались в `_active_tasks`, поэтому при `logout` появлялись ложные сообщения `Cancelled search task ... on FAZ`.
6. После `Fetched X/Y` визуально казалось, что всё зависло, хотя процесс мог надолго уйти в reverse DNS на этапе построения отчёта.

### Что исправлено в backend

#### `web/app.py`

Уже сделано:
- добавлена поддержка `policyids: Optional[List[int]]`;
- добавлена нормализация `policyids` из строки/списка;
- добавлена нормализация `datetime-local` в `YYYY-MM-DD HH:MM:SS`;
- в `policyid` режиме backend работает со списком policy ID, а не только с одним значением;
- для обычного `policyid` режима добавлен явный worker label `P{policy_id}`;
- для `_faz_search_wrapper()` добавлен `progress_label`;
- patched SSE fetch:
  - retry на пустых батчах;
  - retry на incomplete batch;
  - cleanup `_active_tasks` при завершении/ошибке/отмене;
- добавлены progress-сообщения до и после `logout`;
- при `progress=100` завершённый task удаляется из `_active_tasks`;
- event generator для SSE больше не завершает поток по `TimeoutError`, а шлёт keepalive timeout-event и продолжает ждать;
- `update_env_file()` теперь не только обновляет существующие ключи, но и добавляет новые, если их раньше не было в `.env`.

#### `web/analysis_scheduler.py`

Новый модуль, в который вынесены:
- orchestration анализа;
- worker scheduling;
- сохранение результатов;
- запись history;
- patching FAZ-клиента под progress events;
- новый typed event model для SSE.

Что в нём теперь есть:
- `run_analysis_request(...)` — единая точка входа для backend orchestration;
- `AnalysisCancelled` — отдельное завершение для пользовательской отмены;
- `SchedulerEmitter` — генерация typed events;
- новый `direction/time-split` scheduler по модели:
  - есть очередь IP;
  - воркер берёт один IP;
  - полностью обрабатывает для него весь requested time range и все направления;
  - только потом берёт следующий IP.

Также были сохранены и улучшены старые сценарии:
- `direction`:
  - fallback, если `split_mode=time`, но фактически только один time segment;
  - `ip split` по-прежнему работает параллельно по IP;
  - последовательная ветка осталась как fallback.
- `policyid`:
  - `time-split` по policy всё ещё работает через `analyzer/time_range_analyzer.py`;
  - `ip split` для нескольких policy ID работает параллельно через очередь futures.

#### `client/faz_client.py`

Уже сделано:
- добавлен `_normalize_result()` для ответов FAZ;
- `wait_for_task_completion()` теперь корректно обрабатывает `result` как `dict` и как `list[dict]`;
- `fetch_logs()` теперь тоже использует нормализацию формы ответа.

Это особенно важно, потому что у пользователя наблюдалась ошибка вида:
- `Progress: 0%`
- `Task failed with status code: -1`

После правки логика стала устойчивее к вариациям формата ответа FAZ.

#### `analyzer/log_analyzer.py`

Добавлены progress-сообщения после fetch:
- `aggregating ... logs`
- `building report`

Аналогично и для `policyid` режима.

#### `utils/network.py`

Сделано:
- reverse DNS timeout через `REVERSE_DNS_TIMEOUT`, дефолт `0.3`;
- добавлено динамическое отключение reverse DNS через `.env` флаг.

### Что исправлено во фронтенде

#### `web/static/script.js`

Уже сделано:
- разбор списка `policyid` через запятую;
- нормализация exact datetime перед отправкой;
- передача `workers` в payload;
- явная обработка HTTP-ошибок, включая `422`;
- убран постоянный терминал `System`:
  - broadcast-сообщения буферизуются;
  - после появления worker terminal они подливаются в него;
- история теперь умеет восстанавливать:
  - `policyids`;
  - exact datetime;
  - targets;
  - output format;
  - columns.

Дополнительно сделано:
- в `policyid` режиме скрывается ручной блок хостов;
- кнопка `Добавить хост` в `policyid` режиме скрывается;
- при входе в `policyid` уже вручную добавленные хосты очищаются;
- при возврате в `direction` режим ручной блок и кнопка снова показываются;
- история тоже теперь после восстановления формы вызывает ту же синхронизацию видимости блока хостов;
- обработан SSE keepalive event `timeout`, чтобы UI не выглядел как полностью умерший при долгом ожидании следующего события.
- фронтенд теперь умеет принимать не только старые `progress/worker_start`, но и новый typed event model:
  - `job_started`
  - `worker_started`
  - `message`
  - `segment_started`
  - `fetch_progress`
  - `aggregation_started`
  - `report_started`
  - `logout_started`
  - `logout_finished`
  - `worker_finished`
  - `done`
  - `error`
  - `cancelled`

#### `web/templates/index.html`

Сделано:
- поле `Policy ID` заменено на `Policy ID(s)` с подсказкой `123 или 123,124,125`;
- добавлен чекбокс в настройки: `Отключить DNS resolve`.

## Настройки и `.env`

### Что уже поддерживается динамически

Через `config.py` динамически читаются:
- `MAX_WORKERS`
- `BATCH_SIZE`
- `MAX_TASK_HOURS`
- `MAX_MATCHED_LOGS_PER_TASK`
- `SESSION_SPLIT_MODE`
- `DISABLE_REVERSE_DNS`

### Reverse DNS toggle

Добавлена полноценная настройка отключения reverse DNS:
- UI чекбокс: `Отключить DNS resolve`;
- backend API:
  - `GET /api/settings` возвращает `disable_reverse_dns`;
  - `PUT /api/settings` принимает `disable_reverse_dns`;
- `.env` ключ: `DISABLE_REVERSE_DNS=true/false`;
- `.env.example` обновлён;
- `utils/network.resolve_hostname()` теперь динамически смотрит `DISABLE_REVERSE_DNS`.

Поведение:
- если DNS resolve отключён, в колонке `Hostname` остаётся сам IP;
- это уменьшает риск долгих зависаний на PTR lookup.

## Текущее поведение режимов

### `direction`

Сейчас есть 3 ветки:

1. `time split`, если:
   - `SESSION_SPLIT_MODE=time`
   - `workers > 1`
   - временных сегментов больше одного

2. `ip split`, если:
   - `workers > 1`
   - target IP больше одного

3. последовательный режим — иначе.

Важно:
- `time-split` для `direction` уже переписан под целевую логику пользователя;
- теперь время больше не режется сразу "по всему набору IP";
- новая модель:
  - есть очередь IP;
  - воркер полностью обрабатывает один IP;
  - затем берёт следующий IP;
  - UI в этом режиме показывает worker terminals (`W0`, `W1`, ...), а внутри сообщений видно, какой IP сейчас назначен воркеру.

### `policyid`

Сейчас поведение такое:

1. Если `split_mode == time` и `workers > 1`:
   - каждый `policyid` обрабатывается последовательно;
   - внутри конкретного policy id используется `time-split` по временным сегментам;
   - worker labels: `W0`, `W1`, ...

2. Если `split_mode != time`, `workers > 1` и `policy_ids > 1`:
   - включён параллельный policy mode;
   - каждый policy ID уходит как отдельная задача в `ThreadPoolExecutor`;
   - worker labels: `P123`, `P456`, ...
   - если policy больше, чем воркеров, следующую политику берёт первый освободившийся воркер.

3. Иначе:
   - обычная последовательная обработка policy ID.

Это было сделано по явному запросу пользователя:
- в `ip split` режиме несколько policy ID должны работать так же, как несколько IP.

## Что уже подтверждено пользователем

После последних правок пользователь сообщил:
- “вроде всё хорошо” по части последних фиксов UI/`direction`;
- DNS toggle нужен был и был добавлен;
- поведение `policyid` хотелось улучшить так, чтобы в `ip split` несколько policy ID работали параллельно;
- это уже реализовано.

## Что всё ещё осталось как техдолг

### Что ещё осталось как техдолг

1. Вынести и унифицировать policy/time-split scheduler на тот же event model чуть аккуратнее.
   Сейчас он уже работает, но по структуре всё ещё менее чистый, чем новый `direction/time-split`.

2. Продолжить вынос orchestration из `web/app.py`:
   - отделить planner/scheduler/workers от UI-слоя;
   - это уже начато и основная логика вынесена в `web/analysis_scheduler.py`, но `web/app.py` ещё стоит дополнительно подчистить от старых helper-ов и битой кодировки.

3. Упростить и довести до конца единый event model для SSE:
   - typed events уже добавлены;
   - нужно ещё при желании сократить legacy-совместимость во фронтенде и убрать старые ветки обработки после стабилизации.

4. Улучшить безопасность:
   - нормальная TLS-проверка к FAZ вместо `verify=False`;
   - аккуратнее логировать чувствительные данные;
   - жёстче валидировать `.env` и входные значения.

5. Улучшить производительность:
   - убрать лишние reload/read;
   - кэшировать reverse DNS осторожнее;
   - минимизировать работу в UI-слое;
   - возможно добавить ещё более явный disable для enrichments.

## Наблюдения по коду

1. В `web/app.py` часть русских комментариев/строк отображается как битая кодировка.
   Это всё ещё косметическая проблема.

2. `main.py` и web-layer уже немного расходятся по orchestration-модели.
   Это не критично, но в будущем стоит либо унифицировать planner, либо честно принять, что web — основной entrypoint.

## Практический чек-лист на следующий заход

1. Проверить новый `direction/time-split`:
   - `1 IP`
   - `2 workers`
   - `3 часа`
   - DNS resolve выключен
   - убедиться, что UI не зависает и показывает результат.

2. Проверить новый `direction/time-split`:
   - `2+ IP`
   - `2 workers`
   - `split_mode=time`
   - убедиться, что один воркер сначала полностью добивает один IP и только потом берёт следующий.

3. Проверить `direction`:
   - `2 IP`
   - `2 workers`
   - `split_mode=ip`
   - убедиться, что оба IP реально обрабатываются и терминалы отображаются корректно.

4. Проверить `policyid`:
   - `2 workers`
   - `2 policy ID`
   - `split_mode=ip`
   - убедиться, что обе политики реально идут параллельно.

5. Проверить `policyid` UI:
   - при переключении в `policyid` ручные хосты и кнопка `Добавить хост` исчезают;
   - при возврате в `direction` появляются обратно.

6. Проверить настройки:
   - `Отключить DNS resolve`
   - настройка сохраняется в `.env`
   - после обновления страницы подтягивается корректно.

## Ограничение этой среды

Полноценного runtime-прогона в этой среде по FAZ не было.

Основная работа в этой сессии делалась:
- по коду;
- по архитектурным связям;
- по логам пользователя;
- по поведению, которое пользователь вручную проверял у себя локально.

То есть `codex.md` отражает уже не только статический анализ, но и фактическую обратную связь пользователя о том, что ломалось, что было исправлено и как теперь устроен новый scheduler/event слой.
