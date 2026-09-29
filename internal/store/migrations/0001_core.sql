-- =============================================================================
-- InvMon — схема БД MVP (мониторинг и инвентаризация парка Windows-ПК)
-- PostgreSQL 16+ (проверено на 16; целевые версии — 17/18)
--
-- Соглашения:
--   * PK — bigint identity; время — timestamptz (хранится в UTC);
--   * метрики и аудит — декларативное партиционирование по времени;
--   * «горячее» состояние устройства вынесено в device_state (частые UPDATE);
--   * накат схемы — миграциями (goose) под ролью-владельцем invmon_owner,
--     сервер работает под ролью invmon_app (только DML, см. конец файла).
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS pg_trgm;   -- поиск по подстроке в названиях ПО / хостов
CREATE EXTENSION IF NOT EXISTS citext;    -- регистронезависимые логины

-- Общий триггер для поля updated_at
CREATE FUNCTION set_updated_at() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END $$;

-- =============================================================================
-- 1. Пользователи веб-интерфейса и сессии
-- =============================================================================
CREATE TYPE user_role AS ENUM ('admin', 'operator', 'viewer');

CREATE TABLE users (
    id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username       citext      NOT NULL UNIQUE,
    display_name   text        NOT NULL DEFAULT '',
    email          citext,
    password_hash  text,                    -- argon2id в PHC-формате; NULL для LDAP (v1.1)
    auth_source    text        NOT NULL DEFAULT 'local' CHECK (auth_source IN ('local', 'ldap')),
    role           user_role   NOT NULL DEFAULT 'viewer',
    is_active      boolean     NOT NULL DEFAULT true,
    failed_logins  integer     NOT NULL DEFAULT 0,
    locked_until   timestamptz,
    last_login_at  timestamptz,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    CHECK (auth_source <> 'local' OR password_hash IS NOT NULL)
);
CREATE TRIGGER users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Серверные сессии: в cookie лежит случайный ID, в БД — только его SHA-256
CREATE TABLE sessions (
    id_hash       bytea       PRIMARY KEY,
    user_id       bigint      NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL,
    ip            inet,
    user_agent    text
);
CREATE INDEX sessions_user_idx    ON sessions (user_id);
CREATE INDEX sessions_expires_idx ON sessions (expires_at);

-- =============================================================================
-- 2. Устройства, группы, регистрация агентов
-- =============================================================================
CREATE TABLE device_groups (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name         text        NOT NULL UNIQUE,
    description  text        NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL DEFAULT now()
);

-- Токены регистрации (enrollment): выдаются админом, передаются агенту при установке
CREATE TABLE enrollment_tokens (
    id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name          text        NOT NULL,
    token_hash    bytea       NOT NULL UNIQUE,        -- SHA-256 от токена; сам токен показывается один раз
    token_prefix  text        NOT NULL,               -- «imenr_7Hk2» — для опознания в UI и логах
    group_id      bigint      REFERENCES device_groups (id) ON DELETE SET NULL,
    auto_approve  boolean     NOT NULL DEFAULT true,  -- false → новые устройства ждут одобрения (pending)
    max_uses      integer     CHECK (max_uses > 0),   -- NULL = без ограничения
    used_count    integer     NOT NULL DEFAULT 0,
    expires_at    timestamptz NOT NULL,
    revoked_at    timestamptz,
    created_by    bigint      REFERENCES users (id) ON DELETE SET NULL,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TYPE device_status AS ENUM (
    'pending',   -- зарегистрирован, ждёт одобрения администратором
    'active',    -- принимаем данные
    'revoked',   -- токен отозван (данные сохраняются)
    'retired'    -- выведен из эксплуатации (скрыт из списков по умолчанию)
);

CREATE TABLE devices (
    id                     bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    agent_uid              uuid          NOT NULL UNIQUE,   -- генерирует агент при установке → идемпотентная регистрация
    status                 device_status NOT NULL DEFAULT 'active',
    hostname               text          NOT NULL,
    domain                 text,                             -- AD-домен или рабочая группа
    group_id               bigint        REFERENCES device_groups (id) ON DELETE SET NULL,
    tags                   text[]        NOT NULL DEFAULT '{}',
    notes                  text          NOT NULL DEFAULT '',
    -- аппаратные идентификаторы: поиск дублей, переустановок ОС, клонированных образов
    machine_guid           text,                             -- HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid
    smbios_uuid            uuid,                             -- Win32_ComputerSystemProduct.UUID
    serial_number          text,                             -- Win32_BIOS.SerialNumber
    -- ОС и агент (денормализовано для быстрого списка устройств)
    os_name                text,                             -- «Windows 11 Pro»
    os_version             text,                             -- «10.0.22631.4169»
    os_display_version     text,                             -- «23H2»
    os_arch                text CHECK (os_arch IN ('x86', 'x64', 'arm64')),
    agent_version          text,
    -- аутентификация агента: храним только SHA-256 токена
    token_hash             bytea UNIQUE,
    token_issued_at        timestamptz,
    prev_token_hash        bytea UNIQUE,                     -- старый токен живёт до prev_token_expires_at (ротация)
    prev_token_expires_at  timestamptz,
    enrolled_via           bigint REFERENCES enrollment_tokens (id) ON DELETE SET NULL,
    enrolled_at            timestamptz   NOT NULL DEFAULT now(),
    -- инвентаризация
    inventory_hash         bytea,                            -- SHA-256 канонического JSON последнего снимка
    inventory_at           timestamptz,
    inventory_requested    boolean       NOT NULL DEFAULT false,  -- кнопка «Обновить инвентаризацию» в UI
    created_at             timestamptz   NOT NULL DEFAULT now(),
    updated_at             timestamptz   NOT NULL DEFAULT now()
);
CREATE INDEX devices_group_idx         ON devices (group_id);
CREATE INDEX devices_tags_idx          ON devices USING gin (tags);
CREATE INDEX devices_hostname_trgm_idx ON devices USING gin (hostname gin_trgm_ops);
CREATE INDEX devices_smbios_idx        ON devices (smbios_uuid);
CREATE INDEX devices_machine_guid_idx  ON devices (machine_guid);
CREATE TRIGGER devices_updated_at BEFORE UPDATE ON devices
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- «Горячее» состояние: одна строка на устройство, UPDATE при каждом приёме метрик.
-- fillfactor < 100 оставляет место для HOT-обновлений без раздувания индексов.
CREATE TABLE device_state (
    device_id          bigint      PRIMARY KEY REFERENCES devices (id) ON DELETE CASCADE,
    last_seen_at       timestamptz NOT NULL,
    last_ip            inet,
    boot_time          timestamptz,
    logged_on_user     text,                   -- только если collect_logged_on_user = true
    cpu_pct            real,
    mem_used_pct       real,
    mem_total_bytes    bigint,
    min_disk_free_pct  real,                   -- минимум по фиксированным томам — для сортировки списка
    clock_skew_s       integer     NOT NULL DEFAULT 0,   -- расхождение часов агента с сервером
    agent_uptime_s     bigint,
    agent_rss_bytes    bigint,
    agent_errors       jsonb       NOT NULL DEFAULT '[]' -- последние ошибки сборщиков (таймаут WMI и т.п.)
) WITH (fillfactor = 70);

-- =============================================================================
-- 3. Инвентаризация (текущее состояние)
-- =============================================================================
CREATE TABLE device_hardware (
    device_id        bigint      PRIMARY KEY REFERENCES devices (id) ON DELETE CASCADE,
    manufacturer     text,                     -- Win32_ComputerSystem.Manufacturer
    model            text,                     -- Win32_ComputerSystem.Model
    bios_vendor      text,
    bios_version     text,
    bios_date        date,
    cpu_model        text,                     -- Win32_Processor.Name
    cpu_sockets      smallint,
    cpu_cores        smallint,
    cpu_threads      smallint,
    cpu_max_mhz      integer,
    ram_total_bytes  bigint,
    ram_modules      jsonb       NOT NULL DEFAULT '[]',  -- [{slot,size_bytes,speed_mhz,manufacturer,part_number}]
    os_install_date  timestamptz,
    raw              jsonb       NOT NULL DEFAULT '{}',  -- снимок «как прислал агент» (отладка, новые поля)
    updated_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX device_hardware_cpu_idx ON device_hardware (cpu_model);

-- Физические диски
CREATE TABLE device_disks (
    device_id      bigint   NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    disk_index     smallint NOT NULL,           -- Win32_DiskDrive.Index
    model          text,
    serial_number  text,
    media_type     text CHECK (media_type IN ('SSD', 'HDD', 'Unknown')),  -- на Win7 обычно Unknown
    bus_type       text,                        -- NVMe | SATA | SAS | USB | ...
    size_bytes     bigint,
    status         text,                        -- Win32_DiskDrive.Status: OK | Pred Fail | ...
    PRIMARY KEY (device_id, disk_index)
);

-- Логические тома (фиксированные). free_* обновляются при приёме дисковых метрик.
CREATE TABLE device_volumes (
    device_id    bigint      NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    volume       text        NOT NULL,          -- «C:»
    label        text,
    filesystem   text,                          -- NTFS | ReFS | FAT32
    total_bytes  bigint      NOT NULL CHECK (total_bytes > 0),
    free_bytes   bigint      NOT NULL CHECK (free_bytes >= 0),
    free_pct     real GENERATED ALWAYS AS ((free_bytes * 100.0 / total_bytes)::real) STORED,
    updated_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, volume)
) WITH (fillfactor = 70);

-- Сетевые адаптеры (физические, с MAC)
CREATE TABLE device_network_adapters (
    device_id     bigint  NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    mac           macaddr NOT NULL,
    name          text,                         -- «Ethernet»
    description   text,                         -- «Intel(R) Ethernet Connection I219-LM»
    speed_mbps    integer,
    dhcp_enabled  boolean,
    ipv4          inet[]  NOT NULL DEFAULT '{}', -- с маской: {192.168.10.23/24}
    ipv6          inet[]  NOT NULL DEFAULT '{}',
    gateways      inet[]  NOT NULL DEFAULT '{}',
    dns_servers   inet[]  NOT NULL DEFAULT '{}',
    PRIMARY KEY (device_id, mac)
);
CREATE INDEX device_network_adapters_mac_idx ON device_network_adapters (mac);

-- Справочник ПО: одна строка на нормализованную пару (название, издатель)
CREATE TABLE software (
    id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name           text        NOT NULL,        -- «7-Zip» (без версии и разрядности)
    publisher      text        NOT NULL DEFAULT '',
    first_seen_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (name, publisher)
);
CREATE INDEX software_name_trgm_idx ON software USING gin (name gin_trgm_ops);

-- Установленное ПО. Текущее состояние = строки с removed_at IS NULL;
-- обновление версии = закрытие старой строки + новая строка → история бесплатно.
CREATE TABLE device_software (
    id                bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    device_id         bigint      NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    software_id       bigint      NOT NULL REFERENCES software (id),
    display_name      text        NOT NULL,     -- DisplayName из реестра как есть
    version           text        NOT NULL DEFAULT '',
    version_parts     integer[],                -- «23.01» → {23,1}: сравнение версий в SQL
    arch              text        NOT NULL DEFAULT '' CHECK (arch IN ('x64', 'x86', 'arm64', '')),
    scope             text        NOT NULL DEFAULT 'machine' CHECK (scope IN ('machine', 'user')),
    install_date      date,
    msi_product_code  uuid,
    size_kb           bigint,
    first_seen_at     timestamptz NOT NULL DEFAULT now(),
    last_seen_at      timestamptz NOT NULL DEFAULT now(),
    removed_at        timestamptz
);
CREATE UNIQUE INDEX device_software_live_uq
    ON device_software (device_id, software_id, version, arch, scope) WHERE removed_at IS NULL;
CREATE INDEX device_software_sw_idx ON device_software (software_id, version_parts) WHERE removed_at IS NULL;
CREATE INDEX device_software_device_idx ON device_software (device_id);

-- Журнал изменений инвентаризации (заполняется при сравнении снимков)
CREATE TABLE inventory_changes (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    device_id  bigint      NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    ts         timestamptz NOT NULL DEFAULT now(),
    category   text        NOT NULL CHECK (category IN ('software', 'hardware', 'disk', 'volume', 'network', 'os')),
    change     text        NOT NULL CHECK (change IN ('added', 'removed', 'changed')),
    item       text        NOT NULL,            -- «7-Zip 23.01 (x64)», «RAM», «C:»
    old_value  jsonb,
    new_value  jsonb
);
CREATE INDEX inventory_changes_device_ts_idx ON inventory_changes (device_id, ts DESC);
CREATE INDEX inventory_changes_ts_idx        ON inventory_changes (ts DESC);

-- =============================================================================
-- 4. Метрики
--    Сырые данные: партиции по суткам (UTC), хранение 14 дней (drop partition).
--    Агрегаты по часам: хранение ~13 мес. FK на devices сознательно нет:
--    лишняя проверка на каждой вставке; очистку при удалении устройства делает фоновая задача.
-- =============================================================================
CREATE TABLE metrics_host (
    device_id        bigint      NOT NULL,
    ts               timestamptz NOT NULL,     -- конец интервала усреднения (по часам сервера)
    cpu_pct          real        NOT NULL CHECK (cpu_pct BETWEEN 0 AND 100),      -- среднее за интервал
    cpu_max_pct      real        NOT NULL CHECK (cpu_max_pct BETWEEN 0 AND 100),  -- максимум 15-сек. выборок
    mem_used_bytes   bigint      NOT NULL CHECK (mem_used_bytes >= 0),
    mem_total_bytes  bigint      NOT NULL CHECK (mem_total_bytes > 0),
    mem_used_pct     real GENERATED ALWAYS AS ((mem_used_bytes * 100.0 / mem_total_bytes)::real) STORED,
    PRIMARY KEY (device_id, ts)                -- повторная отправка пачки идемпотентна (ON CONFLICT DO NOTHING)
) PARTITION BY RANGE (ts);
CREATE INDEX metrics_host_ts_brin ON metrics_host USING brin (ts);

CREATE TABLE metrics_disk (
    device_id    bigint      NOT NULL,
    ts           timestamptz NOT NULL,
    volume       text        NOT NULL,
    total_bytes  bigint      NOT NULL CHECK (total_bytes > 0),
    free_bytes   bigint      NOT NULL CHECK (free_bytes >= 0),
    free_pct     real GENERATED ALWAYS AS ((free_bytes * 100.0 / total_bytes)::real) STORED,
    PRIMARY KEY (device_id, volume, ts),
    CHECK (free_bytes <= total_bytes)
) PARTITION BY RANGE (ts);
CREATE INDEX metrics_disk_ts_brin ON metrics_disk USING brin (ts);

CREATE TABLE metrics_host_hourly (
    device_id    bigint      NOT NULL,
    hour         timestamptz NOT NULL,
    cpu_avg_pct  real        NOT NULL,
    cpu_max_pct  real        NOT NULL,
    mem_avg_pct  real        NOT NULL,
    mem_max_pct  real        NOT NULL,
    samples      smallint    NOT NULL,
    PRIMARY KEY (device_id, hour)
);

CREATE TABLE metrics_disk_hourly (
    device_id       bigint      NOT NULL,
    volume          text        NOT NULL,
    hour            timestamptz NOT NULL,
    total_bytes     bigint      NOT NULL,
    free_min_bytes  bigint      NOT NULL,
    free_min_pct    real        NOT NULL,
    PRIMARY KEY (device_id, volume, hour)
);

-- =============================================================================
-- 5. Алерты и уведомления
-- =============================================================================
CREATE TYPE alert_severity AS ENUM ('info', 'warning', 'critical');
CREATE TYPE alert_metric   AS ENUM ('cpu_pct', 'mem_used_pct', 'disk_free_pct', 'disk_free_bytes', 'offline');
CREATE TYPE channel_type   AS ENUM ('email', 'webhook');

CREATE TABLE notification_channels (
    id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name          text           NOT NULL UNIQUE,
    type          channel_type   NOT NULL,
    enabled       boolean        NOT NULL DEFAULT true,
    -- email:   {"to": ["it-alerts@corp.local"]}
    -- webhook: {"url": "https://hooks.corp.local/invmon", "timeout_s": 10}
    config        jsonb          NOT NULL,
    secret_enc    bytea,                        -- секрет HMAC для webhook: AES-256-GCM мастер-ключом сервера
    min_severity  alert_severity NOT NULL DEFAULT 'warning',
    created_at    timestamptz    NOT NULL DEFAULT now(),
    updated_at    timestamptz    NOT NULL DEFAULT now()
);
CREATE TRIGGER notification_channels_updated_at BEFORE UPDATE ON notification_channels
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE alert_rules (
    id                 bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name               text             NOT NULL,
    enabled            boolean          NOT NULL DEFAULT true,
    severity           alert_severity   NOT NULL DEFAULT 'warning',
    metric             alert_metric     NOT NULL,
    operator           text CHECK (operator IN ('>', '>=', '<', '<=')),
    threshold          double precision,
    resolve_threshold  double precision,        -- гистерезис; NULL = совпадает с threshold
    -- для метрик: условие должно держаться всё окно; для offline: сколько нет данных
    duration           interval         NOT NULL DEFAULT '0',
    volume_pattern     text,                    -- для disk_*: 'C:' или '*' (все фиксированные тома)
    scope_group_id     bigint REFERENCES device_groups (id) ON DELETE CASCADE,  -- NULL = все группы
    scope_tag          text,                    -- NULL = без фильтра по тегу
    renotify_interval  interval,                -- повтор уведомления, пока алерт активен и не подтверждён
    created_by         bigint REFERENCES users (id) ON DELETE SET NULL,
    created_at         timestamptz      NOT NULL DEFAULT now(),
    updated_at         timestamptz      NOT NULL DEFAULT now(),
    CHECK (
        (metric = 'offline' AND operator IS NULL AND threshold IS NULL AND duration > interval '0')
        OR (metric <> 'offline' AND operator IS NOT NULL AND threshold IS NOT NULL)
    ),
    CHECK ((metric IN ('disk_free_pct', 'disk_free_bytes')) = (volume_pattern IS NOT NULL))
);
CREATE TRIGGER alert_rules_updated_at BEFORE UPDATE ON alert_rules
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Сравнение «значение <оператор> порог» для движка алертов (оператор — из белого списка)
CREATE FUNCTION alert_cmp(v double precision, op text, t double precision) RETURNS boolean
LANGUAGE sql IMMUTABLE AS $$
    SELECT CASE op WHEN '>'  THEN v >  t
                   WHEN '>=' THEN v >= t
                   WHEN '<'  THEN v <  t
                   WHEN '<=' THEN v <= t END
$$;

CREATE TABLE alert_rule_channels (
    rule_id     bigint NOT NULL REFERENCES alert_rules (id) ON DELETE CASCADE,
    channel_id  bigint NOT NULL REFERENCES notification_channels (id) ON DELETE CASCADE,
    PRIMARY KEY (rule_id, channel_id)
);

CREATE TYPE alert_state AS ENUM ('firing', 'resolved');

-- Экземпляры алертов (история сохраняется и после удаления правила)
CREATE TABLE alerts (
    id                bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    rule_id           bigint REFERENCES alert_rules (id) ON DELETE SET NULL,
    device_id         bigint           NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    dimension         text             NOT NULL DEFAULT '',   -- том ('C:') для дисковых правил
    state             alert_state      NOT NULL DEFAULT 'firing',
    severity          alert_severity   NOT NULL,
    value             double precision,                       -- значение при срабатывании
    last_value        double precision,                       -- последнее вычисленное значение
    message           text             NOT NULL,
    fired_at          timestamptz      NOT NULL DEFAULT now(),
    resolved_at       timestamptz,
    acknowledged_by   bigint REFERENCES users (id) ON DELETE SET NULL,
    acknowledged_at   timestamptz,
    last_notified_at  timestamptz,
    CHECK ((state = 'resolved') = (resolved_at IS NOT NULL))
);
-- Не более одного активного алерта на (правило, устройство, том) — дедупликация
CREATE UNIQUE INDEX alerts_active_uq ON alerts (rule_id, device_id, dimension) WHERE state = 'firing';
CREATE INDEX alerts_device_idx ON alerts (device_id, fired_at DESC);
CREATE INDEX alerts_state_idx  ON alerts (state, fired_at DESC);

-- Журнал доставки уведомлений. Строка создаётся в той же транзакции, что и смена
-- состояния алерта (transactional outbox); доставку с ретраями выполняет очередь задач.
CREATE TABLE notification_log (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    alert_id    bigint REFERENCES alerts (id) ON DELETE CASCADE,
    channel_id  bigint REFERENCES notification_channels (id) ON DELETE SET NULL,
    event       text        NOT NULL CHECK (event IN ('firing', 'resolved', 'reminder', 'test')),
    status      text        NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'sent', 'failed')),
    attempts    integer     NOT NULL DEFAULT 0,
    last_error  text,
    created_at  timestamptz NOT NULL DEFAULT now(),
    sent_at     timestamptz
);
CREATE INDEX notification_log_alert_idx  ON notification_log (alert_id);
CREATE INDEX notification_log_status_idx ON notification_log (status, created_at) WHERE status <> 'sent';

-- =============================================================================
-- 6. Настройки и журнал аудита
-- =============================================================================
CREATE TABLE settings (
    key         text        PRIMARY KEY,
    value       jsonb       NOT NULL,
    updated_by  bigint      REFERENCES users (id) ON DELETE SET NULL,
    updated_at  timestamptz NOT NULL DEFAULT now()
);

-- Аудит: только INSERT/SELECT для рабочей роли, UPDATE/DELETE блокируются триггером.
-- Удаление старых данных — только DROP месячных партиций (drop_partitions_older_than).
CREATE TABLE audit_log (
    id           bigint GENERATED ALWAYS AS IDENTITY,
    ts           timestamptz NOT NULL DEFAULT now(),
    actor_type   text        NOT NULL CHECK (actor_type IN ('user', 'agent', 'system')),
    actor_id     bigint,                        -- users.id или devices.id
    actor_name   text        NOT NULL,          -- снимок логина / hostname на момент события
    action       text        NOT NULL,          -- 'user.login', 'alert_rule.update', 'agent.enroll', ...
    object_type  text,
    object_id    text,
    result       text        NOT NULL DEFAULT 'success' CHECK (result IN ('success', 'failure')),
    ip           inet,
    user_agent   text,
    details      jsonb       NOT NULL DEFAULT '{}',   -- diff «до/после»; секреты вырезаются на уровне приложения
    PRIMARY KEY (id, ts)
) PARTITION BY RANGE (ts);
CREATE INDEX audit_log_ts_idx     ON audit_log (ts DESC);
CREATE INDEX audit_log_actor_idx  ON audit_log (actor_type, actor_id, ts DESC);
CREATE INDEX audit_log_action_idx ON audit_log (action, ts DESC);
CREATE INDEX audit_log_object_idx ON audit_log (object_type, object_id, ts DESC);

CREATE FUNCTION audit_log_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only (% is not allowed)', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END $$;
CREATE TRIGGER audit_log_no_update_delete BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_append_only();

-- =============================================================================
-- 7. Обслуживание партиций (вызывается фоновой задачей сервера раз в сутки).
--    SECURITY DEFINER: рабочая роль может создавать/удалять партиции только
--    у перечисленных таблиц, не являясь их владельцем.
-- =============================================================================
CREATE FUNCTION ensure_partitions(p_parent text, p_grain text, p_start date, p_count integer)
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    v_from    date;
    v_to      date;
    v_name    text;
    v_created integer := 0;
BEGIN
    IF p_parent NOT IN ('metrics_host', 'metrics_disk', 'audit_log') THEN
        RAISE EXCEPTION 'ensure_partitions: table % is not managed', p_parent;
    END IF;
    IF p_grain NOT IN ('day', 'month') THEN
        RAISE EXCEPTION 'ensure_partitions: unknown grain %', p_grain;
    END IF;

    v_from := CASE p_grain WHEN 'month' THEN date_trunc('month', p_start)::date ELSE p_start END;
    FOR i IN 1..p_count LOOP
        v_to   := (v_from + CASE p_grain WHEN 'day' THEN interval '1 day' ELSE interval '1 month' END)::date;
        v_name := p_parent || '_p' || to_char(v_from, CASE p_grain WHEN 'day' THEN 'YYYYMMDD' ELSE 'YYYYMM' END);
        IF to_regclass('public.' || v_name) IS NULL THEN
            EXECUTE format('CREATE TABLE public.%I PARTITION OF public.%I FOR VALUES FROM (%L) TO (%L)',
                           v_name, p_parent,
                           v_from::timestamp AT TIME ZONE 'UTC',
                           v_to::timestamp   AT TIME ZONE 'UTC');
            v_created := v_created + 1;
        END IF;
        v_from := v_to;
    END LOOP;
    RETURN v_created;
END $$;

CREATE FUNCTION drop_partitions_older_than(p_parent text, p_before timestamptz)
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    r         record;
    v_upper   timestamptz;
    v_dropped integer := 0;
BEGIN
    IF p_parent NOT IN ('metrics_host', 'metrics_disk', 'audit_log') THEN
        RAISE EXCEPTION 'drop_partitions_older_than: table % is not managed', p_parent;
    END IF;
    -- Защита журнала аудита: не короче 12 месяцев, даже если приложение попросит иначе
    IF p_parent = 'audit_log' AND p_before > now() - interval '12 months' THEN
        RAISE EXCEPTION 'audit_log retention must be at least 12 months';
    END IF;

    FOR r IN
        SELECT c.oid::regclass AS part, pg_get_expr(c.relpartbound, c.oid) AS bound
        FROM pg_inherits i
        JOIN pg_class c ON c.oid = i.inhrelid
        WHERE i.inhparent = ('public.' || p_parent)::regclass
    LOOP
        v_upper := substring(r.bound FROM 'TO \(''([^'']+)''\)')::timestamptz;
        IF v_upper IS NOT NULL AND v_upper <= p_before THEN
            EXECUTE format('DROP TABLE %s', r.part);
            v_dropped := v_dropped + 1;
        END IF;
    END LOOP;
    RETURN v_dropped;
END $$;

-- Стартовые партиции: вчера + 8 дней вперёд; аудит — текущий месяц + 2 вперёд
DO $$
BEGIN
    PERFORM ensure_partitions('metrics_host', 'day',   current_date - 1, 9);
    PERFORM ensure_partitions('metrics_disk', 'day',   current_date - 1, 9);
    PERFORM ensure_partitions('audit_log',    'month', current_date,     3);
END $$;

-- =============================================================================
-- 8. Представление для списка устройств (главный экран)
-- =============================================================================
CREATE VIEW v_device_list AS
SELECT
    d.id,
    d.hostname,
    d.domain,
    d.status,
    d.group_id,
    g.name                    AS group_name,
    d.tags,
    d.os_name,
    d.os_display_version,
    d.os_arch,
    d.agent_version,
    s.last_seen_at,
    s.last_ip,
    s.cpu_pct,
    s.mem_used_pct,
    s.min_disk_free_pct,
    COALESCE(s.last_seen_at > now() - make_interval(secs => ot.threshold_s), false) AS online,
    a.critical                AS alerts_critical,
    a.warning                 AS alerts_warning
FROM devices d
LEFT JOIN device_groups g ON g.id = d.group_id
LEFT JOIN device_state  s ON s.device_id = d.id
CROSS JOIN LATERAL (
    SELECT COALESCE((SELECT (value #>> '{}')::integer FROM settings WHERE key = 'online_threshold_s'), 180) AS threshold_s
) ot
CROSS JOIN LATERAL (
    SELECT count(*) FILTER (WHERE al.severity = 'critical') AS critical,
           count(*) FILTER (WHERE al.severity = 'warning')  AS warning
    FROM alerts al
    WHERE al.device_id = d.id AND al.state = 'firing'
) a;

-- =============================================================================
-- 9. Начальные данные
-- =============================================================================
INSERT INTO settings (key, value) VALUES
    ('agent', '{
        "config_version": 1,
        "metrics_send_interval_s": 60,
        "cpu_sample_interval_s": 15,
        "disk_interval_s": 300,
        "inventory_interval_s": 3600,
        "inventory_full_resend_s": 86400,
        "collect_logged_on_user": false
     }'),
    ('retention', '{
        "metrics_raw_days": 14,
        "metrics_hourly_days": 400,
        "audit_months": 13,
        "resolved_alerts_days": 180,
        "removed_software_days": 365
     }'),
    ('online_threshold_s', '180');

INSERT INTO alert_rules (name, severity, metric, operator, threshold, resolve_threshold, duration, volume_pattern, renotify_interval) VALUES
    ('Мало места на системном диске',   'critical', 'disk_free_pct', '<',  10, 12, '0',          'C:', '24 hours'),
    ('Мало места на томе',              'warning',  'disk_free_pct', '<',  15, 17, '0',          '*',  NULL),
    ('Высокая загрузка CPU',            'warning',  'cpu_pct',       '>',  90, 80, '15 minutes', NULL, NULL),
    ('Высокое использование RAM',       'warning',  'mem_used_pct',  '>',  90, 85, '15 minutes', NULL, NULL);
INSERT INTO alert_rules (name, severity, metric, duration) VALUES
    ('Устройство не на связи',          'warning',  'offline', '10 minutes');

-- =============================================================================
-- 10. Права рабочей роли (роль создаёт установщик: CREATE ROLE invmon_app LOGIN ...)
-- =============================================================================
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'invmon_app') THEN
        GRANT USAGE ON SCHEMA public TO invmon_app;
        GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO invmon_app;
        GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO invmon_app;
        REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM invmon_app;
        REVOKE ALL ON FUNCTION ensure_partitions(text, text, date, integer) FROM PUBLIC;
        REVOKE ALL ON FUNCTION drop_partitions_older_than(text, timestamptz) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION ensure_partitions(text, text, date, integer) TO invmon_app;
        GRANT EXECUTE ON FUNCTION drop_partitions_older_than(text, timestamptz) TO invmon_app;
    END IF;
END $$;
