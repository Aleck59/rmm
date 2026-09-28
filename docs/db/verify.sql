-- =============================================================================
-- Исполняемая проверка схемы и SQL-примеров из docs/architecture.md
--
-- Запуск (суперпользователь, пустая БД; при отсутствии создаёт роли
-- invmon_owner / invmon_app без права входа):
--   createdb invmon_verify
--   psql -X -q -v ON_ERROR_STOP=1 -d invmon_verify -f docs/db/verify.sql
-- Итог: строка «ALL CHECKS PASSED» либо ошибка с текстом «FAIL: …».
-- =============================================================================
\set ON_ERROR_STOP on
SET client_min_messages = warning;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'invmon_owner') THEN
        CREATE ROLE invmon_owner NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'invmon_app') THEN
        CREATE ROLE invmon_app NOLOGIN;
    END IF;
END $$;
SELECT format('ALTER DATABASE %I OWNER TO invmon_owner', current_database()) \gexec

-- ---------------------------------------------------------------- схема (владелец)
SET ROLE invmon_owner;
\ir schema.sql

-- ---------------------------------------------------------------- тестовые данные (владелец)
INSERT INTO device_groups (name) VALUES ('Бухгалтерия'), ('ИТ');

INSERT INTO devices (agent_uid, hostname, domain, group_id, tags, os_name, os_version, os_display_version, os_arch, agent_version, token_hash)
VALUES
    ('5b7c1c7e-2f3a-4c55-9a0e-3c1f9f0d2a11', 'PC-ACC-012', 'CORP', 1, '{office-1}', 'Windows 10 Pro',         '10.0.19045.4894', '22H2', 'x64', '1.0.0', sha256('imagt_one')),
    ('6c8d2d8f-3a4b-4d66-8b1f-4d2a0a1e3b22', 'PC-ACC-015', 'CORP', 1, '{office-1}', 'Windows 7 Professional', '6.1.7601',        'SP1',  'x86', '1.0.0', sha256('imagt_two')),
    ('7d9e3e9a-4b5c-4e77-9c2a-5e3b1b2f4c33', 'PC-IT-001',  'CORP', 2, '{office-2}', 'Windows 11 Pro',         '10.0.22631.4169', '23H2', 'x64', '1.0.0', sha256('imagt_three'));

INSERT INTO device_volumes (device_id, volume, filesystem, total_bytes, free_bytes) VALUES
    (1, 'C:', 'NTFS',  255369105408,  20132659200),   -- 7.9 % свободно
    (1, 'D:', 'NTFS', 1000202039296, 600000000000),
    (2, 'C:', 'NTFS',  160039272448,  40000000000),
    (3, 'C:', 'NTFS',  510770802688, 300000000000);

INSERT INTO software (name, publisher) VALUES ('7-Zip', 'Igor Pavlov'), ('Google Chrome', 'Google LLC');
INSERT INTO device_software (device_id, software_id, display_name, version, version_parts, arch) VALUES
    (1, 1, '7-Zip 19.00 (x64)', '19.00',         '{19,0}',          'x64'),
    (2, 1, '7-Zip 23.01',       '23.01',         '{23,1}',          'x86'),
    (3, 1, '7-Zip 24.08 (x64)', '24.08',         '{24,8}',          'x64'),
    (1, 2, 'Google Chrome',     '129.0.6668.90', '{129,0,6668,90}', 'x64');

INSERT INTO audit_log (actor_type, actor_name, action) VALUES ('system', 'verify', 'verify.seed');
DO $$ BEGIN PERFORM ensure_partitions('metrics_host', 'day', current_date - 20, 3); END $$;  -- «старые» партиции

-- Под владельцем журнал аудита защищает триггер
DO $$
BEGIN
    BEGIN
        UPDATE audit_log SET action = 'tampered';
        RAISE EXCEPTION 'FAIL: owner UPDATE audit_log';
    EXCEPTION WHEN insufficient_privilege THEN NULL;
    END;
    BEGIN
        DELETE FROM audit_log;
        RAISE EXCEPTION 'FAIL: owner DELETE audit_log';
    EXCEPTION WHEN insufficient_privilege THEN NULL;
    END;
END $$;

-- ---------------------------------------------------------------- сценарий (рабочая роль сервера)
SET ROLE invmon_app;
SELECT date_trunc('minute', now()) AS t0 \gset

-- 1. Приём метрик. dev1, dev2 — 29 точек до t0; dev2 — CPU 95–99 %; dev3 — данные оборвались 30 мин назад
INSERT INTO metrics_host (device_id, ts, cpu_pct, cpu_max_pct, mem_used_bytes, mem_total_bytes)
SELECT d.id, g,
       CASE d.id WHEN 2 THEN 95 + (random() * 4)::int ELSE 12.5 END,
       CASE d.id WHEN 2 THEN 100 ELSE 40 END,
       6012345344, 8467914752
FROM (VALUES (1, 29, 1), (2, 29, 1), (3, 59, 30)) AS d(id, from_min, to_min)
CROSS JOIN LATERAL generate_series(:'t0'::timestamptz - make_interval(mins => d.from_min),
                                   :'t0'::timestamptz - make_interval(mins => d.to_min),
                                   interval '1 minute') AS g;

-- Форма запроса из сервера: пачка агента передаётся массивами
PREPARE ingest_host(bigint, timestamptz[], real[], real[], bigint[], bigint[]) AS
INSERT INTO metrics_host (device_id, ts, cpu_pct, cpu_max_pct, mem_used_bytes, mem_total_bytes)
SELECT $1, t.ts, t.cpu, t.cpu_max, t.mem_used, t.mem_total
FROM unnest($2, $3, $4, $5, $6) AS t(ts, cpu, cpu_max, mem_used, mem_total)
ON CONFLICT (device_id, ts) DO NOTHING;

EXECUTE ingest_host(1, ARRAY[:'t0'::timestamptz], '{12.5}', '{40}', '{6012345344}', '{8467914752}');
EXECUTE ingest_host(1, ARRAY[:'t0'::timestamptz], '{12.5}', '{40}', '{6012345344}', '{8467914752}');  -- повтор пачки

DO $$
BEGIN
    IF (SELECT count(*) FROM metrics_host WHERE device_id = 1) <> 30 THEN
        RAISE EXCEPTION 'FAIL: повтор пачки создал дубль';
    END IF;
    IF (SELECT round(max(mem_used_pct)::numeric, 1) FROM metrics_host WHERE device_id = 1) <> 71.0 THEN
        RAISE EXCEPTION 'FAIL: вычисляемая колонка mem_used_pct';
    END IF;
END $$;

INSERT INTO metrics_disk (device_id, ts, volume, total_bytes, free_bytes)
SELECT v.device_id, g, v.volume, v.total_bytes, v.free_bytes
FROM device_volumes v
CROSS JOIN generate_series(:'t0'::timestamptz - interval '25 minutes', :'t0'::timestamptz, interval '5 minutes') AS g
ON CONFLICT DO NOTHING;

INSERT INTO device_state (device_id, last_seen_at, last_ip, cpu_pct, mem_used_pct, mem_total_bytes, min_disk_free_pct)
SELECT d.id,
       CASE d.id WHEN 3 THEN now() - interval '30 minutes' ELSE now() END,
       '192.168.10.23', 12.5, 71.0, 8467914752,
       (SELECT min(free_pct) FROM device_volumes v WHERE v.device_id = d.id)
FROM devices d
ON CONFLICT (device_id) DO UPDATE
SET last_seen_at = EXCLUDED.last_seen_at, last_ip = EXCLUDED.last_ip, cpu_pct = EXCLUDED.cpu_pct,
    mem_used_pct = EXCLUDED.mem_used_pct, mem_total_bytes = EXCLUDED.mem_total_bytes,
    min_disk_free_pct = EXCLUDED.min_disk_free_pct;

-- 2. Список устройств
DO $$
BEGIN
    IF (SELECT string_agg(hostname || '=' || online, ',' ORDER BY hostname) FROM v_device_list)
       <> 'PC-ACC-012=true,PC-ACC-015=true,PC-IT-001=false' THEN
        RAISE EXCEPTION 'FAIL: статус online в v_device_list';
    END IF;
END $$;

-- 3. Движок алертов: нарушители трёх типов правил
DO $$
DECLARE
    v_disk text;
    v_cpu  text;
    v_off  text;
BEGIN
    -- 3a. Дисковые правила без окна: текущее состояние томов, только по «свежим» устройствам
    SELECT string_agg(rule_id || ':' || device_id || ':' || dimension, ',' ORDER BY rule_id) INTO v_disk
    FROM (
        SELECT r.id AS rule_id, v.device_id, v.volume AS dimension, v.free_pct AS value
        FROM alert_rules r
        JOIN devices d        ON d.status = 'active'
                             AND (r.scope_group_id IS NULL OR d.group_id = r.scope_group_id)
                             AND (r.scope_tag IS NULL OR r.scope_tag = ANY (d.tags))
        JOIN device_state s   ON s.device_id = d.id AND s.last_seen_at > now() - interval '15 minutes'
        JOIN device_volumes v ON v.device_id = d.id AND (r.volume_pattern = '*' OR v.volume = r.volume_pattern)
        WHERE r.enabled AND r.metric = 'disk_free_pct'
          AND alert_cmp(v.free_pct, r.operator, r.threshold)
    ) q;
    IF v_disk IS DISTINCT FROM '1:1:C:,2:1:C:' THEN
        RAISE EXCEPTION 'FAIL: нарушители дисковых правил: %', v_disk;
    END IF;

    -- 3b. Правило с окном: CPU > 90 % всё окно 15 мин (для '>' — минимум за окно)
    SELECT string_agg(rule_id || ':' || device_id, ',') INTO v_cpu
    FROM (
        SELECT r.id AS rule_id, m.device_id, '' AS dimension,
               CASE WHEN r.operator IN ('>', '>=') THEN min(m.cpu_pct) ELSE max(m.cpu_pct) END AS value
        FROM alert_rules r
        JOIN devices d      ON d.status = 'active'
                           AND (r.scope_group_id IS NULL OR d.group_id = r.scope_group_id)
                           AND (r.scope_tag IS NULL OR r.scope_tag = ANY (d.tags))
        JOIN metrics_host m ON m.device_id = d.id
                           AND m.ts > now() - r.duration AND m.ts <= now()
        WHERE r.enabled AND r.metric = 'cpu_pct'
        GROUP BY r.id, m.device_id
        HAVING count(*) >= 0.8 * extract(epoch FROM r.duration) / 60
           AND alert_cmp(CASE WHEN r.operator IN ('>', '>=') THEN min(m.cpu_pct) ELSE max(m.cpu_pct) END,
                         r.operator, r.threshold)
    ) q;
    IF v_cpu IS DISTINCT FROM '3:2' THEN
        RAISE EXCEPTION 'FAIL: нарушители правила CPU: %', v_cpu;
    END IF;

    -- 3c. Offline: нет данных дольше duration
    SELECT string_agg(rule_id || ':' || device_id, ',') INTO v_off
    FROM (
        SELECT r.id AS rule_id, d.id AS device_id
        FROM alert_rules r
        JOIN devices d      ON d.status = 'active'
                           AND (r.scope_group_id IS NULL OR d.group_id = r.scope_group_id)
                           AND (r.scope_tag IS NULL OR r.scope_tag = ANY (d.tags))
        JOIN device_state s ON s.device_id = d.id
        WHERE r.enabled AND r.metric = 'offline' AND s.last_seen_at < now() - r.duration
    ) q;
    IF v_off IS DISTINCT FROM '5:3' THEN
        RAISE EXCEPTION 'FAIL: нарушители offline: %', v_off;
    END IF;
END $$;

-- 3d. Открытие алертов и дедупликация, 3e. закрытие с гистерезисом
DO $$
DECLARE
    n integer;
BEGIN
    WITH ins AS (
        INSERT INTO alerts (rule_id, device_id, dimension, severity, value, last_value, message)
        VALUES (1, 1, 'C:', 'critical', 7.9, 7.9,  'PC-ACC-012: свободно на C: 7.9% (порог < 10%)'),
               (2, 1, 'C:', 'warning',  7.9, 7.9,  'PC-ACC-012: свободно на C: 7.9% (порог < 15%)'),
               (3, 2, '',   'warning',  95,  95,   'PC-ACC-015: CPU > 90% 15 мин'),
               (5, 3, '',   'warning',  1800, 1800, 'PC-IT-001: нет данных 30 мин')
        ON CONFLICT (rule_id, device_id, dimension) WHERE state = 'firing' DO NOTHING
        RETURNING 1)
    SELECT count(*) INTO n FROM ins;
    IF n <> 4 THEN RAISE EXCEPTION 'FAIL: открыто % алертов вместо 4', n; END IF;

    WITH ins AS (
        INSERT INTO alerts (rule_id, device_id, dimension, severity, value, last_value, message)
        VALUES (1, 1, 'C:', 'critical', 7.8, 7.8, 'повтор')
        ON CONFLICT (rule_id, device_id, dimension) WHERE state = 'firing' DO NOTHING
        RETURNING 1)
    SELECT count(*) INTO n FROM ins;
    IF n <> 0 THEN RAISE EXCEPTION 'FAIL: дубль активного алерта'; END IF;

    -- освободили до 11 % — ещё рано (resolve_threshold = 12)
    UPDATE device_volumes SET free_bytes = (total_bytes * 0.11)::bigint WHERE device_id = 1 AND volume = 'C:';
    WITH upd AS (
        UPDATE alerts a
        SET state = 'resolved', resolved_at = now(), last_value = v.free_pct
        FROM alert_rules r, device_volumes v
        WHERE a.rule_id = r.id AND r.id = 1 AND a.state = 'firing'
          AND v.device_id = a.device_id AND v.volume = a.dimension
          AND NOT alert_cmp(v.free_pct, r.operator, COALESCE(r.resolve_threshold, r.threshold))
        RETURNING 1)
    SELECT count(*) INTO n FROM upd;
    IF n <> 0 THEN RAISE EXCEPTION 'FAIL: алерт закрылся до порога гистерезиса'; END IF;

    -- освободили до 13 % — закрываем
    UPDATE device_volumes SET free_bytes = (total_bytes * 0.13)::bigint WHERE device_id = 1 AND volume = 'C:';
    WITH upd AS (
        UPDATE alerts a
        SET state = 'resolved', resolved_at = now(), last_value = v.free_pct
        FROM alert_rules r, device_volumes v
        WHERE a.rule_id = r.id AND r.id = 1 AND a.state = 'firing'
          AND v.device_id = a.device_id AND v.volume = a.dimension
          AND NOT alert_cmp(v.free_pct, r.operator, COALESCE(r.resolve_threshold, r.threshold))
        RETURNING 1)
    SELECT count(*) INTO n FROM upd;
    IF n <> 1 THEN RAISE EXCEPTION 'FAIL: алерт не закрылся после порога гистерезиса'; END IF;

    IF (SELECT alerts_warning FROM v_device_list WHERE hostname = 'PC-ACC-012') <> 1 THEN
        RAISE EXCEPTION 'FAIL: счётчик активных алертов в v_device_list';
    END IF;
END $$;

-- 4. Часовые агрегаты и данные для графика
INSERT INTO metrics_host_hourly (device_id, hour, cpu_avg_pct, cpu_max_pct, mem_avg_pct, mem_max_pct, samples)
SELECT device_id, date_trunc('hour', ts, 'UTC'), avg(cpu_pct), max(cpu_max_pct), avg(mem_used_pct), max(mem_used_pct), count(*)
FROM metrics_host
WHERE ts >= date_trunc('hour', :'t0'::timestamptz, 'UTC') - interval '1 hour'
  AND ts <  date_trunc('hour', :'t0'::timestamptz, 'UTC') + interval '1 hour'
GROUP BY 1, 2
ON CONFLICT (device_id, hour) DO UPDATE
SET cpu_avg_pct = EXCLUDED.cpu_avg_pct, cpu_max_pct = EXCLUDED.cpu_max_pct,
    mem_avg_pct = EXCLUDED.mem_avg_pct, mem_max_pct = EXCLUDED.mem_max_pct, samples = EXCLUDED.samples;

DO $$
BEGIN
    -- все тестовые выборки лежат в пределах часа до t0, т.е. целиком внутри окна агрегации
    IF (SELECT sum(samples) FROM metrics_host_hourly) <> (SELECT count(*) FROM metrics_host) THEN
        RAISE EXCEPTION 'FAIL: часовые агрегаты не сходятся с сырыми данными';
    END IF;
    IF NOT EXISTS (
        SELECT date_bin('15 minutes', ts, TIMESTAMPTZ '2000-01-01 00:00:00+00') AS bucket,
               avg(cpu_pct), max(cpu_max_pct), avg(mem_used_pct)
        FROM metrics_host
        WHERE device_id = 2 AND ts >= now() - interval '2 days' AND ts < now()
        GROUP BY bucket) THEN
        RAISE EXCEPTION 'FAIL: запрос для графика пуст';
    END IF;
END $$;

-- 5. Отчёты по ПО и история версий
DO $$
BEGIN
    IF (SELECT string_agg(d.hostname, ',')
        FROM device_software ds
        JOIN software s ON s.id = ds.software_id
        JOIN devices  d ON d.id = ds.device_id
        WHERE ds.removed_at IS NULL AND s.name = '7-Zip' AND ds.version_parts < ARRAY[23, 1]) <> 'PC-ACC-012' THEN
        RAISE EXCEPTION 'FAIL: отчёт «7-Zip старше 23.01»';
    END IF;

    -- обновление версии: закрыть старую строку, добавить новую
    UPDATE device_software SET removed_at = now()
    WHERE device_id = 1 AND software_id = 1 AND removed_at IS NULL AND version <> '24.08';
    INSERT INTO device_software (device_id, software_id, display_name, version, version_parts, arch)
    VALUES (1, 1, '7-Zip 24.08 (x64)', '24.08', '{24,8}', 'x64')
    ON CONFLICT (device_id, software_id, version, arch, scope) WHERE removed_at IS NULL
    DO UPDATE SET last_seen_at = now();
    INSERT INTO inventory_changes (device_id, category, change, item, old_value, new_value)
    VALUES (1, 'software', 'changed', '7-Zip', '{"version": "19.00"}', '{"version": "24.08"}');

    IF (SELECT count(*) FILTER (WHERE removed_at IS NULL) || '/' || count(*)
        FROM device_software WHERE device_id = 1 AND software_id = 1) <> '1/2' THEN
        RAISE EXCEPTION 'FAIL: история версий ПО';
    END IF;
    IF (SELECT count(DISTINCT ds.device_id) FROM device_software ds
        WHERE ds.software_id = 1 AND ds.removed_at IS NULL) <> 3 THEN
        RAISE EXCEPTION 'FAIL: каталог ПО';
    END IF;
END $$;

-- 6. Аудит: рабочая роль может только дописывать
INSERT INTO audit_log (actor_type, actor_id, actor_name, action, object_type, object_id, ip, details)
VALUES ('user', 1, 'admin', 'alert_rule.update', 'alert_rule', '1', '10.10.0.15',
        '{"before": {"threshold": 10}, "after": {"threshold": 8}}');
DO $$
BEGIN
    BEGIN
        UPDATE audit_log SET action = 'tampered';
        RAISE EXCEPTION 'FAIL: app UPDATE audit_log';
    EXCEPTION WHEN insufficient_privilege THEN NULL;
    END;
    BEGIN
        DELETE FROM audit_log;
        RAISE EXCEPTION 'FAIL: app DELETE audit_log';
    EXCEPTION WHEN insufficient_privilege THEN NULL;
    END;
    BEGIN
        TRUNCATE audit_log;
        RAISE EXCEPTION 'FAIL: app TRUNCATE audit_log';
    EXCEPTION WHEN insufficient_privilege THEN NULL;
    END;
END $$;

-- 7. Партиции: рабочая роль управляет ими только через функции с белым списком
DO $$
BEGIN
    IF ensure_partitions('metrics_host', 'day', current_date, 3) <> 0 THEN
        RAISE EXCEPTION 'FAIL: ensure_partitions не идемпотентна';
    END IF;
    IF drop_partitions_older_than('metrics_host', now() - interval '14 days') <> 3 THEN
        RAISE EXCEPTION 'FAIL: старые партиции не удалены';
    END IF;
    BEGIN
        PERFORM drop_partitions_older_than('audit_log', now() - interval '1 month');
        RAISE EXCEPTION 'FAIL: аудит можно удалить раньше 12 месяцев';
    EXCEPTION WHEN raise_exception THEN
        IF SQLERRM LIKE 'FAIL%' THEN RAISE; END IF;
    END;
    BEGIN
        PERFORM ensure_partitions('users', 'day', current_date, 1);
        RAISE EXCEPTION 'FAIL: функция приняла таблицу не из белого списка';
    EXCEPTION WHEN raise_exception THEN
        IF SQLERRM LIKE 'FAIL%' THEN RAISE; END IF;
    END;
    BEGIN
        CREATE TABLE metrics_host_hack PARTITION OF metrics_host
            FOR VALUES FROM ('2030-01-01') TO ('2030-01-02');
        RAISE EXCEPTION 'FAIL: рабочая роль создала партицию напрямую';
    EXCEPTION WHEN insufficient_privilege THEN NULL;
    END;
END $$;

-- 8. Ограничения целостности правил
DO $$
BEGIN
    BEGIN
        INSERT INTO alert_rules (name, metric, operator, threshold, duration) VALUES ('bad', 'offline', '>', 5, '5 minutes');
        RAISE EXCEPTION 'FAIL: offline-правило с порогом принято';
    EXCEPTION WHEN check_violation THEN NULL;
    END;
    BEGIN
        INSERT INTO alert_rules (name, metric, operator, threshold) VALUES ('bad', 'disk_free_pct', '<', 10);
        RAISE EXCEPTION 'FAIL: дисковое правило без тома принято';
    EXCEPTION WHEN check_violation THEN NULL;
    END;
END $$;

RESET ROLE;
\echo 'ALL CHECKS PASSED'
