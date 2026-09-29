-- =============================================================================
-- Исполняемая проверка схемы и SQL-примеров из docs/architecture.md,
-- а также проекта модуля выполнения (schema_execution.sql, docs/execution.md)
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

-- =============================================================================
-- Модуль выполнения скриптов и управления ПО (проект v2.0, docs/execution.md)
-- =============================================================================

-- ---------------------------------------------------------------- схема модуля (владелец)
RESET ROLE;
SET ROLE invmon_owner;
\ir schema_execution.sql

INSERT INTO users (username, display_name, password_hash, role) VALUES
    ('admin',   'Администратор ИТ', 'x', 'admin'),
    ('petrov',  'Петров П. П.',     'x', 'operator'),   -- автор скриптов и пакетов
    ('ivanov',  'Иванов И. И.',     'x', 'operator'),   -- согласующий
    ('sidorov', 'Сидоров С. С.',    'x', 'operator');   -- оператор группы «Бухгалтерия»

-- ---------------------------------------------------------------- сценарий модуля (рабочая роль сервера)
SET ROLE invmon_app;

CREATE FUNCTION pg_temp.uid(p_username text) RETURNS bigint
LANGUAGE sql STABLE AS $$ SELECT id FROM users WHERE username = p_username $$;

CREATE FUNCTION pg_temp.expect(p_what text, p_ok boolean) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
    IF p_ok IS NOT TRUE THEN
        RAISE EXCEPTION 'FAIL: %', p_what;
    END IF;
END $$;

-- p_sql должен быть отклонён с кодом p_state; его изменения откатываются
CREATE FUNCTION pg_temp.expect_fail(p_what text, p_state text, p_sql text) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
    BEGIN
        EXECUTE p_sql;
    EXCEPTION WHEN OTHERS THEN
        IF SQLSTATE <> p_state THEN
            RAISE EXCEPTION 'FAIL: % — ожидался SQLSTATE %, получен %: %', p_what, p_state, SQLSTATE, SQLERRM;
        END IF;
        RETURN;
    END;
    RAISE EXCEPTION 'FAIL: % — операция не отклонена', p_what;
END $$;

-- INSERT подписи. Байты подписи — заглушка: ECDSA проверяют сервер и агент, БД —
-- принадлежность ключа, роль подписанта и манифест.
CREATE FUNCTION pg_temp.sign(p_subject text, p_id bigint, p_role text, p_user text, p_key text, p_sha bytea) RETURNS text
LANGUAGE sql STABLE AS $$
    SELECT format('INSERT INTO signatures (%I, role, signer_id, signing_key_id, signed_sha256, signature) VALUES (%s, %L, %s, %s, %L, %L)',
                  p_subject, p_id, p_role, pg_temp.uid(p_user),
                  (SELECT id FROM signing_keys WHERE name = p_key), p_sha, '\x3045022100'::bytea)
$$;

-- E1. Права модуля и ключи подписантов
DO $$
DECLARE
    u_admin   bigint := pg_temp.uid('admin');
    u_petrov  bigint := pg_temp.uid('petrov');
    u_ivanov  bigint := pg_temp.uid('ivanov');
    u_sidorov bigint := pg_temp.uid('sidorov');
    g_acc     bigint := (SELECT id FROM device_groups WHERE name = 'Бухгалтерия');
    g_it      bigint := (SELECT id FROM device_groups WHERE name = 'ИТ');
BEGIN
    INSERT INTO user_permissions (user_id, permission, scope_group_id, granted_by) VALUES
        (u_admin,   'execution.admin',        NULL,  NULL),      -- первичная выдача: CLI на сервере
        (u_petrov,  'script.author',          NULL,  u_admin),
        (u_petrov,  'script.approve',         NULL,  u_admin),   -- в маленькой команде автор согласует чужое,
        (u_petrov,  'package.manage',         NULL,  u_admin),   -- но не своё: это проверяет подпись, не право
        (u_ivanov,  'script.approve',         NULL,  u_admin),
        (u_ivanov,  'package.approve',        NULL,  u_admin),
        (u_sidorov, 'script.run',             g_acc, u_admin),
        (u_sidorov, 'script.run_high_impact', g_acc, u_admin),
        (u_sidorov, 'deployment.run',         g_acc, u_admin);

    PERFORM pg_temp.expect_fail('право самому себе', '23514', format(
        $q$INSERT INTO user_permissions (user_id, permission, granted_by) VALUES (%s, 'script.run', %s)$q$, u_admin, u_admin));
    PERFORM pg_temp.expect_fail('дубль права на весь парк', '23505', format(
        $q$INSERT INTO user_permissions (user_id, permission, granted_by) VALUES (%s, 'script.approve', %s)$q$, u_ivanov, u_admin));
    PERFORM pg_temp.expect('право в своей группе',             has_permission(u_sidorov, 'script.run', g_acc));
    PERFORM pg_temp.expect('нет права в чужой группе',         NOT has_permission(u_sidorov, 'script.run', g_it));
    PERFORM pg_temp.expect('нет права на ПК без группы',       NOT has_permission(u_sidorov, 'script.run', NULL));
    PERFORM pg_temp.expect('роль admin не даёт права запуска', NOT has_permission(u_admin, 'script.run', g_acc));

    INSERT INTO signing_keys (owner_id, name, public_key, fingerprint) VALUES
        (u_petrov,  'YubiKey Петрова',     'spki-petrov',     encode(sha256('spki-petrov'), 'hex')),
        (u_ivanov,  'YubiKey Иванова',     'spki-ivanov',     encode(sha256('spki-ivanov'), 'hex')),
        (u_ivanov,  'Старый ключ Иванова', 'spki-ivanov-old', encode(sha256('spki-ivanov-old'), 'hex')),
        (u_sidorov, 'YubiKey Сидорова',    'spki-sidorov',    encode(sha256('spki-sidorov'), 'hex'));
    UPDATE signing_keys SET revoked_at = now() WHERE name = 'Старый ключ Иванова';

    PERFORM pg_temp.expect_fail('отмена отзыва ключа', '23000',
        $q$UPDATE signing_keys SET revoked_at = NULL WHERE name = 'Старый ключ Иванова'$q$);
    PERFORM pg_temp.expect_fail('подмена открытого ключа', '42501',
        $q$UPDATE signing_keys SET public_key = '\x00' WHERE name = 'YubiKey Иванова'$q$);
    PERFORM pg_temp.expect_fail('удаление ключа', '42501', 'DELETE FROM signing_keys');
END $$;

-- E2. Скрипт: черновик → отправка (манифест) → подписи автора и согласующего → одобрен
DO $$
DECLARE
    u_petrov  bigint := pg_temp.uid('petrov');
    s_id      bigint;
    v1        bigint;
    body      text  := 'Get-ChildItem "$env:SystemRoot\Temp" | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue';
    m         bytea := convert_to('{"type":"invmon.script.v1","script":"Очистка временных файлов Windows","version":1}', 'UTF8');
BEGIN
    INSERT INTO scripts (name, category, interpreter, created_by)
    VALUES ('Очистка временных файлов Windows', 'обслуживание', 'powershell', u_petrov)
    RETURNING id INTO s_id;
    INSERT INTO script_versions (script_id, version, content, content_sha256, author_id)
    VALUES (s_id, 1, body, sha256(convert_to(body, 'UTF8')), u_petrov)
    RETURNING id INTO v1;
    PERFORM pg_temp.expect('интерпретатор и high_impact скопированы из скрипта',
        (SELECT interpreter = 'powershell' AND NOT high_impact FROM script_versions WHERE id = v1));

    UPDATE script_versions SET timeout_s = 900 WHERE id = v1;              -- черновик можно править
    PERFORM pg_temp.expect_fail('новая версия сразу одобрена', '23000', format(
        $q$INSERT INTO script_versions (script_id, version, content, content_sha256, author_id, status, manifest, manifest_sha256)
           VALUES (%s, 99, 'x', sha256('x'), %s, 'approved', 'm', sha256('m'))$q$, s_id, u_petrov));
    PERFORM pg_temp.expect_fail('подпись черновика', '23000',
        pg_temp.sign('script_version_id', v1, 'author', 'petrov', 'YubiKey Петрова', sha256(m)));
    PERFORM pg_temp.expect_fail('черновик сразу в approved', '23000',
        format($q$UPDATE script_versions SET status = 'approved' WHERE id = %s$q$, v1));

    UPDATE script_versions
    SET status = 'pending_approval', manifest = m, manifest_sha256 = sha256(m), submitted_at = now()
    WHERE id = v1;
    PERFORM pg_temp.expect_fail('правка кода после отправки', '23000',
        format($q$UPDATE script_versions SET content = 'Format-Volume -DriveLetter C' WHERE id = %s$q$, v1));
    PERFORM pg_temp.expect_fail('правка ограничений после отправки', '23000',
        format($q$UPDATE script_versions SET run_as = 'local_service' WHERE id = %s$q$, v1));
    PERFORM pg_temp.expect_fail('одобрение без подписей', '23000',
        format($q$UPDATE script_versions SET status = 'approved' WHERE id = %s$q$, v1));

    PERFORM pg_temp.expect_fail('автор подписывает как согласующий', '23000',
        pg_temp.sign('script_version_id', v1, 'approver', 'petrov', 'YubiKey Петрова', sha256(m)));
    PERFORM pg_temp.expect_fail('согласующий подписывает как автор', '23000',
        pg_temp.sign('script_version_id', v1, 'author', 'ivanov', 'YubiKey Иванова', sha256(m)));
    PERFORM pg_temp.expect_fail('подпись чужим ключом', '23000',
        pg_temp.sign('script_version_id', v1, 'approver', 'ivanov', 'YubiKey Петрова', sha256(m)));
    PERFORM pg_temp.expect_fail('подпись отозванным ключом', '23000',
        pg_temp.sign('script_version_id', v1, 'approver', 'ivanov', 'Старый ключ Иванова', sha256(m)));
    PERFORM pg_temp.expect_fail('подпись другого манифеста', '23000',
        pg_temp.sign('script_version_id', v1, 'approver', 'ivanov', 'YubiKey Иванова', sha256('other')));
    PERFORM pg_temp.expect_fail('согласующий без права согласования', '42501',
        pg_temp.sign('script_version_id', v1, 'approver', 'sidorov', 'YubiKey Сидорова', sha256(m)));

    EXECUTE pg_temp.sign('script_version_id', v1, 'author', 'petrov', 'YubiKey Петрова', sha256(m));
    PERFORM pg_temp.expect_fail('вторая подпись того же человека', '23505',
        pg_temp.sign('script_version_id', v1, 'author', 'petrov', 'YubiKey Петрова', sha256(m)));
    PERFORM pg_temp.expect_fail('одобрение только с подписью автора', '23000',
        format($q$UPDATE script_versions SET status = 'approved' WHERE id = %s$q$, v1));
    EXECUTE pg_temp.sign('script_version_id', v1, 'approver', 'ivanov', 'YubiKey Иванова', sha256(m));
    UPDATE script_versions SET status = 'approved', decided_at = now() WHERE id = v1;

    PERFORM pg_temp.expect_fail('возврат одобренной версии в черновик', '23000',
        format($q$UPDATE script_versions SET status = 'draft' WHERE id = %s$q$, v1));
    PERFORM pg_temp.expect_fail('удаление одобренной версии', '23000',
        format('DELETE FROM script_versions WHERE id = %s', v1));
    PERFORM pg_temp.expect_fail('подпись уже одобренной версии', '23000',
        pg_temp.sign('script_version_id', v1, 'approver', 'sidorov', 'YubiKey Сидорова', sha256(m)));
    PERFORM pg_temp.expect_fail('удаление подписи', '42501', 'DELETE FROM signatures');
    PERFORM pg_temp.expect_fail('правка подписи', '42501', $q$UPDATE signatures SET comment = 'x'$q$);
END $$;

-- E3. Запуск: постановка по области прав, выдача агенту, машина состояний, отмена
DO $$
DECLARE
    u_petrov  bigint := pg_temp.uid('petrov');
    u_sidorov bigint := pg_temp.uid('sidorov');
    v1        bigint := (SELECT v.id FROM script_versions v JOIN scripts s ON s.id = v.script_id
                         WHERE s.name = 'Очистка временных файлов Windows' AND v.version = 1);
    v2        bigint;
    r1        bigint;
    t1        bigint;
BEGIN
    INSERT INTO script_versions (script_id, version, content, content_sha256, author_id)
    SELECT script_id, 2, content || ' # v2', sha256(convert_to(content || ' # v2', 'UTF8')), u_petrov
    FROM script_versions WHERE id = v1
    RETURNING id INTO v2;
    PERFORM pg_temp.expect_fail('запуск неодобренной версии', '23000', format(
        $q$INSERT INTO script_runs (script_version_id, target_spec, target_count, status, reason, created_by, expires_at)
           VALUES (%s, '{"group_id": 1}', 2, 'scheduled', 'INC-1024: очистка', %s, now() + interval '1 day')$q$, v2, u_sidorov));
    PERFORM pg_temp.expect_fail('запуск без обоснования', '23514', format(
        $q$INSERT INTO script_runs (script_version_id, target_spec, target_count, status, reason, created_by, expires_at)
           VALUES (%s, '{"group_id": 1}', 2, 'scheduled', '  ', %s, now() + interval '1 day')$q$, v1, u_sidorov));

    INSERT INTO script_runs (script_version_id, target_spec, target_count, status, reason, created_by, expires_at, max_concurrency)
    VALUES (v1, '{"group_id": 1}', 2, 'scheduled', 'INC-1024: мало места на C: у бухгалтерии', u_sidorov,
            now() + interval '1 day', 10)
    RETURNING id INTO r1;

    -- Раскладка по ПК: 1 и 2 — «Бухгалтерия» (область прав Сидорова), 3 — «ИТ»
    INSERT INTO agent_tasks (device_id, kind, script_run_id) VALUES (1, 'script', r1), (2, 'script', r1);
    PERFORM pg_temp.expect_fail('ПК вне области прав инициатора', '42501',
        format($q$INSERT INTO agent_tasks (device_id, kind, script_run_id) VALUES (3, 'script', %s)$q$, r1));
    PERFORM pg_temp.expect_fail('вторая задача запуска на тот же ПК', '23505',
        format($q$INSERT INTO agent_tasks (device_id, kind, script_run_id) VALUES (1, 'script', %s)$q$, r1));
    PERFORM pg_temp.expect_fail('задача сразу в работе', '23000',
        format($q$INSERT INTO agent_tasks (device_id, kind, script_run_id, state) VALUES (3, 'script', %s, 'running')$q$, r1));

    -- Выдача: модуль выключен по умолчанию, ПК без локального разрешения задач не получает, стоп-кран
    PERFORM pg_temp.expect('модуль выключен — выдачи нет', (SELECT count(*) FROM claim_agent_tasks(1, 600, 5)) = 0);
    UPDATE settings SET value = value || '{"enabled": true}' WHERE key = 'execution';
    PERFORM pg_temp.expect('ПК не сообщил о возможностях — выдачи нет', (SELECT count(*) FROM claim_agent_tasks(1, 600, 5)) = 0);
    INSERT INTO device_execution_capabilities (device_id, scripts_enabled, packages_enabled, powershell_version) VALUES
        (1, false, false, '5.1'), (2, true, true, '2.0');
    PERFORM pg_temp.expect('скрипты выключены локальной политикой ПК — выдачи нет',
        (SELECT count(*) FROM claim_agent_tasks(1, 600, 5)) = 0);
    UPDATE device_execution_capabilities SET scripts_enabled = true, packages_enabled = true WHERE device_id = 1;
    UPDATE settings SET value = value || '{"paused": true}' WHERE key = 'execution';
    PERFORM pg_temp.expect('стоп-кран — выдачи нет', (SELECT count(*) FROM claim_agent_tasks(1, 600, 5)) = 0);
    UPDATE settings SET value = value || '{"paused": false}' WHERE key = 'execution';

    SELECT id INTO t1 FROM claim_agent_tasks(1, 600, 5);
    PERFORM pg_temp.expect('ПК 1 получил задачу', t1 IS NOT NULL);
    PERFORM pg_temp.expect('повторная выдача пуста', (SELECT count(*) FROM claim_agent_tasks(1, 600, 5)) = 0);
    PERFORM pg_temp.expect('запуск перешёл в running', (SELECT status FROM script_runs WHERE id = r1) = 'running');

    PERFORM pg_temp.expect_fail('dispatched → succeeded без подтверждения старта', '23000',
        format($q$UPDATE agent_tasks SET state = 'succeeded', finished_at = now() WHERE id = %s$q$, t1));
    UPDATE agent_tasks SET state = 'running', started_at = now(), lease_expires_at = now() + interval '20 minutes' WHERE id = t1;
    PERFORM pg_temp.expect_fail('итог без времени завершения', '23514',
        format($q$UPDATE agent_tasks SET state = 'succeeded' WHERE id = %s$q$, t1));
    UPDATE agent_tasks
    SET state = 'succeeded', finished_at = now(), exit_code = 0,
        stdout = 'Удалено файлов: 1532, освобождено 2,1 ГБ', output_bytes = 60, last_output_seq = 1
    WHERE id = t1;
    PERFORM pg_temp.expect_fail('переписать код возврата', '23000',
        format('UPDATE agent_tasks SET exit_code = 1 WHERE id = %s', t1));
    PERFORM pg_temp.expect_fail('завершённая задача снова в работе', '23000',
        format($q$UPDATE agent_tasks SET state = 'running' WHERE id = %s$q$, t1));
    UPDATE agent_tasks SET stdout = '', stderr = '', output_purged_at = now() WHERE id = t1;   -- очистка вывода по сроку
    PERFORM pg_temp.expect_fail('удаление истории задач', '42501', 'DELETE FROM agent_tasks');
    PERFORM pg_temp.expect_fail('удаление запуска', '42501', 'DELETE FROM script_runs');
    PERFORM pg_temp.expect_fail('подмена параметров запуска', '23000',
        format($q$UPDATE script_runs SET parameters = '{"path": "C:\\Users"}' WHERE id = %s$q$, r1));

    -- Отмена (как в docs/execution.md, 10.4): в очереди и выданные, но не начатые — сразу
    -- (двухфазный старт не даст агенту начать); выполняемым — флаг для агента
    UPDATE script_runs SET status = 'canceled', cancel_requested_at = now(), canceled_by = u_sidorov WHERE id = r1;
    UPDATE agent_tasks SET state = 'canceled', finished_at = now()
    WHERE script_run_id = r1 AND state IN ('queued', 'dispatched');
    UPDATE agent_tasks SET cancel_requested = true WHERE script_run_id = r1 AND state = 'running';
    PERFORM pg_temp.expect('отменённый запуск не выдаётся', (SELECT count(*) FROM claim_agent_tasks(2, 600, 5)) = 0);
    PERFORM pg_temp.expect_fail('отменённый запуск снова в работе', '23000',
        format($q$UPDATE script_runs SET status = 'running' WHERE id = %s$q$, r1));
    PERFORM reap_agent_tasks(3);
    PERFORM pg_temp.expect('сводка отменённого запуска', (
        SELECT (status, tasks, succeeded, canceled_or_expired, queued, in_progress) = ('canceled'::job_status, 2, 1, 1, 0, 0)
        FROM v_job_summary WHERE job_type = 'script_run' AND job_id = r1));
    PERFORM pg_temp.expect('время завершения отменённого запуска',
        (SELECT finished_at IS NOT NULL FROM script_runs WHERE id = r1));
END $$;

-- E4. high_impact: запуск подписывают инициатор и согласующий; аренда, lost, поздний результат
DO $$
DECLARE
    u_petrov  bigint := pg_temp.uid('petrov');
    u_sidorov bigint := pg_temp.uid('sidorov');
    s_hi      bigint;
    v_hi      bigint;
    r_hi      bigint;
    body      text  := 'Stop-Service wuauserv, bits -Force; Remove-Item "$env:SystemRoot\SoftwareDistribution\Download\*" -Recurse -Force; Start-Service wuauserv, bits';
    m         bytea := convert_to('{"type":"invmon.script.v1","script":"Сброс кэша Windows Update","version":1,"high_impact":true}', 'UTF8');
    rm        bytea := convert_to('{"type":"invmon.run.v1","devices":["6c8d2d8f-3a4b-4d66-8b1f-4d2a0a1e3b22"],"parameters":{}}', 'UTF8');
BEGIN
    INSERT INTO scripts (name, category, interpreter, high_impact, created_by)
    VALUES ('Сброс кэша Windows Update', 'обслуживание', 'powershell', true, u_petrov)
    RETURNING id INTO s_hi;
    -- версию можно создать сразу на согласование
    INSERT INTO script_versions (script_id, version, content, content_sha256, author_id, status, manifest, manifest_sha256, submitted_at)
    VALUES (s_hi, 1, body, sha256(convert_to(body, 'UTF8')), u_petrov, 'pending_approval', m, sha256(m), now())
    RETURNING id INTO v_hi;
    EXECUTE pg_temp.sign('script_version_id', v_hi, 'author', 'petrov', 'YubiKey Петрова', sha256(m));
    EXECUTE pg_temp.sign('script_version_id', v_hi, 'approver', 'ivanov', 'YubiKey Иванова', sha256(m));
    UPDATE script_versions SET status = 'approved', decided_at = now() WHERE id = v_hi;

    PERFORM pg_temp.expect_fail('high_impact без согласования запуска', '23000', format(
        $q$INSERT INTO script_runs (script_version_id, target_spec, target_count, status, reason, created_by, expires_at)
           VALUES (%s, '{"device_ids": [2]}', 1, 'scheduled', 'INC-1040: не ставятся обновления', %s, now() + interval '1 day')$q$,
        v_hi, u_sidorov));
    INSERT INTO script_runs (script_version_id, target_spec, target_count, status, reason, created_by, expires_at,
                             run_manifest, run_manifest_sha256)
    VALUES (v_hi, '{"device_ids": [2]}', 1, 'pending_approval', 'INC-1040: не ставятся обновления', u_sidorov,
            now() + interval '1 day', rm, sha256(rm))
    RETURNING id INTO r_hi;
    INSERT INTO agent_tasks (device_id, kind, script_run_id) VALUES (2, 'script', r_hi);
    PERFORM pg_temp.expect('до согласования не выдаётся', (SELECT count(*) FROM claim_agent_tasks(2, 600, 5)) = 0);
    PERFORM pg_temp.expect_fail('согласование без подписей', '23000',
        format($q$UPDATE script_runs SET status = 'scheduled' WHERE id = %s$q$, r_hi));
    EXECUTE pg_temp.sign('script_run_id', r_hi, 'author', 'sidorov', 'YubiKey Сидорова', sha256(rm));
    PERFORM pg_temp.expect_fail('инициатор согласует свой запуск', '23000',
        pg_temp.sign('script_run_id', r_hi, 'approver', 'sidorov', 'YubiKey Сидорова', sha256(rm)));
    EXECUTE pg_temp.sign('script_run_id', r_hi, 'approver', 'ivanov', 'YubiKey Иванова', sha256(rm));
    UPDATE script_runs SET status = 'scheduled' WHERE id = r_hi;
    PERFORM pg_temp.expect('после согласования выдаётся', (SELECT count(*) FROM claim_agent_tasks(2, 600, 5)) = 1);

    -- агент не подтвердил старт за время аренды → задача снова в очереди
    UPDATE agent_tasks SET lease_expires_at = now() - interval '1 second' WHERE script_run_id = r_hi;
    PERFORM reap_agent_tasks(3);
    PERFORM pg_temp.expect('неподтверждённая выдача вернулась в очередь',
        (SELECT state = 'queued' AND attempt = 1 FROM agent_tasks WHERE script_run_id = r_hi));

    -- вторая выдача; старт подтверждён; агент пропал дольше таймаута → lost; поздний результат принят
    PERFORM pg_temp.expect('вторая выдача', (SELECT attempt FROM claim_agent_tasks(2, 600, 5)) = 2);
    UPDATE agent_tasks SET state = 'running', started_at = now(), lease_expires_at = now() - interval '1 second'
    WHERE script_run_id = r_hi;
    PERFORM reap_agent_tasks(3);
    PERFORM pg_temp.expect('зависшая задача — lost', (SELECT state FROM agent_tasks WHERE script_run_id = r_hi) = 'lost');
    PERFORM pg_temp.expect('запуск без открытых задач завершён',
        (SELECT status = 'completed' AND finished_at IS NOT NULL FROM script_runs WHERE id = r_hi));
    UPDATE agent_tasks SET state = 'succeeded', exit_code = 0, finished_at = now() WHERE script_run_id = r_hi;
    PERFORM pg_temp.expect('поздний результат учтён в сводке',
        (SELECT succeeded = 1 AND lost = 0 FROM v_job_summary WHERE job_type = 'script_run' AND job_id = r_hi));
END $$;

-- E5. Окно обслуживания (время — в поясе окна; 2026-09-28 — понедельник)
DO $$
DECLARE
    w jsonb := '{"days": ["mon", "tue", "wed", "thu", "fri"], "from": "20:00", "to": "06:00", "tz": "Europe/Moscow"}';
BEGIN
    PERFORM pg_temp.expect('пн 21:00 — в окне',                   in_maintenance_window(w, '2026-09-28 21:00+03'));
    PERFORM pg_temp.expect('вт 05:59 — окно понедельника',        in_maintenance_window(w, '2026-09-29 05:59+03'));
    PERFORM pg_temp.expect('вт 06:00 — вне окна',                 NOT in_maintenance_window(w, '2026-09-29 06:00+03'));
    PERFORM pg_temp.expect('пн 05:00 — окна воскресенья нет',     NOT in_maintenance_window(w, '2026-09-28 05:00+03'));
    PERFORM pg_temp.expect('сб 01:00 — окно пятницы',             in_maintenance_window(w, '2026-10-03 01:00+03'));
    PERFORM pg_temp.expect('сб 21:00 — вне окна',                 NOT in_maintenance_window(w, '2026-10-03 21:00+03'));
    PERFORM pg_temp.expect('пн 18:00 UTC = 21:00 МСК — в окне',   in_maintenance_window(w, '2026-09-28 18:00+00'));
    PERFORM pg_temp.expect('без окна — всегда',                   in_maintenance_window(NULL, now()));
END $$;

-- E6. Каталог ПО, развёртывание по кольцам, политики желаемого состояния
DO $$
DECLARE
    u_petrov  bigint := pg_temp.uid('petrov');
    u_ivanov  bigint := pg_temp.uid('ivanov');
    u_sidorov bigint := pg_temp.uid('sidorov');
    g_acc     bigint := (SELECT id FROM device_groups WHERE name = 'Бухгалтерия');
    p_chrome  bigint;
    p_tool    bigint;
    pv        bigint;
    pv_exe    bigint;
    d1        bigint;
    pol       bigint;
    m         bytea := convert_to('{"type":"invmon.package.v1","package":"Google Chrome","version":"129.0.6668.90","arch":"x64"}', 'UTF8');
    m_exe     bytea := convert_to('{"type":"invmon.package.v1","package":"Клиент учёта","version":"3.2","arch":"x64"}', 'UTF8');
BEGIN
    INSERT INTO software_packages (name, vendor, software_id, created_by)
    VALUES ('Google Chrome', 'Google LLC', (SELECT id FROM software WHERE name = 'Google Chrome'), u_petrov)
    RETURNING id INTO p_chrome;

    PERFORM pg_temp.expect_fail('MSI без ProductCode', '23514', format(
        $q$INSERT INTO software_package_versions (package_id, version, arch, installer_type, file_name, file_sha256, file_size,
                                                  detection, expected_signer, uploaded_by)
           VALUES (%s, '129.0', 'x64', 'msi', 'chrome.msi', sha256('msi'), 1000, '{"type": "msi_product_code"}', 'Google LLC', %s)$q$,
        p_chrome, u_petrov));
    PERFORM pg_temp.expect_fail('установщик без SHA-256', '23514', format(
        $q$INSERT INTO software_package_versions (package_id, version, arch, installer_type, file_name, file_size,
                                                  install_args, detection, expected_signer, uploaded_by)
           VALUES (%s, '129.0', 'x64', 'exe', 'setup.exe', 1000, '/S', '{"type": "uninstall_entry"}', 'Google LLC', %s)$q$,
        p_chrome, u_petrov));
    PERFORM pg_temp.expect_fail('проверка издателя без ожидаемого издателя', '23514', format(
        $q$INSERT INTO software_package_versions (package_id, version, arch, installer_type, file_name, file_sha256, file_size,
                                                  msi_product_code, detection, uploaded_by)
           VALUES (%s, '129.0', 'x64', 'msi', 'chrome.msi', sha256('msi'), 1000, gen_random_uuid(), '{"type": "msi_product_code"}', %s)$q$,
        p_chrome, u_petrov));
    PERFORM pg_temp.expect_fail('правило обнаружения без типа', '23514', format(
        $q$INSERT INTO software_package_versions (package_id, version, arch, installer_type, file_name, file_sha256, file_size,
                                                  msi_product_code, detection, expected_signer, uploaded_by)
           VALUES (%s, '129.0', 'x64', 'msi', 'chrome.msi', sha256('msi'), 1000, gen_random_uuid(), '{}', 'Google LLC', %s)$q$,
        p_chrome, u_petrov));

    INSERT INTO software_package_versions (package_id, version, version_parts, arch, installer_type, file_name, file_sha256,
                                           file_size, msi_product_code, detection, expected_signer, uploaded_by)
    VALUES (p_chrome, '129.0.6668.90', '{129,0,6668,90}', 'x64', 'msi', 'googlechromestandaloneenterprise64.msi',
            sha256('chrome-129-x64.msi'), 118784000, '6f2a0e1c-3b8d-4c5e-9a7f-1d2e3f4a5b6c',
            '{"type": "uninstall_entry", "display_name": "^Google Chrome$", "min_version": "129.0.6668.90"}',
            'Google LLC', u_petrov)
    RETURNING id INTO pv;
    UPDATE software_package_versions
    SET status = 'pending_approval', manifest = m, manifest_sha256 = sha256(m), submitted_at = now()
    WHERE id = pv;
    PERFORM pg_temp.expect_fail('правка аргументов установки после отправки', '23000',
        format($q$UPDATE software_package_versions SET install_args = 'INSTALLDIR=C:\Temp' WHERE id = %s$q$, pv));
    PERFORM pg_temp.expect_fail('подмена файла после отправки', '23000',
        format($q$UPDATE software_package_versions SET file_sha256 = sha256('evil') WHERE id = %s$q$, pv));
    EXECUTE pg_temp.sign('package_version_id', pv, 'author', 'petrov', 'YubiKey Петрова', sha256(m));
    EXECUTE pg_temp.sign('package_version_id', pv, 'approver', 'ivanov', 'YubiKey Иванова', sha256(m));
    UPDATE software_package_versions SET status = 'approved', decided_at = now() WHERE id = pv;

    -- Развёртывание по кольцам: ПК 1 — pilot (кольцо 0), ПК 2 — broad (кольцо 1)
    INSERT INTO deployment_tasks (package_version_id, action, target_spec, target_count, status, reason, created_by,
                                  expires_at, ring_plan)
    VALUES (pv, 'install', '{"group_id": 1}', 2, 'scheduled', 'CHG-311: браузер для бухгалтерии', u_sidorov,
            now() + interval '7 days', '[{"name": "pilot", "tag": "pilot", "soak_hours": 24}, {"name": "broad"}]')
    RETURNING id INTO d1;
    INSERT INTO agent_tasks (device_id, kind, deployment_task_id, ring) VALUES (1, 'package', d1, 0), (2, 'package', d1, 1);
    PERFORM pg_temp.expect_fail('ПК вне области прав', '42501',
        format($q$INSERT INTO agent_tasks (device_id, kind, deployment_task_id) VALUES (3, 'package', %s)$q$, d1));
    PERFORM pg_temp.expect('кольцо broad ждёт pilot', (SELECT count(*) FROM claim_agent_tasks(2, 600, 5)) = 0);
    PERFORM pg_temp.expect('кольцо pilot выдаётся',   (SELECT count(*) FROM claim_agent_tasks(1, 600, 5)) = 1);
    UPDATE agent_tasks SET state = 'running', started_at = now() WHERE deployment_task_id = d1 AND device_id = 1;
    UPDATE agent_tasks SET state = 'succeeded', finished_at = now(), exit_code = 3010, result = 'reboot_required'
    WHERE deployment_task_id = d1 AND device_id = 1;
    PERFORM pg_temp.expect_fail('пауза без причины', '23514',
        format($q$UPDATE deployment_tasks SET status = 'paused' WHERE id = %s$q$, d1));
    UPDATE deployment_tasks SET status = 'paused', paused_reason = 'ручная пауза: проверка pilot' WHERE id = d1;
    UPDATE deployment_tasks SET current_ring = 1 WHERE id = d1;                  -- pilot прошёл, выдержка окончена
    PERFORM pg_temp.expect('на паузе не выдаётся', (SELECT count(*) FROM claim_agent_tasks(2, 600, 5)) = 0);
    UPDATE deployment_tasks SET status = 'running' WHERE id = d1;
    PERFORM pg_temp.expect('кольцо broad выдаётся', (SELECT count(*) FROM claim_agent_tasks(2, 600, 5)) = 1);
    PERFORM pg_temp.expect('сводка развёртывания', (
        SELECT succeeded = 1 AND in_progress = 1 AND reboot_required = 1
        FROM v_job_summary WHERE job_type = 'deployment' AND job_id = d1));
    PERFORM pg_temp.expect_fail('удаление развёртывания', '42501', 'DELETE FROM deployment_tasks');
    PERFORM pg_temp.expect_fail('удаление ПК с историей выполнения', '23503', 'DELETE FROM devices WHERE id = 1');

    -- Удаление ПО — только если в подписанном манифесте есть способ удаления
    INSERT INTO software_packages (name, vendor, created_by) VALUES ('Клиент учёта', 'ООО «Пример»', u_petrov)
    RETURNING id INTO p_tool;
    INSERT INTO software_package_versions (package_id, version, arch, installer_type, file_name, file_sha256, file_size,
                                           install_args, detection, require_authenticode, uploaded_by,
                                           status, manifest, manifest_sha256, submitted_at)
    VALUES (p_tool, '3.2', 'x64', 'exe', 'client-3.2-setup.exe', sha256('client'), 5242880, '/VERYSILENT',
            '{"type": "file_version", "path": "%ProgramFiles%\\Client\\client.exe", "min_version": "3.2"}', false, u_petrov,
            'pending_approval', m_exe, sha256(m_exe), now())
    RETURNING id INTO pv_exe;
    EXECUTE pg_temp.sign('package_version_id', pv_exe, 'author', 'petrov', 'YubiKey Петрова', sha256(m_exe));
    EXECUTE pg_temp.sign('package_version_id', pv_exe, 'approver', 'ivanov', 'YubiKey Иванова', sha256(m_exe));
    UPDATE software_package_versions SET status = 'approved', decided_at = now() WHERE id = pv_exe;
    PERFORM pg_temp.expect_fail('удаление без способа удаления в манифесте', '23000', format(
        $q$INSERT INTO deployment_tasks (package_version_id, action, target_spec, target_count, status, reason, created_by, expires_at)
           VALUES (%s, 'uninstall', '{"device_ids": [1]}', 1, 'scheduled', 'CHG-312: удалить клиент', %s, now() + interval '1 day')$q$,
        pv_exe, u_sidorov));

    -- Политика: включает второй человек; изменение сути снимает одобрение
    INSERT INTO deployment_policies (name, package_id, intent, version_rule, scope_group_id, maintenance_window, created_by)
    VALUES ('Chrome у бухгалтерии — последняя одобренная версия', p_chrome, 'required', 'latest', g_acc,
            '{"days": ["mon", "tue", "wed", "thu", "fri"], "from": "20:00", "to": "06:00", "tz": "Europe/Moscow"}', u_sidorov)
    RETURNING id INTO pol;
    PERFORM pg_temp.expect_fail('новая политика сразу включена', '23000', format(
        $q$INSERT INTO deployment_policies (name, package_id, intent, created_by, enabled, approved_by, approved_at)
           VALUES ('x', %s, 'prohibited', %s, true, %s, now())$q$, p_chrome, u_sidorov, u_ivanov));
    PERFORM pg_temp.expect_fail('включение без одобрения', '23514',
        format('UPDATE deployment_policies SET enabled = true WHERE id = %s', pol));
    PERFORM pg_temp.expect_fail('одобрение автором политики', '23514',
        format('UPDATE deployment_policies SET approved_by = %s, approved_at = now() WHERE id = %s', u_sidorov, pol));
    PERFORM pg_temp.expect_fail('запрет ПО с правилом версии', '23514', format(
        $q$INSERT INTO deployment_policies (name, package_id, intent, version_rule, min_version, created_by)
           VALUES ('y', %s, 'prohibited', 'minimum', '1.0', %s)$q$, p_chrome, u_sidorov));
    UPDATE deployment_policies SET approved_by = u_ivanov, approved_at = now(), enabled = true WHERE id = pol;

    -- Развёртывание от политики: без инициатора, сразу scheduled; область прав — автора политики
    INSERT INTO deployment_tasks (package_version_id, action, policy_id, target_spec, target_count, status, reason, expires_at)
    VALUES (pv, 'install', pol, jsonb_build_object('policy_id', pol), 1, 'scheduled',
            'политика «Chrome у бухгалтерии»', now() + interval '7 days')
    RETURNING id INTO d1;
    INSERT INTO agent_tasks (device_id, kind, deployment_task_id) VALUES (1, 'package', d1);
    UPDATE deployment_policies SET scope_group_id = NULL WHERE id = pol;          -- расширение на весь парк
    PERFORM pg_temp.expect('изменение политики снимает одобрение',
        (SELECT NOT enabled AND approved_by IS NULL FROM deployment_policies WHERE id = pol));
    PERFORM pg_temp.expect_fail('развёртывание от выключенной политики', '23000', format(
        $q$INSERT INTO deployment_tasks (package_version_id, action, policy_id, target_spec, target_count, status, reason, expires_at)
           VALUES (%s, 'install', %s, '{}', 1, 'scheduled', 'политика: повтор', now() + interval '7 days')$q$, pv, pol));
END $$;

RESET ROLE;
\echo 'ALL CHECKS PASSED'
