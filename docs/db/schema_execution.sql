-- =============================================================================
-- InvMon — модуль выполнения скриптов и управления ПО (ПРОЕКТ, v2.0)
-- Применяется поверх docs/db/schema.sql; при реализации станет очередной
-- встроенной миграцией. PostgreSQL 16+.
-- Описание модуля и модель угроз: docs/execution.md.
-- Исполняемая проверка: docs/db/verify.sql, раздел «Модуль выполнения».
--
-- Инварианты закреплены в БД, а не только в коде сервера:
--   * версия скрипта или пакета после отправки на согласование неизменяема;
--   * «одобрена» = есть подпись автора и подпись другого человека с правом
--     согласования; обе сделаны неотозванными ключами подписантов и относятся
--     к текущему манифесту;
--   * запускать можно только одобренные версии; запуск high_impact требует
--     таких же двух подписей на сам запуск (что, где, с какими параметрами);
--   * задача ставится только на активный ПК из области прав инициатора;
--   * задачи проходят строгую машину состояний, итог задним числом не меняется;
--   * права модуля не выдаются самому себе; подписи и история не удаляются.
-- Подписи ECDSA P-256 проверяет сервер перед записью и — независимо от
-- сервера — агент перед выполнением. БД хранит подписи и гарантирует, к какому
-- объекту и к какому манифесту они относятся.
-- =============================================================================

-- =============================================================================
-- 1. Права модуля: явные разрешения с областью действия (группа устройств).
--    Роли admin / operator / viewer из ядра НЕ дают права выполнять код на ПК.
-- =============================================================================
CREATE TYPE permission AS ENUM (
    'script.author',           -- создавать скрипты и версии, отправлять на согласование
    'script.approve',          -- подписывать чужие версии скриптов и чужие запуски
    'script.run',              -- запускать одобренные скрипты в своей области
    'script.run_high_impact',  -- запускать скрипты high_impact (запуск подписывают двое)
    'package.manage',          -- загружать пакеты ПО, создавать и отправлять версии
    'package.approve',         -- подписывать чужие версии пакетов и чужие развёртывания
    'deployment.run',          -- развёртывания и политики ПО в своей области
    'task.view_output',        -- видеть вывод выполнения (может содержать персональные данные)
    'task.cancel_any',         -- отменять чужие запуски и развёртывания
    'execution.admin'          -- стоп-кран, реестр ключей, выдача прав модуля
);

CREATE TABLE user_permissions (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id         bigint      NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    permission      permission  NOT NULL,
    scope_group_id  bigint      REFERENCES device_groups (id) ON DELETE CASCADE,  -- NULL = весь парк
    granted_by      bigint      REFERENCES users (id) ON DELETE SET NULL,         -- NULL = CLI на сервере
    granted_at      timestamptz NOT NULL DEFAULT now(),
    CHECK (granted_by IS NULL OR granted_by <> user_id)                           -- себе права не выдают
);
CREATE UNIQUE INDEX user_permissions_uq ON user_permissions (user_id, permission, COALESCE(scope_group_id, 0));

-- Есть ли у активного пользователя право на устройство из группы p_group
-- (p_group = NULL — ПК без группы: подходит только право на весь парк).
CREATE FUNCTION has_permission(p_user bigint, p_perm permission, p_group bigint) RETURNS boolean
LANGUAGE sql STABLE AS $$
    SELECT EXISTS (
        SELECT 1
        FROM user_permissions up
        JOIN users u ON u.id = up.user_id AND u.is_active
        WHERE up.user_id = p_user
          AND up.permission = p_perm
          AND (up.scope_group_id IS NULL OR up.scope_group_id = p_group)
    )
$$;

-- =============================================================================
-- 2. Открытые ключи подписантов. Закрытые ключи — только на аппаратных токенах
--    сотрудников (смарт-карта, YubiKey PIV). Агенты доверяют не этой таблице,
--    а списку отпечатков из локальной политики ПК (GPO): сервер не может
--    «добавить себе» доверенный ключ.
-- =============================================================================
CREATE TABLE signing_keys (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    owner_id     bigint      NOT NULL REFERENCES users (id),
    name         text        NOT NULL,                       -- «YubiKey 5 NFC, серийный 123»
    algorithm    text        NOT NULL DEFAULT 'ecdsa-p256-sha256' CHECK (algorithm = 'ecdsa-p256-sha256'),
    public_key   bytea       NOT NULL,                       -- SubjectPublicKeyInfo, DER
    fingerprint  text        NOT NULL UNIQUE CHECK (fingerprint ~ '^[0-9a-f]{64}$'),  -- hex SHA-256 от SPKI
    created_at   timestamptz NOT NULL DEFAULT now(),
    revoked_at   timestamptz
);

-- Меняться может только revoked_at и только один раз: отзыв окончателен.
CREATE FUNCTION signing_keys_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF (to_jsonb(NEW) - 'revoked_at') IS DISTINCT FROM (to_jsonb(OLD) - 'revoked_at')
       OR (OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at) THEN
        RAISE EXCEPTION 'signing key %: only a one-time revocation is allowed', OLD.id
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER signing_keys_guard BEFORE UPDATE ON signing_keys
    FOR EACH ROW EXECUTE FUNCTION signing_keys_guard();

-- =============================================================================
-- 3. Библиотека скриптов
-- =============================================================================
CREATE TYPE script_interpreter AS ENUM ('powershell', 'cmd');
CREATE TYPE script_run_as      AS ENUM ('system', 'local_service');   -- LocalSystem или NT AUTHORITY\LocalService
CREATE TYPE artifact_status    AS ENUM ('draft', 'pending_approval', 'approved', 'rejected', 'retired');

CREATE TABLE scripts (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name         text        NOT NULL UNIQUE,
    description  text        NOT NULL DEFAULT '',
    category     text        NOT NULL DEFAULT '',              -- обслуживание, диагностика, ПО…
    interpreter  script_interpreter NOT NULL,
    high_impact  boolean     NOT NULL DEFAULT false,           -- запуск подписывают двое
    created_by   bigint      NOT NULL REFERENCES users (id),
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    archived_at  timestamptz
);
CREATE TRIGGER scripts_updated_at BEFORE UPDATE ON scripts
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Версия — неизменяемый снимок: код, схема параметров, ограничения выполнения.
-- interpreter и high_impact копируются из scripts при создании версии и входят
-- в подписанный манифест: агент видит их в подписанном виде.
CREATE TABLE script_versions (
    id                      bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    script_id               bigint      NOT NULL REFERENCES scripts (id),
    version                 integer     NOT NULL CHECK (version > 0),
    interpreter             script_interpreter NOT NULL,
    high_impact             boolean     NOT NULL,
    content                 text        NOT NULL CHECK (octet_length(content) <= 262144),   -- ≤ 256 КиБ
    content_sha256          bytea       NOT NULL CHECK (octet_length(content_sha256) = 32),
    -- Схема параметров (подмножество JSON Schema): только типизированные значения;
    -- у строк обязательны enum или pattern + maxLength. «Произвольной команды» нет.
    params_schema           jsonb       NOT NULL DEFAULT '{"type": "object", "properties": {}, "additionalProperties": false}'
                                        CHECK (jsonb_typeof(params_schema) = 'object'),
    timeout_s               integer     NOT NULL DEFAULT 600 CHECK (timeout_s BETWEEN 10 AND 14400),
    run_as                  script_run_as NOT NULL DEFAULT 'system',
    max_output_bytes        integer     NOT NULL DEFAULT 1048576 CHECK (max_output_bytes BETWEEN 1024 AND 10485760),
    success_exit_codes      integer[]   NOT NULL DEFAULT '{0}' CHECK (cardinality(success_exit_codes) > 0),
    min_os_build            integer,                                -- 7601 = Windows 7 SP1; NULL — без ограничения
    min_powershell_version  text        CHECK (min_powershell_version ~ '^[0-9]+\.[0-9]+$'),   -- «5.1»; в Win7 из коробки 2.0
    status                  artifact_status NOT NULL DEFAULT 'draft',
    manifest                bytea,          -- ТОЧНЫЕ подписываемые байты (канонический JSON), фиксируются при отправке
    manifest_sha256         bytea,
    author_id               bigint      NOT NULL REFERENCES users (id),
    change_note             text        NOT NULL DEFAULT '',
    submitted_at            timestamptz,
    decided_at              timestamptz,
    created_at              timestamptz NOT NULL DEFAULT now(),
    UNIQUE (script_id, version),
    CHECK ((status = 'draft') = (manifest IS NULL)),
    CHECK ((manifest IS NULL) = (manifest_sha256 IS NULL))
);

-- =============================================================================
-- 4. Каталог ПО: MSI, EXE или установка скриптом
-- =============================================================================
CREATE TYPE installer_type AS ENUM ('msi', 'exe', 'script');

CREATE TABLE software_packages (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name         text        NOT NULL UNIQUE,                  -- «Google Chrome»
    vendor       text        NOT NULL DEFAULT '',
    description  text        NOT NULL DEFAULT '',
    software_id  bigint      REFERENCES software (id) ON DELETE SET NULL,   -- связь с инвентаризацией ПО
    created_by   bigint      NOT NULL REFERENCES users (id),
    created_at   timestamptz NOT NULL DEFAULT now(),
    archived_at  timestamptz
);

CREATE TABLE software_package_versions (
    id                           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    package_id                   bigint      NOT NULL REFERENCES software_packages (id),
    version                      text        NOT NULL,             -- «129.0.6668.90»
    version_parts                integer[],                        -- {129,0,6668,90} — для сравнения версий
    arch                         text        NOT NULL CHECK (arch IN ('x86', 'x64', 'arm64', 'any')),
    installer_type               installer_type NOT NULL,
    file_name                    text,
    file_sha256                  bytea       CHECK (octet_length(file_sha256) = 32),
    file_size                    bigint      CHECK (file_size > 0),
    -- Всё ниже входит в подписанный манифест; при запуске оператор это не меняет
    install_args                 text        NOT NULL DEFAULT '',   -- EXE: «/S»; MSI: свойства «ALLUSERS=1»
    uninstall_command            text,                              -- EXE: «%ProgramFiles%\Vendor\uninstall.exe»
    uninstall_args               text        NOT NULL DEFAULT '',
    msi_product_code             uuid,
    install_script_version_id    bigint      REFERENCES script_versions (id),
    uninstall_script_version_id  bigint      REFERENCES script_versions (id),
    detection                    jsonb       NOT NULL CHECK (jsonb_typeof(detection) = 'object' AND detection ? 'type'),
    success_exit_codes           integer[]   NOT NULL DEFAULT '{0,1641,3010}',
    timeout_s                    integer     NOT NULL DEFAULT 3600 CHECK (timeout_s BETWEEN 60 AND 14400),
    reboot_behavior              text        NOT NULL DEFAULT 'suppress'
                                             CHECK (reboot_behavior IN ('suppress', 'allow_in_window')),
    require_authenticode         boolean     NOT NULL DEFAULT true,
    expected_signer              text,                              -- субъект сертификата издателя
    status                       artifact_status NOT NULL DEFAULT 'draft',
    manifest                     bytea,
    manifest_sha256              bytea,
    uploaded_by                  bigint      NOT NULL REFERENCES users (id),
    submitted_at                 timestamptz,
    decided_at                   timestamptz,
    created_at                   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (package_id, version, arch),
    CHECK ((installer_type = 'script') = (install_script_version_id IS NOT NULL)),
    CHECK (installer_type = 'script' OR (file_name IS NOT NULL AND file_sha256 IS NOT NULL AND file_size IS NOT NULL)),
    CHECK (installer_type <> 'msi' OR msi_product_code IS NOT NULL),
    CHECK (installer_type = 'exe' OR uninstall_command IS NULL),
    CHECK (installer_type = 'script' OR uninstall_script_version_id IS NULL),
    CHECK (NOT require_authenticode OR installer_type = 'script' OR expected_signer IS NOT NULL),
    CHECK ((status = 'draft') = (manifest IS NULL)),
    CHECK ((manifest IS NULL) = (manifest_sha256 IS NULL))
);

-- =============================================================================
-- 5. Подписи: автор (инициатор) и согласующий подписывают одни и те же байты
--    манифеста. Подпись относится ровно к одному объекту: версии скрипта,
--    версии пакета, запуску скрипта или развёртыванию.
-- =============================================================================
CREATE TYPE signature_role AS ENUM ('author', 'approver');

CREATE TABLE signatures (
    id                  bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    script_version_id   bigint REFERENCES script_versions (id),
    package_version_id  bigint REFERENCES software_package_versions (id),
    script_run_id       bigint,          -- внешние ключи добавляются в разделе 6
    deployment_task_id  bigint,
    role                signature_role NOT NULL,
    signer_id           bigint      NOT NULL REFERENCES users (id),
    signing_key_id      bigint      NOT NULL REFERENCES signing_keys (id),
    signed_sha256       bytea       NOT NULL CHECK (octet_length(signed_sha256) = 32),   -- что именно подписано
    signature           bytea       NOT NULL,                                            -- ECDSA P-256, ASN.1 DER
    comment             text        NOT NULL DEFAULT '',
    created_at          timestamptz NOT NULL DEFAULT now(),
    CHECK (num_nonnulls(script_version_id, package_version_id, script_run_id, deployment_task_id) = 1)
);
-- Один человек — одна подпись на объект
CREATE UNIQUE INDEX signatures_subject_signer_uq ON signatures
    (script_version_id, package_version_id, script_run_id, deployment_task_id, signer_id) NULLS NOT DISTINCT;
CREATE INDEX signatures_script_run_idx ON signatures (script_run_id) WHERE script_run_id IS NOT NULL;
CREATE INDEX signatures_deployment_idx ON signatures (deployment_task_id) WHERE deployment_task_id IS NOT NULL;

-- Есть ли у объекта подписи автора и согласующего. Что обе относятся к текущему
-- манифесту, гарантируют signatures_enforce и неизменяемость манифеста.
CREATE FUNCTION has_two_signatures(p_kind text, p_id bigint) RETURNS boolean
LANGUAGE sql STABLE AS $$
    SELECT count(DISTINCT s.role) = 2
    FROM signatures s
    WHERE CASE p_kind
              WHEN 'script_version'  THEN s.script_version_id = p_id
              WHEN 'package_version' THEN s.package_version_id = p_id
              WHEN 'script_run'      THEN s.script_run_id = p_id
              WHEN 'deployment'      THEN s.deployment_task_id = p_id
          END
$$;

-- Версии: создаются черновиком или сразу на согласование; после отправки
-- неизменяемы; одобрение — только при двух подписях; удалить можно лишь черновик.
CREATE FUNCTION artifact_version_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status NOT IN ('draft', 'pending_approval') THEN
            RAISE EXCEPTION '%: a new version starts as draft or pending_approval, not %', TG_TABLE_NAME, NEW.status
                USING ERRCODE = 'integrity_constraint_violation';
        END IF;
        IF TG_TABLE_NAME = 'script_versions' THEN
            SELECT interpreter, high_impact INTO NEW.interpreter, NEW.high_impact
            FROM scripts WHERE id = NEW.script_id;
        END IF;
        RETURN NEW;
    END IF;

    IF TG_OP = 'DELETE' THEN
        IF OLD.status <> 'draft' THEN
            RAISE EXCEPTION '%: version % is %, only drafts can be deleted', TG_TABLE_NAME, OLD.id, OLD.status
                USING ERRCODE = 'integrity_constraint_violation';
        END IF;
        RETURN OLD;
    END IF;

    IF OLD.status <> 'draft'
       AND (to_jsonb(NEW) - ARRAY['status', 'decided_at']) IS DISTINCT FROM (to_jsonb(OLD) - ARRAY['status', 'decided_at']) THEN
        RAISE EXCEPTION '%: version % is %, its content is immutable', TG_TABLE_NAME, OLD.id, OLD.status
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.status IS DISTINCT FROM OLD.status AND NOT (
           (OLD.status = 'draft'            AND NEW.status = 'pending_approval')
        OR (OLD.status = 'pending_approval' AND NEW.status IN ('approved', 'rejected'))
        OR (OLD.status = 'approved'         AND NEW.status = 'retired')
    ) THEN
        RAISE EXCEPTION '%: transition % -> % is not allowed', TG_TABLE_NAME, OLD.status, NEW.status
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF OLD.status = 'pending_approval' AND NEW.status = 'approved'
       AND NOT has_two_signatures(CASE TG_TABLE_NAME WHEN 'script_versions' THEN 'script_version'
                                                     ELSE 'package_version' END, NEW.id) THEN
        RAISE EXCEPTION '%: version % needs author and approver signatures', TG_TABLE_NAME, NEW.id
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER script_versions_guard BEFORE INSERT OR UPDATE OR DELETE ON script_versions
    FOR EACH ROW EXECUTE FUNCTION artifact_version_guard();
CREATE TRIGGER software_package_versions_guard BEFORE INSERT OR UPDATE OR DELETE ON software_package_versions
    FOR EACH ROW EXECUTE FUNCTION artifact_version_guard();

-- =============================================================================
-- 6. Запуски скриптов, политики и развёртывания ПО: «что, где, кто и зачем»
-- =============================================================================
CREATE TYPE job_status AS ENUM ('pending_approval', 'scheduled', 'running', 'paused', 'completed', 'canceled', 'expired');

CREATE FUNCTION job_transition_allowed(p_old job_status, p_new job_status) RETURNS boolean
LANGUAGE sql IMMUTABLE AS $$
    SELECT p_old = p_new OR (p_old, p_new) IN (
        ('pending_approval', 'scheduled'), ('pending_approval', 'canceled'), ('pending_approval', 'expired'),
        ('scheduled', 'running'), ('scheduled', 'paused'), ('scheduled', 'canceled'), ('scheduled', 'expired'),
        ('running', 'completed'), ('running', 'paused'), ('running', 'canceled'),
        ('paused', 'running'), ('paused', 'canceled'), ('paused', 'expired')
    )
$$;

CREATE TABLE script_runs (
    id                   bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    script_version_id    bigint      NOT NULL REFERENCES script_versions (id),
    parameters           jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(parameters) = 'object'),
    target_spec          jsonb       NOT NULL CHECK (jsonb_typeof(target_spec) = 'object'),  -- как задал оператор
    target_count         integer     NOT NULL CHECK (target_count > 0),                      -- после разрешения целей
    status               job_status  NOT NULL,
    reason               text        NOT NULL CHECK (length(btrim(reason)) >= 5),            -- № заявки и обоснование
    created_by           bigint      NOT NULL REFERENCES users (id),
    not_before           timestamptz NOT NULL DEFAULT now(),
    expires_at           timestamptz NOT NULL,        -- невыданные задачи истекают (ПК долго офлайн)
    max_concurrency      integer     CHECK (max_concurrency > 0),   -- не больше N ПК одновременно
    run_manifest         bytea,                       -- подписываемые байты запуска, если нужно согласование
    run_manifest_sha256  bytea,
    cancel_requested_at  timestamptz,
    canceled_by          bigint      REFERENCES users (id),
    created_at           timestamptz NOT NULL DEFAULT now(),
    finished_at          timestamptz,
    CHECK (expires_at > not_before),
    CHECK ((run_manifest IS NULL) = (run_manifest_sha256 IS NULL)),
    CHECK (status <> 'pending_approval' OR run_manifest IS NOT NULL)
);
CREATE INDEX script_runs_open_idx ON script_runs (status) WHERE finished_at IS NULL;

CREATE TYPE deployment_action AS ENUM ('install', 'uninstall', 'update');

-- Политика желаемого состояния: ПО должно быть установлено (required, с правилом
-- версии) или отсутствовать (prohibited). Движок политик создаёт deployment_tasks
-- для несоответствующих ПК. Включает политику только второй человек; изменение
-- сути политики снимает одобрение.
CREATE TABLE deployment_policies (
    id                  bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name                text        NOT NULL UNIQUE,
    package_id          bigint      NOT NULL REFERENCES software_packages (id),
    intent              text        NOT NULL CHECK (intent IN ('required', 'prohibited')),
    version_rule        text        NOT NULL DEFAULT 'any' CHECK (version_rule IN ('any', 'minimum', 'latest')),
    min_version         text,
    scope_group_id      bigint      REFERENCES device_groups (id) ON DELETE CASCADE,
    scope_tag           text,
    maintenance_window  jsonb,       -- {"days": ["mon", …], "from": "20:00", "to": "06:00", "tz": "Europe/Moscow"}
    ring_plan           jsonb       NOT NULL DEFAULT '[{"name": "pilot", "tag": "pilot", "soak_hours": 24}, {"name": "broad"}]',
    max_failure_pct     integer     NOT NULL DEFAULT 10 CHECK (max_failure_pct BETWEEN 1 AND 100),
    reboot_policy       text        NOT NULL DEFAULT 'suppress' CHECK (reboot_policy IN ('suppress', 'allow_in_window')),
    enabled             boolean     NOT NULL DEFAULT false,
    created_by          bigint      NOT NULL REFERENCES users (id),
    approved_by         bigint      REFERENCES users (id),
    approved_at         timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    CHECK ((version_rule = 'minimum') = (min_version IS NOT NULL)),
    CHECK (intent = 'required' OR version_rule = 'any'),
    CHECK (approved_by IS NULL OR approved_by <> created_by),
    CHECK ((approved_by IS NULL) = (approved_at IS NULL)),
    CHECK (NOT enabled OR approved_by IS NOT NULL)
);

CREATE FUNCTION deployment_policies_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.enabled OR NEW.approved_by IS NOT NULL THEN
            RAISE EXCEPTION 'a new policy starts disabled and unapproved'
                USING ERRCODE = 'integrity_constraint_violation';
        END IF;
    ELSIF (to_jsonb(NEW) - ARRAY['enabled', 'approved_by', 'approved_at', 'updated_at'])
          IS DISTINCT FROM (to_jsonb(OLD) - ARRAY['enabled', 'approved_by', 'approved_at', 'updated_at']) THEN
        NEW.approved_by := NULL;
        NEW.approved_at := NULL;
        NEW.enabled     := false;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER deployment_policies_guard BEFORE INSERT OR UPDATE ON deployment_policies
    FOR EACH ROW EXECUTE FUNCTION deployment_policies_guard();
CREATE TRIGGER deployment_policies_updated_at BEFORE UPDATE ON deployment_policies
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE deployment_tasks (
    id                   bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    package_version_id   bigint      NOT NULL REFERENCES software_package_versions (id),
    action               deployment_action NOT NULL,
    policy_id            bigint      REFERENCES deployment_policies (id),
    target_spec          jsonb       NOT NULL CHECK (jsonb_typeof(target_spec) = 'object'),
    target_count         integer     NOT NULL CHECK (target_count > 0),
    status               job_status  NOT NULL,
    reason               text        NOT NULL CHECK (length(btrim(reason)) >= 5),
    created_by           bigint      REFERENCES users (id),       -- NULL — создано политикой
    not_before           timestamptz NOT NULL DEFAULT now(),
    deadline             timestamptz,                             -- после дедлайна окно обслуживания не ждём
    expires_at           timestamptz NOT NULL,
    maintenance_window   jsonb,
    ring_plan            jsonb       NOT NULL DEFAULT '[{"name": "broad"}]',
    current_ring         smallint    NOT NULL DEFAULT 0,          -- выдаются задачи колец 0..current_ring
    max_failure_pct      integer     NOT NULL DEFAULT 10 CHECK (max_failure_pct BETWEEN 1 AND 100),
    reboot_policy        text        NOT NULL DEFAULT 'suppress' CHECK (reboot_policy IN ('suppress', 'allow_in_window')),
    run_manifest         bytea,
    run_manifest_sha256  bytea,
    paused_reason        text,                                    -- «ошибок в кольце pilot 25 % > 10 %»
    cancel_requested_at  timestamptz,
    canceled_by          bigint      REFERENCES users (id),
    created_at           timestamptz NOT NULL DEFAULT now(),
    finished_at          timestamptz,
    CHECK (num_nonnulls(created_by, policy_id) >= 1),
    CHECK (expires_at > not_before),
    CHECK ((run_manifest IS NULL) = (run_manifest_sha256 IS NULL)),
    CHECK (status <> 'pending_approval' OR run_manifest IS NOT NULL),
    CHECK (status <> 'paused' OR paused_reason IS NOT NULL)
);
CREATE INDEX deployment_tasks_open_idx ON deployment_tasks (status) WHERE finished_at IS NULL;

ALTER TABLE signatures
    ADD FOREIGN KEY (script_run_id) REFERENCES script_runs (id),
    ADD FOREIGN KEY (deployment_task_id) REFERENCES deployment_tasks (id);

-- Подпись: ключ принадлежит подписанту и не отозван; объект ждёт согласования;
-- подписан текущий манифест; «автор» — сам автор или инициатор, «согласующий» —
-- другой человек с правом согласования.
CREATE FUNCTION signatures_enforce() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    v_owner     bigint;
    v_revoked   timestamptz;
    v_author    bigint;
    v_status    text;
    v_manifest  bytea;
BEGIN
    SELECT owner_id, revoked_at INTO v_owner, v_revoked FROM signing_keys WHERE id = NEW.signing_key_id;
    IF v_owner IS DISTINCT FROM NEW.signer_id OR v_revoked IS NOT NULL THEN
        RAISE EXCEPTION 'signing key % does not belong to user % or is revoked', NEW.signing_key_id, NEW.signer_id
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;

    IF NEW.script_version_id IS NOT NULL THEN
        SELECT author_id, status::text, manifest_sha256 INTO v_author, v_status, v_manifest
        FROM script_versions WHERE id = NEW.script_version_id;
    ELSIF NEW.package_version_id IS NOT NULL THEN
        SELECT uploaded_by, status::text, manifest_sha256 INTO v_author, v_status, v_manifest
        FROM software_package_versions WHERE id = NEW.package_version_id;
    ELSIF NEW.script_run_id IS NOT NULL THEN
        SELECT created_by, status::text, run_manifest_sha256 INTO v_author, v_status, v_manifest
        FROM script_runs WHERE id = NEW.script_run_id;
    ELSE
        SELECT created_by, status::text, run_manifest_sha256 INTO v_author, v_status, v_manifest
        FROM deployment_tasks WHERE id = NEW.deployment_task_id;
    END IF;

    IF v_status IS DISTINCT FROM 'pending_approval' THEN
        RAISE EXCEPTION 'only objects pending approval can be signed (status %)', v_status
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF v_manifest IS DISTINCT FROM NEW.signed_sha256 THEN
        RAISE EXCEPTION 'signature does not match the current manifest'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.role = 'author' AND v_author IS DISTINCT FROM NEW.signer_id THEN
        RAISE EXCEPTION 'separation of duties: only the author or requester signs as author'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.role = 'approver' AND v_author = NEW.signer_id THEN
        RAISE EXCEPTION 'separation of duties: user % cannot approve own object', NEW.signer_id
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.role = 'approver' AND NOT EXISTS (
        SELECT 1
        FROM user_permissions up
        JOIN users u ON u.id = up.user_id AND u.is_active
        WHERE up.user_id = NEW.signer_id
          AND up.permission = CASE WHEN NEW.script_version_id IS NOT NULL OR NEW.script_run_id IS NOT NULL
                                   THEN 'script.approve'::permission ELSE 'package.approve'::permission END
    ) THEN
        RAISE EXCEPTION 'user % has no approve permission', NEW.signer_id
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER signatures_enforce BEFORE INSERT ON signatures
    FOR EACH ROW EXECUTE FUNCTION signatures_enforce();

-- Запуск: только одобренная версия; high_impact начинается с согласования;
-- «что, где, кто» неизменяемы; выход из pending_approval — при двух подписях.
CREATE FUNCTION script_runs_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    v_status      artifact_status;
    v_high_impact boolean;
BEGIN
    IF TG_OP = 'INSERT' THEN
        SELECT v.status, v.high_impact OR s.high_impact INTO v_status, v_high_impact
        FROM script_versions v JOIN scripts s ON s.id = v.script_id
        WHERE v.id = NEW.script_version_id;
        IF v_status IS DISTINCT FROM 'approved' THEN
            RAISE EXCEPTION 'script version % is not approved', NEW.script_version_id
                USING ERRCODE = 'integrity_constraint_violation';
        END IF;
        IF NEW.status NOT IN ('pending_approval', 'scheduled') OR (v_high_impact AND NEW.status <> 'pending_approval') THEN
            RAISE EXCEPTION 'a script run starts as pending_approval (high impact) or scheduled, not %', NEW.status
                USING ERRCODE = 'integrity_constraint_violation';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.script_version_id <> OLD.script_version_id OR NEW.parameters IS DISTINCT FROM OLD.parameters
       OR NEW.target_spec IS DISTINCT FROM OLD.target_spec OR NEW.created_by <> OLD.created_by
       OR NEW.run_manifest IS DISTINCT FROM OLD.run_manifest THEN
        RAISE EXCEPTION 'script run %: what, where and who are immutable', OLD.id
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NOT job_transition_allowed(OLD.status, NEW.status) THEN
        RAISE EXCEPTION 'script run %: transition % -> % is not allowed', OLD.id, OLD.status, NEW.status
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF OLD.status = 'pending_approval' AND NEW.status = 'scheduled' AND NOT has_two_signatures('script_run', NEW.id) THEN
        RAISE EXCEPTION 'script run % needs requester and approver signatures', NEW.id
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER script_runs_guard BEFORE INSERT OR UPDATE ON script_runs
    FOR EACH ROW EXECUTE FUNCTION script_runs_guard();

-- Развёртывание: только одобренная версия пакета; удаление — только если
-- в манифесте есть способ удаления; от политики — только включённой, того же
-- пакета и сразу scheduled; «что, где, кто» неизменяемы.
CREATE FUNCTION deployment_tasks_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    v_pkg     software_package_versions%ROWTYPE;
    v_policy  deployment_policies%ROWTYPE;
BEGIN
    IF TG_OP = 'INSERT' THEN
        SELECT * INTO v_pkg FROM software_package_versions WHERE id = NEW.package_version_id;
        IF v_pkg.status IS DISTINCT FROM 'approved' THEN
            RAISE EXCEPTION 'package version % is not approved', NEW.package_version_id
                USING ERRCODE = 'integrity_constraint_violation';
        END IF;
        IF NEW.action = 'uninstall'
           AND ((v_pkg.installer_type = 'exe' AND v_pkg.uninstall_command IS NULL)
             OR (v_pkg.installer_type = 'script' AND v_pkg.uninstall_script_version_id IS NULL)) THEN
            RAISE EXCEPTION 'package version % has no uninstall method in its manifest', NEW.package_version_id
                USING ERRCODE = 'integrity_constraint_violation';
        END IF;
        IF NEW.policy_id IS NOT NULL THEN
            SELECT * INTO v_policy FROM deployment_policies WHERE id = NEW.policy_id;
            IF v_policy.enabled IS NOT TRUE OR v_policy.package_id <> v_pkg.package_id THEN
                RAISE EXCEPTION 'policy % is disabled or targets another package', NEW.policy_id
                    USING ERRCODE = 'integrity_constraint_violation';
            END IF;
        END IF;
        IF NEW.status NOT IN ('pending_approval', 'scheduled') OR (NEW.created_by IS NULL AND NEW.status <> 'scheduled') THEN
            RAISE EXCEPTION 'a deployment starts as pending_approval or scheduled (policy: scheduled), not %', NEW.status
                USING ERRCODE = 'integrity_constraint_violation';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.package_version_id <> OLD.package_version_id OR NEW.action <> OLD.action
       OR NEW.target_spec IS DISTINCT FROM OLD.target_spec OR NEW.created_by IS DISTINCT FROM OLD.created_by
       OR NEW.policy_id IS DISTINCT FROM OLD.policy_id OR NEW.run_manifest IS DISTINCT FROM OLD.run_manifest THEN
        RAISE EXCEPTION 'deployment %: what, where and who are immutable', OLD.id
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NOT job_transition_allowed(OLD.status, NEW.status) THEN
        RAISE EXCEPTION 'deployment %: transition % -> % is not allowed', OLD.id, OLD.status, NEW.status
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF OLD.status = 'pending_approval' AND NEW.status = 'scheduled' AND NOT has_two_signatures('deployment', NEW.id) THEN
        RAISE EXCEPTION 'deployment % needs requester and approver signatures', NEW.id
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER deployment_tasks_guard BEFORE INSERT OR UPDATE ON deployment_tasks
    FOR EACH ROW EXECUTE FUNCTION deployment_tasks_guard();

-- =============================================================================
-- 7. Задачи агентов — очередь «что выполнить на конкретном ПК» и результат.
--    Запуск или развёртывание раскладывается на строки agent_tasks при создании
--    (согласующий видит точный список ПК). id — task_id в протоколе агента.
-- =============================================================================
CREATE TYPE task_kind  AS ENUM ('script', 'package');
CREATE TYPE task_state AS ENUM (
    'queued',      -- ждёт выдачи агенту
    'dispatched',  -- выдана агенту, ждём подтверждения старта (аренда lease_expires_at)
    'running',     -- старт подтверждён сервером, агент выполняет
    'succeeded', 'failed', 'timed_out', 'canceled',
    'expired',     -- не выдана до expires_at (ПК был офлайн)
    'rejected',    -- агент отказался: подпись, локальная политика, параметры, ОС…
    'lost'         -- агент не отчитался вовремя; поздний результат будет принят
);

CREATE TABLE agent_tasks (
    id                  bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    device_id           bigint      NOT NULL REFERENCES devices (id),   -- ПК с историей не удаляют, а выводят (retired)
    kind                task_kind   NOT NULL,
    script_run_id       bigint      REFERENCES script_runs (id),
    deployment_task_id  bigint      REFERENCES deployment_tasks (id),
    ring                smallint    NOT NULL DEFAULT 0,
    state               task_state  NOT NULL DEFAULT 'queued',
    attempt             integer     NOT NULL DEFAULT 0,                 -- номер выдачи
    lease_expires_at    timestamptz,
    queued_at           timestamptz NOT NULL DEFAULT now(),
    dispatched_at       timestamptz,
    started_at          timestamptz,
    finished_at         timestamptz,
    exit_code           integer,
    result              text CHECK (result IN ('installed', 'already_installed', 'uninstalled', 'not_installed', 'reboot_required')),
    stdout              text        NOT NULL DEFAULT '' CHECK (octet_length(stdout) <= 10485760),
    stderr              text        NOT NULL DEFAULT '' CHECK (octet_length(stderr) <= 10485760),
    output_bytes        bigint      NOT NULL DEFAULT 0,       -- сколько вывода было всего (до усечения)
    output_truncated    boolean     NOT NULL DEFAULT false,
    last_output_seq     integer     NOT NULL DEFAULT 0,       -- идемпотентная потоковая выгрузка вывода
    output_purged_at    timestamptz,                          -- вывод удалён по сроку хранения
    error_code          text,        -- signature_invalid | execution_disabled | params_invalid | hash_mismatch | …
    error_detail        text,
    cancel_requested    boolean     NOT NULL DEFAULT false,
    CHECK ((kind = 'script') = (script_run_id IS NOT NULL)),
    CHECK ((kind = 'package') = (deployment_task_id IS NOT NULL)),
    CHECK (num_nonnulls(script_run_id, deployment_task_id) = 1),
    CHECK (result IS NULL OR kind = 'package'),
    CHECK (state NOT IN ('succeeded', 'failed', 'timed_out', 'canceled', 'expired', 'rejected') OR finished_at IS NOT NULL)
);
CREATE UNIQUE INDEX agent_tasks_run_device_uq ON agent_tasks (script_run_id, device_id) WHERE script_run_id IS NOT NULL;
CREATE UNIQUE INDEX agent_tasks_deploy_device_uq ON agent_tasks (deployment_task_id, device_id) WHERE deployment_task_id IS NOT NULL;
CREATE INDEX agent_tasks_device_open_idx ON agent_tasks (device_id, id) WHERE state IN ('queued', 'dispatched', 'running');
CREATE INDEX agent_tasks_lease_idx ON agent_tasks (lease_expires_at) WHERE state IN ('dispatched', 'running');

-- Постановка: только в состояние queued, только на активный ПК из области прав
-- инициатора (для политики — её автора). Дальше — машина состояний; итог
-- завершённой задачи не меняется, разрешена лишь очистка вывода по сроку.
CREATE FUNCTION agent_tasks_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    v_device_status  device_status;
    v_group          bigint;
    v_user           bigint;
    v_perm           permission;
    v_job            job_status;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'queued' THEN
            RAISE EXCEPTION 'a new agent task starts as queued' USING ERRCODE = 'integrity_constraint_violation';
        END IF;
        SELECT status, group_id INTO v_device_status, v_group FROM devices WHERE id = NEW.device_id;
        IF v_device_status IS DISTINCT FROM 'active' THEN
            RAISE EXCEPTION 'device % is not active', NEW.device_id USING ERRCODE = 'integrity_constraint_violation';
        END IF;
        IF NEW.kind = 'script' THEN
            SELECT r.created_by, r.status,
                   CASE WHEN v.high_impact OR s.high_impact THEN 'script.run_high_impact' ELSE 'script.run' END::permission
              INTO v_user, v_job, v_perm
            FROM script_runs r
            JOIN script_versions v ON v.id = r.script_version_id
            JOIN scripts s ON s.id = v.script_id
            WHERE r.id = NEW.script_run_id;
        ELSE
            SELECT COALESCE(d.created_by, p.created_by), d.status, 'deployment.run'::permission
              INTO v_user, v_job, v_perm
            FROM deployment_tasks d
            LEFT JOIN deployment_policies p ON p.id = d.policy_id
            WHERE d.id = NEW.deployment_task_id;
        END IF;
        IF v_job IS NULL OR v_job NOT IN ('pending_approval', 'scheduled', 'running') THEN
            RAISE EXCEPTION 'job is % — no new tasks', v_job USING ERRCODE = 'integrity_constraint_violation';
        END IF;
        IF NOT has_permission(v_user, v_perm, v_group) THEN
            RAISE EXCEPTION 'user % has no % permission for device %', v_user, v_perm, NEW.device_id
                USING ERRCODE = 'insufficient_privilege';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.device_id <> OLD.device_id OR NEW.kind <> OLD.kind OR NEW.ring <> OLD.ring
       OR NEW.script_run_id IS DISTINCT FROM OLD.script_run_id
       OR NEW.deployment_task_id IS DISTINCT FROM OLD.deployment_task_id THEN
        RAISE EXCEPTION 'agent task %: device and job are immutable', OLD.id
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF OLD.state IN ('succeeded', 'failed', 'timed_out', 'canceled', 'expired', 'rejected') THEN
        IF NEW.state <> OLD.state OR NEW.exit_code IS DISTINCT FROM OLD.exit_code
           OR NEW.result IS DISTINCT FROM OLD.result OR NEW.error_code IS DISTINCT FROM OLD.error_code
           OR NEW.started_at IS DISTINCT FROM OLD.started_at OR NEW.finished_at IS DISTINCT FROM OLD.finished_at THEN
            RAISE EXCEPTION 'agent task % is % — its outcome is immutable', OLD.id, OLD.state
                USING ERRCODE = 'integrity_constraint_violation';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.state <> OLD.state AND NOT (
           (OLD.state = 'queued'     AND NEW.state IN ('dispatched', 'canceled', 'expired'))
        OR (OLD.state = 'dispatched' AND NEW.state IN ('running', 'rejected', 'queued', 'canceled', 'lost'))
        OR (OLD.state = 'running'    AND NEW.state IN ('succeeded', 'failed', 'timed_out', 'canceled', 'lost'))
        OR (OLD.state = 'lost'       AND NEW.state IN ('succeeded', 'failed', 'timed_out', 'canceled'))
    ) THEN
        RAISE EXCEPTION 'agent task %: transition % -> % is not allowed', OLD.id, OLD.state, NEW.state
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER agent_tasks_guard BEFORE INSERT OR UPDATE ON agent_tasks
    FOR EACH ROW EXECUTE FUNCTION agent_tasks_guard();

-- Что агент сообщил о себе (каждый heartbeat). Включение — локальной политикой ПК.
CREATE TABLE device_execution_capabilities (
    device_id                 bigint      PRIMARY KEY REFERENCES devices (id) ON DELETE CASCADE,
    scripts_enabled           boolean     NOT NULL,          -- HKLM\SOFTWARE\Policies\InvMon\Agent: ScriptsEnabled
    packages_enabled          boolean     NOT NULL,          -- … PackagesEnabled
    trusted_key_fingerprints  text[]      NOT NULL DEFAULT '{}',
    powershell_version        text,                          -- «2.0» на Win7 без WMF 5.1
    reported_at               timestamptz NOT NULL DEFAULT now()
);

-- =============================================================================
-- 8. Механика очереди: окно обслуживания, выдача задач, просроченные аренды
-- =============================================================================

-- Окно обслуживания {"days": ["mon", …], "from": "20:00", "to": "06:00", "tz": "Europe/Moscow"}.
-- Окно, переходящее через полночь, относится к дню начала: окно понедельника
-- 20:00–06:00 захватывает утро вторника.
CREATE FUNCTION in_maintenance_window(p_window jsonb, p_at timestamptz) RETURNS boolean
LANGUAGE sql STABLE AS $$
    SELECT p_window IS NULL OR EXISTS (
        SELECT 1
        FROM (SELECT p_at AT TIME ZONE (p_window ->> 'tz') AS ts) l
        CROSS JOIN generate_series(0, 1) AS back(days)
        CROSS JOIN LATERAL (
            SELECT (l.ts::date - back.days) + (p_window ->> 'from')::time              AS starts,
                   (p_window ->> 'to')::time - (p_window ->> 'from')::time              AS len
        ) w
        WHERE p_window -> 'days' ? lower(to_char(w.starts, 'Dy'))
          AND l.ts >= w.starts
          AND l.ts <  w.starts + CASE WHEN w.len > interval '0' THEN w.len ELSE w.len + interval '24 hours' END
    )
$$;

-- Выдача задач агенту: атомарно, без двойной выдачи (SKIP LOCKED), с учётом
-- включения модуля и стоп-крана, локальной политики ПК, окна запуска, колец и
-- окна обслуживания развёртываний, лимита одновременности запуска.
-- Лимит одновременности приблизительный: параллельные выдачи разным ПК могут
-- превысить его на число одновременных запросов.
CREATE FUNCTION claim_agent_tasks(p_device bigint, p_lease_s integer, p_limit integer)
RETURNS SETOF agent_tasks
LANGUAGE sql AS $$
    WITH candidates AS (
        SELECT t.id
        FROM agent_tasks t
        JOIN device_execution_capabilities c ON c.device_id = t.device_id
        LEFT JOIN script_runs r      ON r.id = t.script_run_id
        LEFT JOIN deployment_tasks d ON d.id = t.deployment_task_id
        WHERE t.device_id = p_device
          AND t.state = 'queued'
          AND NOT t.cancel_requested
          AND EXISTS (SELECT 1 FROM settings s
                      WHERE s.key = 'execution'
                        AND (s.value ->> 'enabled')::boolean
                        AND NOT (s.value ->> 'paused')::boolean)
          AND CASE t.kind WHEN 'script' THEN c.scripts_enabled ELSE c.packages_enabled END
          AND COALESCE(r.status, d.status) IN ('scheduled', 'running')
          AND now() >= COALESCE(r.not_before, d.not_before)
          AND now() <  COALESCE(r.expires_at, d.expires_at)
          AND (r.max_concurrency IS NULL
               OR r.max_concurrency > (SELECT count(*) FROM agent_tasks x
                                       WHERE x.script_run_id = r.id AND x.state IN ('dispatched', 'running')))
          AND (d.id IS NULL
               OR (t.ring <= d.current_ring
                   AND (now() >= d.deadline OR in_maintenance_window(d.maintenance_window, now()))))
        ORDER BY t.id
        LIMIT p_limit
        FOR UPDATE OF t SKIP LOCKED
    ),
    claimed AS (
        UPDATE agent_tasks t
        SET state            = 'dispatched',
            attempt          = t.attempt + 1,
            dispatched_at    = now(),
            lease_expires_at = now() + make_interval(secs => p_lease_s)
        FROM candidates
        WHERE t.id = candidates.id
        RETURNING t.*
    ),
    started_runs AS (
        UPDATE script_runs SET status = 'running'
        WHERE status = 'scheduled' AND id IN (SELECT script_run_id FROM claimed)
    ),
    started_deployments AS (
        UPDATE deployment_tasks SET status = 'running'
        WHERE status = 'scheduled' AND id IN (SELECT deployment_task_id FROM claimed)
    )
    SELECT * FROM claimed
$$;

-- Фоновая задача сервера (раз в минуту): просроченные аренды, истёкшие задачи,
-- завершение запусков и развёртываний без открытых задач.
CREATE FUNCTION reap_agent_tasks(p_max_attempts integer) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
    -- Выдана, но старт не подтверждён за время аренды → снова в очередь; после N выдач — lost
    UPDATE agent_tasks
    SET state = CASE WHEN attempt < p_max_attempts THEN 'queued' ELSE 'lost' END::task_state,
        lease_expires_at = NULL
    WHERE state = 'dispatched' AND lease_expires_at < now();

    -- Выполняется дольше таймаута и запаса → lost (поздний результат будет принят)
    UPDATE agent_tasks SET state = 'lost'
    WHERE state = 'running' AND lease_expires_at < now();

    -- Не выдана до конца окна запуска → expired
    UPDATE agent_tasks t SET state = 'expired', finished_at = now()
    FROM script_runs r
    WHERE t.script_run_id = r.id AND t.state = 'queued' AND r.expires_at <= now();
    UPDATE agent_tasks t SET state = 'expired', finished_at = now()
    FROM deployment_tasks d
    WHERE t.deployment_task_id = d.id AND t.state = 'queued' AND d.expires_at <= now();

    -- Заголовок без открытых задач: running → completed, canceled — фиксируем время,
    -- не дошедший до выполнения к expires_at → expired
    UPDATE script_runs r
    SET status = CASE r.status WHEN 'running' THEN 'completed'::job_status
                               WHEN 'canceled' THEN 'canceled'::job_status
                               ELSE 'expired'::job_status END,
        finished_at = now()
    WHERE r.finished_at IS NULL
      AND (r.status IN ('running', 'canceled') OR r.expires_at <= now())
      AND NOT EXISTS (SELECT 1 FROM agent_tasks t
                      WHERE t.script_run_id = r.id AND t.state IN ('queued', 'dispatched', 'running'));
    UPDATE deployment_tasks d
    SET status = CASE d.status WHEN 'running' THEN 'completed'::job_status
                               WHEN 'canceled' THEN 'canceled'::job_status
                               ELSE 'expired'::job_status END,
        finished_at = now()
    WHERE d.finished_at IS NULL
      AND (d.status IN ('running', 'canceled') OR d.expires_at <= now())
      AND NOT EXISTS (SELECT 1 FROM agent_tasks t
                      WHERE t.deployment_task_id = d.id AND t.state IN ('queued', 'dispatched', 'running'));
END $$;

-- =============================================================================
-- 9. Сводка по запускам и развёртываниям — для UI и API статуса
-- =============================================================================
CREATE VIEW v_job_summary AS
SELECT
    j.job_type,
    j.job_id,
    j.status,
    j.target_count,
    count(t.id)                                                     AS tasks,
    count(t.id) FILTER (WHERE t.state = 'queued')                   AS queued,
    count(t.id) FILTER (WHERE t.state IN ('dispatched', 'running')) AS in_progress,
    count(t.id) FILTER (WHERE t.state = 'succeeded')                AS succeeded,
    count(t.id) FILTER (WHERE t.state IN ('failed', 'timed_out'))   AS failed,
    count(t.id) FILTER (WHERE t.state = 'lost')                     AS lost,
    count(t.id) FILTER (WHERE t.state = 'rejected')                 AS rejected,
    count(t.id) FILTER (WHERE t.state IN ('canceled', 'expired'))   AS canceled_or_expired,
    count(t.id) FILTER (WHERE t.result = 'reboot_required')         AS reboot_required
FROM (
    SELECT 'script_run'::text AS job_type, id AS job_id, status, target_count FROM script_runs
    UNION ALL
    SELECT 'deployment', id, status, target_count FROM deployment_tasks
) j
LEFT JOIN agent_tasks t
       ON CASE j.job_type WHEN 'script_run' THEN t.script_run_id ELSE t.deployment_task_id END = j.job_id
GROUP BY j.job_type, j.job_id, j.status, j.target_count;

-- =============================================================================
-- 10. Настройки модуля и права рабочей роли
-- =============================================================================
INSERT INTO settings (key, value) VALUES
    ('execution', '{
        "enabled": false,
        "paused": false,
        "approval_required_above_targets": 25,
        "dispatch_lease_s": 600,
        "result_grace_s": 300,
        "max_dispatch_attempts": 3,
        "output_retention_days": 90
     }')
ON CONFLICT (key) DO NOTHING;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'invmon_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON
            user_permissions, scripts, script_versions, software_packages, software_package_versions,
            deployment_policies, device_execution_capabilities
        TO invmon_app;
        -- История выполнения и подписи не удаляются; у ключа меняется только revoked_at
        GRANT SELECT, INSERT, UPDATE ON script_runs, deployment_tasks, agent_tasks TO invmon_app;
        GRANT SELECT, INSERT ON signatures, signing_keys TO invmon_app;
        GRANT UPDATE (revoked_at) ON signing_keys TO invmon_app;
        GRANT SELECT ON v_job_summary TO invmon_app;
        GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO invmon_app;
    END IF;
END $$;
