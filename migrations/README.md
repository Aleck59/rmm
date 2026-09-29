# Миграции БД

Миграции живут в [`../internal/store/migrations/`](../internal/store/migrations/) и
встраиваются в бинарник сервера (`go:embed`). Сервер применяет их при старте
(`invmon-server run`) или по команде `invmon-server migrate`: версионные SQL-файлы,
каждый в своей транзакции, под `pg_advisory_lock`, только вперёд. Применённые версии
записываются в таблицу `schema_migrations`.

`0001_core.sql` побайтно совпадает с [`../docs/db/schema.sql`](../docs/db/schema.sql)
(проектная схема, её проверяет `docs/db/verify.sql`); CI сверяет файлы командой `cmp`.
Новые изменения схемы — только новыми файлами `000N_*.sql`.
