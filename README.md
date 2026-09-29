# InvMon — мониторинг и инвентаризация парка Windows-ПК

Система для внутреннего ИТ-отдела: централизованный сбор метрик (CPU, RAM, свободное место на дисках), инвентаризация оборудования и установленного ПО на ПК организации, веб-интерфейс, настраиваемые алерты и уведомления по email и webhook.

В текущей версии (MVP) система только наблюдает за устройствами, принадлежащими организации: агент не принимает команд, не открывает входящих портов и не собирает пользовательские данные.

**Статус:** этап 1 — регистрация агентов и приём метрик. Агент регистрируется по
токену, хранит идентичность под DPAPI и отправляет метрики (CPU, RAM, свободное место);
сервер принимает их в партиционированные таблицы PostgreSQL. Веб-API и интерфейс
администратора — следующие этапы.

**Спроектирован, не реализован (v2.0):** модуль выполнения скриптов и управления ПО для
внутреннего ИТ-отдела — [docs/execution.md](docs/execution.md). Выключен по умолчанию,
включается только локальной политикой ПК (GPO); агент выполняет лишь код и установщики,
подписанные двумя сотрудниками аппаратными ключами; все действия — в аудите и SIEM.

## Документация

| Документ | Содержание |
|---|---|
| [docs/architecture.md](docs/architecture.md) | архитектура, стек, агент, сервер, БД, API, безопасность, развёртывание, план MVP |
| [docs/development.md](docs/development.md) | сборка, запуск, проверки, CI/CD и релизы |
| [docs/db/schema.sql](docs/db/schema.sql) | схема PostgreSQL |
| [docs/db/verify.sql](docs/db/verify.sql) | исполняемая проверка схемы и SQL-примеров из документа |
| [docs/api/openapi.yaml](docs/api/openapi.yaml) | контракт API (OpenAPI 3.1): агент и веб-интерфейс |
| [docs/execution.md](docs/execution.md) | проект v2.0: выполнение скриптов, каталог ПО, развёртывание, модель угроз |
| [docs/db/schema_execution.sql](docs/db/schema_execution.sql) | схема модуля выполнения (проверяется тем же `verify.sql`) |

## Сборка и запуск

```sh
make web       # собрать SPA в internal/webui/dist (Vite)
make build     # собрать bin/invmon-server и bin/invmon-agent
./bin/invmon-server run --addr :8080     # затем открыть http://localhost:8080/

make dist      # кросс-сборка и упаковка релизных артефактов в dist/
```

Полный список команд — `make help`; подробности — [docs/development.md](docs/development.md).

## Релизы

Тег `vX.Y.Z` запускает сборку и публикует GitHub Release с установочными
пакетами:

- `invmon-server-<ver>-windows-<arch>.zip` — сервер + `install.ps1` (регистрация службы);
- `invmon-agent-<ver>-windows-<arch>.zip` — агент + `install.ps1`; сборки `-win7` для Windows 7/8.1;
- `invmon-server-<ver>-linux-amd64.tar.gz` и `SHA256SUMS`.

Установщики этапа 0 — ZIP со службой Windows и скриптом установки; MSI и подпись
кода — этап 4.

## Ключевые решения

| Слой | Выбор |
|---|---|
| Агент | Go, служба Windows, MSI; Windows 7 SP1 – 11 (x86, x64, arm64) |
| Сервер | Go, один исполняемый файл со встроенным веб-интерфейсом, служба Windows Server |
| БД | PostgreSQL 17/18; метрики партиционированы по суткам |
| Очереди | без отдельного брокера: очередь задач в PostgreSQL (River) и буфер на стороне агента |
| Frontend | React + TypeScript |
| Безопасность | TLS 1.2/1.3, токены регистрации и токены устройств, роли admin / operator / viewer, неизменяемый журнал аудита |

## Проверка артефактов

```sh
# Схема БД: пустая база, запуск от суперпользователя PostgreSQL 16+
createdb invmon_verify
psql -X -q -v ON_ERROR_STOP=1 -d invmon_verify -f docs/db/verify.sql   # → ALL CHECKS PASSED

# Контракт API
npx @redocly/cli lint docs/api/openapi.yaml
```
