# Разработка InvMon

Этот документ описывает, как собрать, запустить и проверить сервер, агент и
веб-интерфейс, и как устроен CI/CD с релизами. Реализовано: этап 0 (каркас, CI/CD)
и этап 1 (регистрация агентов и приём метрик).
Архитектура целиком — в [architecture.md](architecture.md).

## Требования

| Инструмент | Версия | Зачем |
|---|---|---|
| Go | ≥ 1.26 (CI — 1.27) | сервер и агент |
| Node.js | 22 | сборка SPA |
| pnpm | 10 | пакеты SPA |
| PostgreSQL | 16+ (прод — 17/18) | БД сервера, интеграционные тесты |
| golangci-lint | 2.14.x | линтер Go |

Для сборки агента под Windows 7/8.1 используется форк
[go-legacy-win7](https://github.com/thongtech/go-legacy-win7) (см. раздел о релизах).

## Раскладка репозитория

```
cmd/invmon-server/     точка входа сервера (run | version | service)
cmd/invmon-agent/      точка входа агента  (run | version | service)
internal/buildinfo/    версия и метаданные сборки (задаются через -ldflags)
internal/cliutil/      общие помощники CLI: логирование, версия, служба
internal/winservice/   установка и супервизия службы Windows (+заглушка для не-Windows)
internal/server/       процесс сервера: веб-листенер (/healthz, /readyz, /version, SPA),
                       агентский листенер, обслуживание партиций
internal/agentapi/     Agent API: регистрация, приём метрик, конфигурация, ротация токена
internal/store/        слой PostgreSQL (pgx) и встроенные миграции (store/migrations/)
internal/protocol/     типы протокола агент ↔ сервер (зеркало OpenAPI)
internal/tokens/       генерация и хэширование токенов (imenr_ / imagt_)
internal/ratelimit/    ограничение частоты запросов
internal/agent/        агент: регистрация, DPAPI-состояние, сборщики, отправка
internal/webui/        встраивание собранного SPA (go:embed); dist/index.html — заглушка
web/                   исходники SPA (Vite + React + TypeScript)
migrations/            указатель на internal/store/migrations
packaging/windows/     шаблоны установщиков: install.ps1, uninstall.ps1, конфиги
scripts/build-dist.sh  кросс-сборка и упаковка релизных артефактов
docs/                  архитектура, схема БД, OpenAPI, этот файл;
                       execution.md + db/schema_execution.sql — проект модуля выполнения (v2.0)
.github/workflows/     CI и релизы
```

Модуль Go: `github.com/Aleck59/rmm`.

## Быстрый старт

```sh
# зависимости Go
go mod download

# сборка SPA в каталог встраивания (internal/webui/dist)
make web

# сборка бинарников в bin/
make build

# запуск сервера локально на :8080 (по умолчанию plain HTTP — только для разработки)
./bin/invmon-server run --addr :8080
# проверка:
curl -s localhost:8080/healthz   # ok
curl -s localhost:8080/version   # JSON с версией
open  http://localhost:8080/     # веб-интерфейс

# агент в консольном режиме
./bin/invmon-agent run
```

> После `make web` каталог `internal/webui/dist` содержит собранный SPA.
> Перед коммитом верните заглушку: `make restore-webui` (собранные ассеты не
> коммитятся, их пересобирает CI).

### Режим разработки SPA

```sh
# терминал 1: сервер API
make run-server
# терминал 2: Vite с горячей перезагрузкой (проксирует /api, /version и т.д. на :8080)
cd web && pnpm dev
```

## Этап 1: регистрация агентов и приём метрик

Нужен PostgreSQL. Сервер применяет миграции при старте (или `migrate`).

```sh
export INVMON_DATABASE_URL='postgres://postgres@127.0.0.1:5432/invmon?sslmode=disable'
createdb invmon

./bin/invmon-server migrate
./bin/invmon-server run --addr :8080 --agent-addr :8443     # веб :8080, агенты :8443

# токен регистрации (показывается один раз; в БД — только SHA-256)
./bin/invmon-server token create --name "Пилот" --days 7 --max-uses 20 [--manual-approve]

# агент (на машине разработчика — синтетический сборщик; на Windows — реальный)
cat > agent.yaml <<YAML
server_url: 'http://127.0.0.1:8443'
enroll_token: 'imenr_...'
allow_insecure: true        # только для разработки: http без TLS
YAML
./bin/invmon-agent run --config ./agent.yaml
```

После регистрации агент сохраняет идентичность в `state.bin` рядом с конфигом (на Windows —
под DPAPI) и заменяет `enroll_token` в `agent.yaml` пустым значением. Одобрить устройство
(при `--manual-approve`) или отозвать его:

```sh
./bin/invmon-server device set-status --id 1 --status active     # или revoked / retired
```

Что проверить в БД: `devices`, `device_state` (последние значения), `metrics_host`,
`metrics_disk` (партиции по суткам), `audit_log` (`enrollment_token.create`, `agent.enroll`).

Интеграционные тесты (хранилище, Agent API, сквозной тест агента) создают и удаляют
временные базы; без переменной окружения они пропускаются:

```sh
INVMON_TEST_DATABASE_URL='postgres://postgres@127.0.0.1:5432/postgres?sslmode=disable' go test -race ./...
```

## Проверки (как в CI)

```sh
gofmt -l .            # должно быть пусто
go vet ./...
go test -race ./...
make lint             # golangci-lint
make vulncheck        # govulncheck (информационно)

cd web && pnpm lint && pnpm typecheck && pnpm build

# схема БД (нужен запущенный PostgreSQL; см. ниже)
createdb invmon_verify
psql -X -q -v ON_ERROR_STOP=1 -d invmon_verify -f docs/db/verify.sql   # → ALL CHECKS PASSED

# контракт API
npx @redocly/cli lint docs/api/openapi.yaml
```

## Служба Windows

`internal/winservice` собирается на всех платформах: на Windows это реальная
работа через SCM (`golang.org/x/sys/windows/svc`), на прочих ОС — заглушки, а
`run` управляется сигналами (Ctrl+C / SIGTERM). Поэтому агент и сервер можно
разрабатывать и тестировать на Linux/macOS, а собирать под Windows.

```powershell
# на Windows, от администратора
invmon-server.exe service install
invmon-server.exe service start
invmon-server.exe service stop
invmon-server.exe service uninstall
```

## CI

Workflow `.github/workflows/ci.yml` (push в `main` и `claude/**`, PR в `main`):

| Задача | Что делает |
|---|---|
| `go` | `gofmt`, `go vet`, `go test -race`, кросс-компиляция всех целей |
| `lint` | golangci-lint 2.14.0 |
| `web` | `pnpm install --frozen-lockfile`, lint, typecheck, build |
| `openapi` | `redocly lint docs/api/openapi.yaml` |
| `db` | PostgreSQL 16: сверка `0001_core.sql` с `docs/db/schema.sql`, `verify.sql`, интеграционные тесты Go |
| `vulncheck` | govulncheck (информационно, не блокирует) |

## Релизы

Тег `vX.Y.Z` → workflow `.github/workflows/release.yml`:

1. собирает SPA и встраивает её в сервер;
2. кросс-компилирует сервер и агент (Windows x64/x86/arm64, Linux x64) с
   версией из тега;
3. по возможности собирает агент для Windows 7/8.1 форком go-legacy-win7
   (пакеты с суффиксом `-win7`). Шаг best-effort: он тянет сторонний
   репозиторий, поэтому на изолированных раннерах без доступа к внешним
   релизам github.com он пропускается и публикуются только стандартные сборки
   для Windows 10+. Полноценная проверка Windows 7/8.1 — прототип на VM (этап 0
   дорожной карты); для стабильной сборки `-win7` в CI toolchain форка стоит
   зеркалировать во внутреннем хранилище артефактов;
4. упаковывает установочные пакеты и `SHA256SUMS`;
5. публикует GitHub Release с этими файлами.

Состав релиза:

| Артефакт | Содержимое |
|---|---|
| `invmon-server-<ver>-windows-<arch>.zip` | `invmon-server.exe`, `install.ps1`, `uninstall.ps1`, `server.example.yaml`, README, LICENSE |
| `invmon-agent-<ver>-windows-<arch>.zip` | `invmon-agent.exe`, `install.ps1`, `uninstall.ps1`, `agent.example.yaml`, README, LICENSE |
| `invmon-agent-<ver>-windows-<arch>-win7.zip` | то же, сборка для Windows 7/8.1 (если собралась) |
| `invmon-server-<ver>-linux-amd64.tar.gz` | бинарник сервера под Linux |
| `SHA256SUMS` | контрольные суммы всех артефактов |

Локальная сборка релиза целиком:

```sh
make dist                      # или: VERSION=v0.1.0 bash scripts/build-dist.sh
SKIP_WEB=1 make dist           # без пересборки SPA
```

> MSI-установщики агента и подпись кода — этап 4 дорожной карты. На этапе 0
> установщик — это ZIP с `install.ps1`, который регистрирует службу через
> `invmon-agent.exe service install`.
