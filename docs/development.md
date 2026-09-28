# Разработка InvMon

Этот документ описывает каркас репозитория (этап 0): как собрать, запустить и
проверить сервер, агент и веб-интерфейс, и как устроен CI/CD с релизами.
Архитектура целиком — в [architecture.md](architecture.md).

## Требования

| Инструмент | Версия | Зачем |
|---|---|---|
| Go | ≥ 1.24 | сервер и агент |
| Node.js | 22 | сборка SPA |
| pnpm | 10 | пакеты SPA |
| PostgreSQL client (`psql`) | 16+ | проверка схемы БД |
| golangci-lint | 2.5.x | линтер Go |

Для сборки агента под Windows 7/8.1 используется форк
[go-legacy-win7](https://github.com/thongtech/go-legacy-win7) (см. раздел о релизах).

## Раскладка репозитория

```
cmd/invmon-server/     точка входа сервера (run | version | service)
cmd/invmon-agent/      точка входа агента  (run | version | service)
internal/buildinfo/    версия и метаданные сборки (задаются через -ldflags)
internal/cliutil/      общие помощники CLI: логирование, версия, служба
internal/winservice/   установка и супервизия службы Windows (+заглушка для не-Windows)
internal/server/       HTTP-сервер: /healthz, /readyz, /version, отдача SPA
internal/agent/        каркас агента (конфиг, цикл; сбор данных — этап 1)
internal/webui/        встраивание собранного SPA (go:embed); dist/index.html — заглушка
web/                   исходники SPA (Vite + React + TypeScript)
migrations/            миграции БД (пусто; первая миграция = docs/db/schema.sql на этапе 1)
packaging/windows/     шаблоны установщиков: install.ps1, uninstall.ps1, конфиги
scripts/build-dist.sh  кросс-сборка и упаковка релизных артефактов
docs/                  архитектура, схема БД, OpenAPI, этот файл
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
| `lint` | golangci-lint 2.5.0 |
| `web` | `pnpm install --frozen-lockfile`, lint, typecheck, build |
| `openapi` | `redocly lint docs/api/openapi.yaml` |
| `db` | поднимает PostgreSQL 16 и прогоняет `docs/db/verify.sql` |
| `vulncheck` | govulncheck (информационно, не блокирует) |

## Релизы

Тег `vX.Y.Z` → workflow `.github/workflows/release.yml`:

1. собирает SPA и встраивает её в сервер;
2. кросс-компилирует сервер и агент (Windows x64/x86/arm64, Linux x64) с
   версией из тега;
3. по возможности собирает агент для Windows 7/8.1 форком go-legacy-win7
   (пакеты с суффиксом `-win7`; шаг best-effort и не блокирует релиз);
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
