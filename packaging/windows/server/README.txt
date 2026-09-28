InvMon Server
=============

Содержимое пакета:
  invmon-server.exe    — сервер (служба Windows)
  install.ps1          — установка службы
  uninstall.ps1        — удаление службы
  server.example.yaml  — пример конфигурации
  LICENSE

Требования:
  - Windows Server 2019 / 2022 / 2025 (для стенда подойдёт Windows 10/11)
  - PostgreSQL 17/18 (устанавливается отдельно; используется с этапа 1)

Установка (PowerShell от имени администратора):
  .\install.ps1 -Start

После установки:
  - конфигурация:  C:\ProgramData\InvMon\Server\server.yaml
  - журналы:       C:\ProgramData\InvMon\Server\logs
  - проверка:      http://<хост>/healthz  и  /version

Ручной запуск в консоли (для отладки):
  .\invmon-server.exe run --addr :8080

Управление службой:
  .\invmon-server.exe service start | stop | uninstall
  или стандартно: Start-Service / Stop-Service InvMonServer

Примечание: это сборка этапа 0 (каркас). Доступны веб-интерфейс-заглушка и
эндпоинты /healthz, /readyz, /version. Приём данных от агентов, база данных и
веб-API добавляются на следующих этапах.
