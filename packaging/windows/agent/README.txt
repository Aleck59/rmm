InvMon Agent
============

Содержимое пакета:
  invmon-agent.exe    — агент (служба Windows)
  install.ps1         — установка службы
  uninstall.ps1       — удаление службы
  agent.example.yaml  — пример конфигурации
  LICENSE

Поддерживаемые ОС:
  Windows 7 SP1, 8.1, 10, 11 (x86 / x64; arm64 — Windows 11).
  Сборки с суффиксом -win7 предназначены для Windows 7/8.1 и
  Server 2008 R2 / 2012 / 2012 R2.

Установка (PowerShell от имени администратора):
  .\install.ps1 -ServerUrl https://invmon.corp.local:8443 `
      -EnrollToken imenr_XXXX -CaFile .\ca.pem -Start

Массовое развёртывание:
  Пакет разворачивается через SCCM/PDQ/GPO. Токен регистрации выпускается
  в веб-интерфейсе; у каждой волны развёртывания — свой токен с ограниченным
  сроком и числом использований.

После установки:
  - конфигурация:  C:\ProgramData\InvMon\Agent\agent.yaml
  - журналы:       C:\ProgramData\InvMon\Agent\logs

Ручной запуск в консоли (для отладки):
  .\invmon-agent.exe run --config C:\ProgramData\InvMon\Agent\agent.yaml

Примечание: это сборка этапа 0 (каркас). Агент устанавливается как служба,
запускается и корректно останавливается; сбор метрик, инвентаризация и связь
с сервером добавляются на этапе 1. Агент не принимает команд и не открывает
входящих сетевых портов.
