import { useEffect, useState } from 'react'

interface VersionInfo {
  version: string
  commit: string
  date: string
  go: string
  platform: string
}

type Health = 'checking' | 'ok' | 'error'

export default function App() {
  const [version, setVersion] = useState<VersionInfo | null>(null)
  const [health, setHealth] = useState<Health>('checking')

  useEffect(() => {
    fetch('/version')
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
      .then((data: VersionInfo) => setVersion(data))
      .catch(() => setVersion(null))

    fetch('/healthz')
      .then((r) => setHealth(r.ok ? 'ok' : 'error'))
      .catch(() => setHealth('error'))
  }, [])

  return (
    <main className="shell">
      <header>
        <h1>InvMon</h1>
        <p className="tagline">Мониторинг и инвентаризация парка Windows-ПК</p>
      </header>

      <section className="card">
        <h2>Состояние сервера</h2>
        <ul className="facts">
          <li>
            <span>Сервер</span>
            <span className={`badge badge--${health}`}>
              {health === 'checking' ? 'проверка…' : health === 'ok' ? 'доступен' : 'недоступен'}
            </span>
          </li>
          <li>
            <span>Версия</span>
            <span>{version ? version.version : '—'}</span>
          </li>
          <li>
            <span>Сборка</span>
            <span>{version ? `${version.commit} · ${version.date}` : '—'}</span>
          </li>
          <li>
            <span>Платформа</span>
            <span>{version ? `${version.platform} · ${version.go}` : '—'}</span>
          </li>
        </ul>
      </section>

      <p className="note">
        Каркас интерфейса (этап 0). Список устройств, метрики и алерты появляются на следующих
        этапах разработки.
      </p>
    </main>
  )
}
