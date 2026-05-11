# Limestone: Kanban/Calendar

Limestone is a self-hosted kanban and calendar app for small teams and personal operations. This public repository contains the Docker-ready runtime package: the built frontend, the Node/Express server, SQLite persistence, and the files needed to clone, configure, and run it on a VPS.

## Showcase

- Projects: organize work into separate project spaces.
- Kanban columns: track cards through board columns with a focused day-to-day workflow.
- Action calendar: schedule and review actions in a calendar view.
- Notes: keep project context beside the board and calendar.
- Accounts and admin: protected login, admin-managed users, and profile password changes.
- Themes and language: light/dark mode, theme presets, and English/Turkish UI text.
- Realtime updates: Socket.IO keeps connected sessions in sync.
- SQLite persistence: app data lives in a Docker volume at `/data`.
- Docker deployment: build and run with the included `Dockerfile` and `docker-compose.yml`.

## Quick Start

```bash
git clone https://github.com/Bl4ckbamba/Limestone-Kanban-Calendar.git
cd Limestone-Kanban-Calendar
cp release.env.example .env
```

Edit `.env` before first start, especially `SESSION_SECRET`. Then run:

```bash
docker compose --env-file .env up -d --build
```

Open `http://your-server:3000` unless you changed `LIMESTONE_PORT`.

## First Login

When the database is empty, Limestone creates the first admin account automatically.

Default credentials:

```text
admin / admin
```

That default password is temporary. After login, the app requires a password change before normal use. If you set a custom `ADMIN_PASSWORD` before first startup, it must be at least 10 characters and the forced-change flag is not applied.

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `SESSION_SECRET` | none | Required in production. Use a long random value. |
| `SESSION_COOKIE_SECURE` | `auto` | Session cookie secure mode. Use `auto` behind trusted HTTPS proxies, `true` for HTTPS-only deployments, or `false` only for direct HTTP/local checks. |
| `ADMIN_USERNAME` | `admin` | Initial admin username when no admin exists. |
| `ADMIN_PASSWORD` | `admin` | Initial admin password when no admin exists. The default forces a password change. Custom values must be at least 10 characters. |
| `LIMESTONE_PORT` | `3000` | Host port exposed by Docker Compose. |
| `TRUST_PROXY` | `1` | Express trust proxy setting. Use deliberately when behind a trusted reverse proxy. Set `false` when directly exposed without a proxy. |
| `LOGIN_BAN_ATTEMPT_LIMIT` | `15` | Failed login attempts allowed during the rolling window. |
| `LOGIN_BAN_WINDOW_MS` | `900000` | Rolling window for counting failed login attempts, in milliseconds. |
| `LOGIN_BAN_DURATION_MS` | `900000` | Length of an IP login ban, in milliseconds. |

SQLite data is stored in the named Docker volume `limestone-data`, mounted inside the container at `/data`.

## Upgrade

Update the repository and rebuild the container:

```bash
git pull
docker compose --env-file .env up -d --build
```

The Docker volume is kept, so the SQLite database persists across rebuilds. Back up the `limestone-data` volume before major upgrades or VPS maintenance.

## Runtime Package

This repository is the deployable Limestone runtime package, not the full private development source tree. It includes:

- `dist/`: built frontend assets.
- `server/`: production Node/Express runtime.
- `bin/limestone`: packaged Limestone CLI binary when available.
- `Dockerfile` and `docker-compose.yml`: container runtime.
- `release-manifest.json`: version, source commit, build node version, and packaging timestamp.

## License And Attribution

Limestone is licensed under the Apache License, Version 2.0. See `LICENSE`.

Attribution and project notice information are in `NOTICE`.
