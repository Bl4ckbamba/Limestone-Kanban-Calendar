# Limestone Runtime Wiki

This wiki documents the public Limestone runtime repository. It is written for
operators and maintainers who need to understand what is included in the
deployable package, how the app runs, and how to update it safely.

This repository intentionally does not document any private infrastructure,
server addresses, credentials, SSH details, domain names, or production paths.
Keep deployment-specific information in your own secure operations system.

## Repository Purpose

Limestone is a self-hosted kanban, calendar, and notes workspace. The public
repository is the runtime package: it contains the built frontend, the
production Node.js backend, Docker configuration, screenshots, license files,
and release metadata needed to run the application.

The repository is suitable for direct deployment with Docker Compose. It is not
the private development source tree and does not include the original React
source modules or build scripts used to create the packaged frontend assets.

## Top-Level Layout

| Path | Purpose |
| --- | --- |
| `dist/` | Built browser assets served by the backend in production. |
| `server/` | Express, Socket.IO, SQLite, authentication, and session runtime. |
| `bin/` | Packaged CLI entrypoint when included in a release. |
| `screenshots/` | Public screenshots used by the README. |
| `Dockerfile` | Production container image definition. |
| `docker-compose.yml` | Generic self-hosting Compose file. |
| `release.env.example` | Environment variable template for operators. |
| `release-manifest.json` | Release metadata, including packaged version information. |
| `README.md` | Public overview, feature tour, and basic self-hosting instructions. |
| `docs/wiki/` | Maintainer and operator documentation for this runtime package. |

## Runtime Architecture

The application runs as one Node.js process:

- Express serves the login page, protected application shell, static assets, and
  JSON API routes.
- Socket.IO pushes realtime project and calendar changes to authenticated users.
- SQLite stores users, sessions, projects, cards, calendar events, notes, and
  action history.
- `express-session` uses a SQLite-backed session store so logins survive process
  restarts.
- Helmet and explicit public/private route handling protect the application
  shell from unauthenticated access.

The frontend is already built into `dist/`. In production the server serves
those files directly, so no Vite dev server is required.

## Data Model Summary

The SQLite database contains:

- `users`: admin and non-admin accounts.
- `projects`: project workspaces with display color metadata.
- `cards`: kanban cards, status, ordering, optional calendar date, and creator.
- `card_actions`: audit-style activity records used by project views.
- `calendar_events`: date and time based calendar items with repeat settings.
- `notes`: shared note documents.
- `user_preferences`: per-user UI preferences.
- `sessions`: persisted login sessions.
- `login_ip_attempts`: login throttling and temporary ban state.

Date-only fields such as card event dates and calendar event start dates are
stored as `YYYY-MM-DD`. Timestamp fields are serialized by the API as explicit
UTC ISO strings so browsers do not reinterpret SQLite `CURRENT_TIMESTAMP`
values as local time.

## Configuration

Configure the app with environment variables. Use `release.env.example` as the
starting point and set real values before production startup.

Required production values:

- `SESSION_SECRET`: long random value used to sign sessions.
- `ADMIN_PASSWORD`: strong initial admin password for the first startup.

Important optional values:

- `ADMIN_USERNAME`: first admin username, defaulting to `admin`.
- `DATABASE_PATH`: SQLite file location inside the container.
- `SESSION_COOKIE_SECURE`: `auto`, `true`, or `false`.
- `TRUST_PROXY`: set deliberately only when the app is behind a trusted proxy.
- `LOGIN_BAN_ATTEMPT_LIMIT`, `LOGIN_BAN_WINDOW_MS`, `LOGIN_BAN_DURATION_MS`:
  login abuse throttling controls.

Do not commit filled `.env` files, generated secrets, database files, logs, or
host-specific deployment notes.

## Deployment Model

The generic deployment flow is:

1. Clone the public repository.
2. Copy `release.env.example` to an untracked `.env`.
3. Fill production secrets and configuration.
4. Build and start with Docker Compose.
5. Put the service behind your chosen HTTPS reverse proxy if you expose it to
   the internet.

The default Compose file mounts SQLite data into a named Docker volume so data
persists across image rebuilds. Back up that volume before major upgrades or
host maintenance.

## Updating

For a normal runtime update:

```bash
git pull
docker compose --env-file .env up -d --build
```

Then verify the container is healthy and that the login page returns a success
status through the public route you operate.

Because data is in the Docker volume, rebuilding the image does not reset the
database. Schema changes are handled by the server startup code when migrations
are present.

## Maintainer Notes

Changes in this public runtime repository should stay narrow and production
oriented:

- Keep security-sensitive or deployment-specific information out of git.
- Avoid documenting private hosts, domains, user names, keys, or absolute server
  paths.
- Keep generated frontend assets and server runtime behavior aligned.
- Validate server changes with syntax checks and a runtime smoke check when
  practical.
- Use clear commit messages that describe behavior, not only touched files.

