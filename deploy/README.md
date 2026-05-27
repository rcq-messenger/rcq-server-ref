# Reference deployment scripts

These are the actual scripts running `api.rcq.app`, kept here as a
reference for self-hosters. They reference the `rcq.app` domain and a
DigitalOcean droplet IP throughout — when adapting:

* **Caddyfile**: swap every `rcq.app` / `api.rcq.app` / `admin.rcq.app`
  / `chat.rcq.app` for your own domain. The site blocks are the
  template; the certificates are issued automatically by Caddy on
  first hit if your DNS points at the host.
* **rcq-backend.service**: the systemd unit. The `WorkingDirectory`,
  `EnvironmentFile`, `ExecStart` and the `User` will all need to
  match your install path.
* **bootstrap.sh**: idempotent host setup (apt install + venv + Caddy
  + systemd) for an Ubuntu 22.04 / 24.04 box. Read it before running —
  it expects a fresh droplet and will refuse to clobber an existing
  install.
* **deploy.sh**: rsync the local `backend/` into `/opt/rcq/app/backend/`
  on a running host + restart the service. Useful for the maintainer's
  workflow; less useful for a one-off self-host where you'd just
  `docker compose up -d` from the repo root.

If you're self-hosting and just want to get going, the
`docker-compose.yml` at the repo root is the friendlier path. These
scripts are here because the production deploy is the production
deploy, and pretending it's anything cleaner would be dishonest.
