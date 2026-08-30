# Deploying mudauth

A long-lived loopback listener managed by **systemd**, fronted by **nginx**
terminating TLS via **certbot**. The MUD never accepts inbound HTTP — nginx proxies
the public `/auth/` path to `127.0.0.1:7700`, and the game talks to the same loopback
port.

```text
Browser ──HTTPS──> nginx (mud.example:443) ──/auth/──> 127.0.0.1:7700 (this service)
Game    ──loopback ────────────────────────────────────> 127.0.0.1:7700
```

## 1. Install

Create an unprivileged user for the service and install the package as that user:

```bash
sudo adduser --system --group --home /home/mudauth mudauth
sudo -u mudauth -H pipx install mudauth     # or: pip install --user mudauth
```

Requirements: Python 3.11+ and the standard library. `mudauth` has no runtime
dependencies. (`mudauth apple-secret` is the one exception — it needs the optional
`apple` extra, and you only ever run it by hand.)

The service is stateless, so there is no data directory to provision.

## 2. Configure the environment

`.env.example` and the files under `deploy/` are not installed by the package; take
them from a checkout or download of the source repository (the `Homepage` URL in the
package metadata).

```bash
sudo mkdir -p /etc/mudauth
sudo cp .env.example /etc/mudauth/.env
sudo chown root:mudauth /etc/mudauth/.env && sudo chmod 640 /etc/mudauth/.env
sudoedit /etc/mudauth/.env
```

Set, at minimum:

- `AUTH_PUBLIC_BASE=https://mud.example` (the host root — the prefix BEFORE
  the service's own `/auth/*` routes; the game appends `/auth/login/...`)
- `AUTH_CALLBACK_URL=https://mud.example/auth/callback`
- `AUTH_BIND=127.0.0.1:7700`
- One or more provider `*_CLIENT_ID` / `*_CLIENT_SECRET` pairs. Only providers
  with **both** set appear in the login menu.

Register `https://mud.example/auth/callback` as the redirect URI in each
provider's developer console. See [providers.md](providers.md).

## 3. Install the systemd unit

```bash
sudo cp deploy/mudauth.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now mudauth
systemctl status mudauth
journalctl -u mudauth -f
```

> The shipped unit runs `ExecStart=/home/mudauth/.local/bin/mudauth serve`, which is
> where `pipx`/`pip --user` put the entry point for a home under `/home`. It sets
> `ProtectHome=read-only` so systemd can still execute it; if you installed
> somewhere outside `/home`, point `ExecStart` there and tighten to
> `ProtectHome=yes`.

## 4. Add the nginx proxy and TLS

> Using Apache instead of nginx? See [`../deploy/apache/mudauth.conf`](../deploy/apache/mudauth.conf)
> for the equivalent `ProxyPass` directives; the rest of this section is nginx-specific.

Add the `/auth/` location block to the HTTPS `server { }` for mud.example, and
define the rate-limit zone once at `http{}` scope:

```nginx
# http { } scope
limit_req_zone $binary_remote_addr zone=auth:10m rate=10r/s;
```

```bash
# inside the mud.example server block
include snippets/mudauth.conf;   # from deploy/nginx/mudauth.conf
```

Then obtain/renew TLS and reload:

```bash
sudo certbot --nginx -d mud.example -d www.mud.example
sudo nginx -t && sudo systemctl reload nginx
```

## 5. Point the running game at the service

- Set `AUTH_SERVICE_URL=http://127.0.0.1:7700` in the game's environment, matching
  `AUTH_BIND`.
- LDMud games: `pip install "mudauth[ldmud]"` to register the
  `auth_service_request` efun, then restart the driver so it loads.
- Everything else: call the endpoints directly. See [integrating.md](integrating.md).

The browser-facing base URL can be **derived automatically**: `GET /auth/providers`
reports `public_base` (the service's `AUTH_PUBLIC_BASE`), so a game can adopt it and
need no URL configuration of its own.

## 6. Verify

```bash
mudauth check --env-file /etc/mudauth/.env    # config + reachability, exit 1 on problems
curl -fsS https://mud.example/auth/healthz    # public path via the proxy
curl -fsS http://127.0.0.1:7700/auth/providers # loopback, on the server
```

`mudauth check` prints the public base and the enabled providers with their callback
URLs. It warns about a public base that already ends in `/auth` (which would produce
`/auth/auth/*` URLs), and about any provider with only one of its two credentials set.
It then probes `/auth/healthz` on `AUTH_SERVICE_URL` if that is set, otherwise on the
`AUTH_BIND` listener. It exits 0 when clean and 1 when it found problems, so it is
usable from a monitoring script.

In game, the provider list should now offer your configured providers. Until then
the flow falls back to whatever login your game does with no providers configured.
