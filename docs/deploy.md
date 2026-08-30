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

### Get the support files

`.env.example` and everything under `deploy/` are **not** installed by the package —
`pipx`/`pip` ship only the Python code and the `mudauth` entry point. Every `sudo cp`
in the steps below copies from a checkout of the source repository, so fetch one now.
The repository URL is the `Home-page` field of the installed package metadata:

```bash
pipx runpip mudauth show mudauth | grep '^Home-page:'   # pip show mudauth, if you used pip
git clone <that URL> ~/mudauth-src                      # or download and unpack the zip
cd ~/mudauth-src
```

Run the rest of this guide from that directory. Nothing on the host depends on it
afterwards — it is only a source of files to copy — so you can delete it once the
service is up.

## 2. Configure the environment

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

## 4. Add the reverse proxy and TLS

Use whichever of the two sections below matches your web server. Skip the other one.

### nginx

Install the shipped `/auth/` location block as an nginx snippet:

```bash
sudo mkdir -p /etc/nginx/snippets
sudo cp deploy/nginx/mudauth.conf /etc/nginx/snippets/mudauth.conf
```

Then define the rate-limit zone once at `http{}` scope, and include the snippet from
the HTTPS `server { }` block that serves mud.example — the same block certbot manages:

```nginx
# http { } scope
limit_req_zone $binary_remote_addr zone=auth:10m rate=10r/s;
```

```nginx
# inside the mud.example server { } block
include snippets/mudauth.conf;
```

(If you would rather not keep a snippet file, paste the contents of
[`../deploy/nginx/mudauth.conf`](../deploy/nginx/mudauth.conf) into the `server { }`
block instead of the `include` line. The `limit_req_zone` still has to go at `http{}`
scope either way.)

Then obtain/renew TLS and reload:

```bash
sudo certbot --nginx -d mud.example -d www.mud.example
sudo nginx -t && sudo systemctl reload nginx
```

### Apache

Apache has no snippet-include convention to copy a file into, so these directives go
**inside** the HTTPS `<VirtualHost *:443>` that serves mud.example — the block certbot
manages, typically `/etc/apache2/sites-available/mud.example-le-ssl.conf`. Find it with
`sudo apache2ctl -S`:

```apache
ProxyPreserveHost On
RequestHeader set X-Forwarded-Proto "https"

ProxyPass        /auth/ http://127.0.0.1:7700/auth/
ProxyPassReverse /auth/ http://127.0.0.1:7700/auth/
```

Enable the modules once, then validate and reload:

```bash
sudo a2enmod proxy proxy_http headers
sudo certbot --apache -d mud.example -d www.mud.example
sudo apache2ctl configtest && sudo systemctl reload apache2
```

[`../deploy/apache/mudauth.conf`](../deploy/apache/mudauth.conf) is the same snippet
with commentary on canonical hosts, rate limiting, and running a second instance. Do
not `Include` it as a vhost of its own.

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
