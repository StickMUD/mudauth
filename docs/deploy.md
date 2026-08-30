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
`apple` extra, and you only ever run it by hand.) `pipx` itself must be installed
system-wide (`sudo apt install pipx`) for the `sudo -u` invocation to find it; the
`pip install --user` alternative has the same effect.

That install puts the entry point at `/home/mudauth/.local/bin/mudauth`, which is
where the shipped systemd unit expects it. It is on the `mudauth` user's `PATH`, not
on yours — every later command in this guide either runs as root or names that path
in full.

The service is stateless, so there is no data directory to provision.

### Get the support files

`.env.example` and everything under `deploy/` are **not** installed by the package —
`pipx`/`pip` ship only the Python code and the `mudauth` entry point. Every `sudo cp`
in the steps below copies from a checkout of the source repository, so fetch one now,
as your own admin user:

```bash
git clone https://github.com/StickMUD/mudauth.git ~/mudauth-src
cd ~/mudauth-src
```

No git? Download and unpack the tarball instead:

```bash
curl -fsSL https://github.com/StickMUD/mudauth/archive/refs/heads/main.tar.gz \
  | tar xz -C ~ && cd ~/mudauth-main
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

Also **recommended**, though not required to get a first login working:
`AUTH_SERVICE_TOKEN`, a shared secret that lets the service identify your game
by something only it can present, instead of only by the *absence* of
forwarding headers. See step 5 below for what it does and the order to turn
it on safely — set it here now, but do not restart the service with it until
your game is already sending it.

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
RequestHeader set X-Real-IP "%{REMOTE_ADDR}s"
ProxyAddHeaders On

ProxyPass        /auth/ http://127.0.0.1:7700/auth/
ProxyPassReverse /auth/ http://127.0.0.1:7700/auth/
```

`ProxyAddHeaders On` is `mod_proxy`'s default, and it is what appends the client to
`X-Forwarded-For`. It is stated explicitly because turning it `Off` — a common privacy
hardening — would strip the forwarding headers, and every internet request would then
reach the service from `127.0.0.1` with nothing to distinguish it from the game's own
loopback calls: origin binding would be skipped entirely. The explicit `X-Real-IP` line
pins the other header the service reads rather than leaving it to an implicit default,
and overwrites any `X-Real-IP` the client sent.

Also suppress access logging for these requests. The request line carries the
`login_nonce`, `?code=` and Steam's signed assertion, so this vhost's `CustomLog` would
record live credentials for their 10-minute lifetime — the same exposure nginx's
`access_log off` closes. Amend the vhost's existing `CustomLog`, rather than adding a
second one:

```apache
SetEnvIf Request_URI "^/auth/" auth_request
CustomLog /var/log/apache2/mud.example-access.log combined env=!auth_request
```

Enable the modules once, then validate and reload:

```bash
sudo a2enmod proxy proxy_http headers setenvif
sudo certbot --apache -d mud.example -d www.mud.example
sudo apache2ctl configtest && sudo systemctl reload apache2
```

[`../deploy/apache/mudauth.conf`](../deploy/apache/mudauth.conf) is the same snippet
with commentary on canonical hosts, access logging, rate limiting, and running a second
instance. Do not `Include` it as a vhost of its own.

## 5. Point the running game at the service

- Set `AUTH_SERVICE_URL=http://127.0.0.1:7700` in the game's environment, matching
  `AUTH_BIND`.
- LDMud games: `pip install "mudauth[ldmud]"` to register the
  `auth_service_request` efun, then restart the driver so it loads. It must go into
  the Python interpreter your driver was built against, not the `mudauth` user's
  pipx environment — those are separate installs and the efun is loaded by the driver.
- Everything else: call the endpoints directly. See [integrating.md](integrating.md).

The browser-facing base URL can be **derived automatically**: `GET /auth/providers`
reports `public_base` (the service's `AUTH_PUBLIC_BASE`), so a game can adopt it and
need no URL configuration of its own.

### Identifying the game with `AUTH_SERVICE_TOKEN` (recommended)

By default, the service tells the game's own loopback poll apart from a browser
request by the **absence** of `X-Forwarded-For`/`X-Real-IP` — a real browser request
arrives through your reverse proxy, which adds those headers; the game's own poll
doesn't have them. That is evidence of absence, not evidence of presence: if the
proxy ever stops adding those headers (`ProxyAddHeaders Off`, a hand-rolled vhost, a
different front end), every internet request then looks exactly like the game's own
loopback poll, and the origin check is skipped entirely — silently, with nothing in
the log to say so.

`AUTH_SERVICE_TOKEN` closes that gap by identifying the game with something only it
can present: a shared secret, sent as `X-Auth-Service-Token` on every request the
client makes, checked with `hmac.compare_digest`. Once the service is configured
with a token, the exemption requires **both** a loopback peer **and** a matching
token — absence of forwarding headers is no longer enough on its own. A valid token
from a non-loopback peer is still refused; both are required, defense in depth.

**The service must not start requiring the token before the game is sending it.**
Getting the order backwards (service restarted first) is what takes logins down:

1. Set **the same value** as `AUTH_SERVICE_TOKEN` in both `/etc/mudauth/.env` and
   the game's environment (generate one with
   `python3 -c "import secrets; print(secrets.token_urlsafe(32))"`), but restart
   neither process yet.
2. **Restart the game** (or its driver) first. It now reads `AUTH_SERVICE_TOKEN`
   from its own environment at call time and sends `X-Auth-Service-Token` on every
   request. The service, still running its old process with the token unset,
   ignores the header and keeps using the legacy header-absence rule — this step is
   a no-op from the service's point of view, so logins are unaffected.
3. Confirm the game can still reach the service (`GET /auth/healthz` through
   whatever check your game exposes) before touching the service's config.
4. **Restart the service** (`sudo systemctl restart mudauth`). From this restart
   on, the loopback exemption requires the token; the game has been sending it
   since step 2, so nothing breaks. `journalctl -u mudauth` should show `auth
   service token: configured` in the startup line — confirm it.
5. Confirm end-to-end: start a login, complete it in a browser, and watch it
   resolve to an account exactly as before. Watch for any
   `[auth][security] ... loopback exemption denied` lines in the service's log,
   which would mean the game is *not* actually sending a valid token despite
   step 2 — investigate before considering the migration complete.

**If it goes wrong** (the service was restarted before the game, or the two
`AUTH_SERVICE_TOKEN` values don't match): every loopback poll from the game now
falls through to the ordinary origin-IP check, which it fails for a loopback-started
flow, so **players see logins hang and time out** rather than being compromised —
this fails closed, not open. Recovery is immediate and has no data-loss risk: unset
(or fix) `AUTH_SERVICE_TOKEN` in the service's `.env` and restart the service again;
that reinstates the legacy header-absence rule and logins resume. There is no
persistent state to repair — the service holds nothing but in-flight, short-TTL
login attempts, which simply time out and can be retried.

Unset is a fully supported, permanent option too, not just a rollback step: the
service keeps working exactly as it does today, with a startup warning reminding
you the gap exists.

## 6. Verify

`pipx install` puts the entry point in the installing user's home, so `mudauth` is on
the `mudauth` user's `PATH`, not yours. Call it by the absolute path the systemd unit
uses:

```bash
sudo -u mudauth /home/mudauth/.local/bin/mudauth check --env-file /etc/mudauth/.env
curl -fsS https://mud.example/auth/healthz      # public path via the proxy
curl -fsS http://127.0.0.1:7700/auth/providers  # loopback, on the server
```

`mudauth check` prints the public base, the bind address, and the enabled providers
with their callback URLs. It warns about:

- a public base that is not `https://` — including the unconfigured default
  `http://localhost:7700`, which is fine only while you are testing locally;
- a public base that already ends in `/auth` (which would produce `/auth/auth/*` URLs);
- an `AUTH_BIND` that is not a loopback address — the listener has no authentication
  of its own and must sit behind your proxy;
- no provider configured at all, which is an install nobody can sign in to;
- any provider with only one of its two credentials set.

It also reports `AUTH_SERVICE_TOKEN: configured` or `AUTH_SERVICE_TOKEN: not set` —
informational, not a problem it counts, since unset is a supported default — so you
can confirm which state you are in before and after the migration in step 5.

It then probes `/auth/healthz` on `AUTH_SERVICE_URL` if that is set, otherwise on the
`AUTH_BIND` listener. It exits 0 when clean and 1 when it found problems, so it is
usable from a monitoring script.

| Symptom | Check |
|---------|-------|
| Logins hang/time out right after setting `AUTH_SERVICE_TOKEN` | The service was restarted before the game, or the two `AUTH_SERVICE_TOKEN` values don't match. See step 5's migration order; the immediate fix is to unset (or correct) the token in the service's `.env` and restart the service again. |
| `[auth][security] ... loopback exemption denied` in the service log | A loopback caller — normally the game — presented a missing or wrong token. If this is the game itself, its `AUTH_SERVICE_TOKEN` does not match the service's; if it isn't, treat it as a genuine local probe worth investigating. |

In game, the provider list should now offer your configured providers. Until then
the flow falls back to whatever login your game does with no providers configured.
