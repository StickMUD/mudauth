# mudauth protocol

`mudauth` exposes six HTTP endpoints on a loopback listener. The game *originates*
every request; the only inbound traffic from the internet is the browser hitting
`/auth/login/*` and `/auth/callback` through your TLS proxy. A successful
`/auth/token-poll` returns `{"provider","provider_id","username"}` exactly once,
then forgets the nonce. The game maps that identity to its own accounts.

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/auth/providers` | List configured providers and the public base |
| GET | `/auth/login/<provider>/<nonce>` | Begin a login (302 to the provider) |
| GET | `/auth/callback?code=&state=` | OAuth redirect target |
| GET | `/auth/token-poll?nonce=` | Poll for the verified identity (returned once) |
| POST | `/auth/login-cancel` `{nonce}` | Drop a pending login |
| GET | `/auth/healthz` | Liveness check |

---

## GMCP protocol (the reusable contract)

Built on `Char.Login.*`:

| Direction | Package | Payload |
|-----------|---------|---------|
| S→C | `Char.Login.Default` | `{"version":2, "type":["oauth","password-credentials"]}` |
| C→S | `Char.Login.Credentials` | `{"account","password"}`, the resume form `{"account","provider"}`, or `{}` to hand off to the game's own screen |
| S→C | `Char.Login.URL` | `{"url":"https://…/auth/login/<provider>/<nonce>", "nonce":"…", "provider":"…"}` — server hands the client a browser URL |
| S→C | `Char.Login.Token` | `{"account","token","secure_only"}` — an opaque reconnect credential for the client's profile |
| C→S | `Char.Login.Reconnect` | `{"account","token"}` — replay the saved token, no browser and no password |
| S→C | `Char.Login.Result` | `{"success","message"}` — terminal message of every flow |

The provider list is deliberately **not** sent on `Char.Login.Default`, and the client
never picks a provider over GMCP. That choice happens on the game's own sign-in screen,
which every client can drive; the client's job is to open the URL the game pushes, save
the token the game mints, and replay it next time.

Only the server-driven tier applies here. The spec's client-driven appendix — where an
OIDC-capable client runs the authorization request itself and returns the code via
`Char.Login.AuthCode` — applies only to a server that is **itself** an OpenID Provider.
A game using `mudauth` brokers external providers (Discord, GitHub, Google, Microsoft,
and the rest), which have no discovery document the game owns and confidential secrets
that must stay server-side, so the appendix cannot apply and `Char.Login.AuthCode` is
not implemented.

---

## Login flows

### Browser + token-poll (telnet-friendly, default)

```text
Player connects ──► WELCOME ──► provider menu
   choose "2 Discord"
        │
   the game: start_login("discord", player)
        │      the game → GET /auth/login/discord/<nonce>
        │      service: store pending state, return authorize URL
   the game prints the URL (OSC 8 clickable) + "waiting…"
   the game polls GET /auth/token-poll?nonce=N every 2s
        │
   (browser) user authorizes ► provider ► GET /auth/callback?code&state
        │      service: code→token→profile, completed[N] = verified identity
        │
   poll returns 200 {provider, provider_id, username}
        │      the game: account_for_identity("provider:provider_id")
        │      → account id + the characters on that account
   the game proceeds to character pick / connect, and records the binding
   in its own store
```

### Password-less reconnect (screenless, after one browser pairing)

Once the browser flow has completed, the game mints an opaque per-device credential
and hands it to the client, which replays it on every later connect:

```text
Player connects ──► Char.Login.Default {version:2, type:["oauth",…]}
Client → Char.Login.Reconnect {account:"acct:character", token}
   → the game verifies (account, token, connection_is_secure)
   → single-use: the presented token is consumed, a fresh one minted (rotation)
Server → Char.Login.Token {account, token, secure_only}   (client overwrites)
Server → Char.Login.Result {success}   ── straight into the named character
```

The token is scoped to the transport that issued it: minted over TLS, it is only
accepted back over TLS, and a client that cannot meet that skips it silently. A
rejected token closes the connection rather than falling through to a password
prompt; the client drops it, keeps the account and provider, and reconnects into
the resume form — `Char.Login.Credentials {account, provider}` — which restarts
that provider's browser flow directly, with no provider menu.

Reconnect tokens are entirely the game's business. `mudauth` neither mints nor
verifies them; it has no store to keep them in.

---

## Security

- **CSRF:** every flow carries a random `state`; `/auth/callback` rejects unknown or
  expired states. Steam has no `state` parameter, so the value rides inside the
  OpenID `return_to` URL, which Steam signs and echoes back.
- **`login_nonce`:** a client-generated UUID; the verified identity is stored keyed
  by it and returned **once** from `/auth/token-poll`, then deleted. 10-minute TTL,
  enforced inline on each request as well as by a 60-second sweep.
- **Origin binding:** the service records the IP that started a login and only returns
  the identity to the same IP — except trusted loopback callers (the game itself),
  which are exempt because they connect from `127.0.0.1` or `::1`. A caller that sends
  `X-Forwarded-For` or `X-Real-IP` is never treated as loopback.
  Those two headers are believed **only** when the immediate peer is loopback, i.e.
  your own reverse proxy; from any other peer the socket address is used and the
  headers are ignored. Within `X-Forwarded-For` only the rightmost element is read —
  the hop your proxy appended — because everything left of it was written by the
  client. Repeated header lines are read as one list. Set
  `AUTH_TRUSTED_PROXY_HOPS=<n>` if `n` proxies append to the header before it reaches
  the service; it is validated once at startup and a non-integer or a value below 1
  stops the service rather than being clamped, because a silently degraded binding is
  worse than a refusal to boot. When a request arrives with a chain shorter than `n`,
  or with a hop that is not an IP address, the service has no origin it can vouch for:
  it logs an `[auth][security]` line and **refuses** the request. It does not fall back
  to the peer address, which on this loopback-only listener is always `127.0.0.1` — the
  origin a game's own flows record — so that fallback would have made every origin
  match. A caller whose origin cannot be resolved, or an entry with no recorded origin,
  is rejected; nothing here fails open. Note the corollary of the recommended
  integration: a game that starts the flow over loopback records the loopback address
  as the origin, so the binding constrains nothing on that path — the nonce is the
  credential there.
- **The loopback exemption itself, `AUTH_SERVICE_TOKEN`:** header-absence alone
  identifies the game only by *not* seeing evidence of a proxy, which a proxy
  misconfiguration (`ProxyAddHeaders Off`, a hand-rolled vhost, a different front end)
  can manufacture for every internet caller at once — every request would then arrive
  from `127.0.0.1` with no forwarding header, indistinguishable from the game, and the
  origin check would be skipped entirely with nothing in the log to say so. Setting
  `AUTH_SERVICE_TOKEN` (the same value in the service's environment and the game's)
  replaces that with positive evidence: the exemption requires a loopback peer, a
  matching token in `X-Auth-Service-Token` compared with `hmac.compare_digest` since it
  is a bearer credential, **and** the absence of a forwarding header. That third
  condition is load-bearing: the shipped nginx and Apache configs both strip a
  client-supplied `X-Auth-Service-Token` before proxying, but the service does not rely
  on the proxy alone to enforce that — the check reads the request directly, so a
  hand-rolled vhost that omitted the strip still cannot grant the exemption to a caller
  arriving through it. Without this, the token alone would have been a net *widening* of
  remote attack surface: a caller who learned the token (from a paste, a log,
  `/proc/<pid>/environ` under the same uid) could present it *through* the proxy and
  inherit the exemption remotely, which the legacy header-absence rule never permitted —
  a correctly configured proxy always appends `X-Forwarded-For`. Requiring all three
  makes the token path a strict tightening of the legacy rule, never a trade against it:
  the game polls over loopback directly and never carries a forwarding header, so this
  costs it nothing. A valid token from a non-loopback peer is still refused regardless —
  a loopback peer and the token are both required on top of the header check, defense in
  depth. Unset, the legacy header-absence rule stands exactly as above, so an existing
  deployment does not break on restart; the service prints a startup warning recommending
  the token be set. The service itself never logs the token, on any path; the
  `mudauth.client` module that sends it validates the value's charset before adding the
  header and, if the underlying HTTP layer ever rejects a header value, logs only the
  exception type rather than its text, so a malformed token cannot reach the game's log
  either. See [deploy.md](deploy.md) for the required migration order — the service must
  not start requiring the token before the game is sending it.
- **Confidential client only:** there is no native-capture or client-driven flow, so
  no PKCE. The `client_secret` is used server-side and never leaves the service.
- **Secrets:** provider `client_secret`s live only in the service's environment, never
  in the game's code and never sent to clients.
- **Logging:** the service redacts query strings and UUIDs from its own request log,
  because both carry live credentials (`?code=`, `?nonce=`, Steam's signed assertion,
  and the `login_nonce` path segment of `/auth/login/<provider>/<nonce>`). Your
  reverse proxy keeps a separate log: nginx's `access_log` and Apache's `CustomLog`
  record the full request line, so those files *would* contain live nonces and
  authorization codes for their 10-minute lifetime. The shipped nginx config therefore
  sets `access_log off` inside `location /auth/`, and the Apache snippet carries the
  `SetEnvIf`/`CustomLog env=!` equivalent for that vhost's `CustomLog`. Security
  decisions — origin rejections, unusable forwarding headers — are logged with the
  distinct `[auth][security]` prefix and carry the peer address, the claimed origin,
  the recorded origin and the provider, so a hijack attempt can be told apart from a
  player moving from wifi to cellular. The nonce is never logged: it is a live
  credential.
- **Passwords:** if the game keeps a password flow alongside this one, it should require
  TLS for it. That is the game's concern; `mudauth` never sees a password.

---

## Request/response detail

Every status code below is what `AuthHandler` in `src/mudauth/server.py` actually
sends. JSON responses carry `Content-Type: application/json`; HTML responses carry
`text/html; charset=utf-8`. Every response this service builds — JSON, HTML, and the
`/auth/login` redirect — sets `Cache-Control: no-store`, `X-Content-Type-Options:
nosniff` and `Referrer-Policy: no-referrer` — these pages render on your public MUD
origin, and the URLs that reach them carry live nonces. A malformed request line never
reaches our handler code; the stdlib's own `send_error` response for that case carries
none of these.

Any path other than the six below answers **404** `{"error":"not found"}` — for both
GET and POST. Methods other than GET and POST get the stdlib `http.server` default of
**501**.

### `GET /auth/providers`

| Status | Body | Trigger |
|--------|------|---------|
| 200 | `{"providers":["discord",…],"public_base":"https://mud.example"}` | Always |

`providers` is the sorted list of providers with complete credentials in the
environment; `public_base` is `AUTH_PUBLIC_BASE` with any trailing slash removed.
A game should offer only the providers this call returns, and can take its browser
base URL from `public_base` rather than configuring one of its own.

### `GET /auth/login/<provider>/<nonce>`

The legacy query form `GET /auth/login?provider=<p>&login_nonce=<n>` is still
accepted; the path form is preferred because it contains no `&` or `=` for a MUD
client's link renderer to mangle. Extra trailing path segments are ignored.

| Status | Body | Trigger |
|--------|------|---------|
| 302 | empty, `Location:` the provider's authorize URL | `<provider>` is configured and `<nonce>` is a valid UUID (or absent) |
| 400 | `Invalid login_nonce format.` | `<nonce>` is present but is not a UUID |
| 404 | `Provider '<p>' is not configured.` | `<provider>` is missing, unknown, or has no credentials set |

Do **not** follow the 302 from the game; read the `Location` header, or just build
`<public_base>/auth/login/<provider>/<nonce>` yourself, and give the URL to the
player's browser. The IP that makes this request is the one recorded for origin
binding, so a game calling over loopback records a loopback origin.

Supplying no nonce is legal but useless: the callback has nothing to file the
identity under, so nothing is ever retrievable by `/auth/token-poll`.

### `GET /auth/callback?code=&state=`

The provider's redirect target. It is reached by the player's browser, not the game.
Steam instead returns an OpenID 2.0 assertion on this URL, with the `state` carried
inside `return_to`.

| Status | Body | Trigger |
|--------|------|---------|
| 200 | branded "Authentication successful" page | Identity verified; stored under the nonce for one retrieval |
| 400 | "You declined the sign-in request…" page | Provider reported `error=access_denied`, or Steam reported `openid.mode=cancel` |
| 400 | "Authentication failed. Please try again." page | `state` missing, unknown, or already consumed; `state` older than the 10-minute TTL; provider returned any other `error`; `code` missing; token exchange failed; Steam assertion failed verification |
| 502 | `Could not fetch your <Provider> profile.` | Token accepted, but the provider's profile endpoint failed or returned nothing usable |
| 503 | `Provider '<p>' is no longer configured.` | The flow started while the provider was configured, but its credentials are gone now (the process was restarted with a different environment) |

The message the player sees is deliberately generic. The specific cause is written
to the service log.

### `GET /auth/token-poll?nonce=`

The game's polling endpoint. Poll about every 2 seconds.

| Status | Body | Trigger |
|--------|------|---------|
| 200 | `{"provider":"discord","provider_id":"…","username":"…"}` | The identity is ready. It is deleted in the same locked section, so a second poll will not see it. |
| 202 | `{"status":"pending"}` | No identity filed under this nonce *yet*, or it expired, or it was already retrieved. These three cases are not distinguishable. |
| 400 | `{"error":"missing nonce"}` | No `nonce` query parameter |
| 403 | `{"error":"forbidden"}` | The caller's IP differs from the one that started the flow, and the caller is not trusted loopback |

**Note for implementers:** an expired or already-consumed nonce answers **202**, not
404. Give up on your own timer — 10 minutes matches the service's TTL — rather than
waiting for an error status that never comes.

`provider_id` is the stable key to map to an account; store that. `username` is the
provider's handle where it has one and a fallback where it does not (an email address,
the profile name, or the provider id) — it is display-only and the player can change
it, so never key on it.

### `POST /auth/login-cancel`

Body: `{"nonce":"<uuid>"}`, `Content-Type: application/json`. Bodies larger than
64 KiB, or that are not a JSON object, are read as empty.

| Status | Body | Trigger |
|--------|------|---------|
| 200 | `{"cancelled":<n>}` | `n` is the number of entries dropped: the completed identity if one was filed, plus every in-flight state carrying this nonce. `0` is a normal answer for an unknown nonce. |
| 400 | `{"error":"invalid nonce"}` | `nonce` missing, not a string, or not a UUID |
| 403 | `{"error":"forbidden"}` | A completed identity or a still-pending flow exists under this nonce, the caller is not trusted loopback, and the caller's IP differs from (or cannot be resolved to match) the one that started the flow |

### `GET /auth/healthz`

| Status | Body | Trigger |
|--------|------|---------|
| 200 | `{"ok":true}` | Always, while the process is serving |

This is what `mudauth check` probes. Use `GET`: `HEAD` is not implemented and answers
501, so point monitoring at a GET.
