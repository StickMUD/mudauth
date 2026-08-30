# mudauth

Sign in to your MUD with Discord, GitHub, Google, Microsoft, Apple, Twitch, Facebook, or Steam.
`mudauth` is a small, **stateless** OAuth/OIDC broker for games that implement the
[GMCP Authentication standard](https://wiki.mudlet.org/w/Standards:GMCP_Authentication) — supported today by Mudlet 5 and LociTerm.

- **No database.** It verifies a provider identity and hands `{provider, provider_id, username}` to your game once. Your game stays the source of truth for accounts and characters.
- **No dependencies.** Python 3.11+ standard library only. One process, one env file.
- **No inbound port on the game.** The game polls `mudauth` over loopback; only `mudauth` sits behind your TLS proxy.
- **Eight providers**, each enabled by environment variables — a client id and secret for the seven OAuth/OIDC providers, a single Web API key for Steam.

## Install

    pipx install mudauth            # or: pip install mudauth
    brew install stickmud/tap/mudauth

## Run

    cp .env.example .env            # fill in AUTH_PUBLIC_BASE and one provider's id/secret
    mudauth serve --env-file .env   # listens on 127.0.0.1:7700
    mudauth check --env-file .env   # validates config and reaches the running service

Put a TLS reverse proxy in front of `AUTH_PUBLIC_BASE` and forward `/auth/` to the
loopback listener. See [docs/deploy.md](docs/deploy.md) for systemd, nginx, and Apache.

## Integrate your game

Your game starts a login with `GET /auth/login/<provider>/<nonce>`, hands the player
the returned URL over `Char.Login.URL`, and polls `GET /auth/token-poll?nonce=` until
the identity arrives. Full contract: [docs/protocol.md](docs/protocol.md).
Driver-specific notes (LDMud efun, Evennia, Node): [docs/integrating.md](docs/integrating.md).

LDMud games get a ready-made efun: `pip install "mudauth[ldmud]"` registers
`auth_service_request(method, path, body)`.

## Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/auth/providers` | List configured providers and the public base |
| GET | `/auth/login/<provider>/<nonce>` | Begin a login (302 to the provider) |
| GET | `/auth/callback?code=&state=` | OAuth redirect target |
| GET | `/auth/token-poll?nonce=` | Poll for the verified identity (returned once) |
| POST | `/auth/login-cancel` `{nonce}` | Drop a pending login |
| GET | `/auth/healthz` | Liveness check |

## Configuration

All settings are environment variables; `--env-file` loads a `KEY=VALUE` file.

| Variable | Default | Meaning |
|----------|---------|---------|
| `AUTH_BIND` | `127.0.0.1:7700` | Loopback listener. Never expose it. |
| `AUTH_PUBLIC_BASE` | `http://localhost:7700` | Browser-facing prefix *before* `/auth/*` |
| `AUTH_CALLBACK_URL` | `$AUTH_PUBLIC_BASE/auth/callback` | Redirect URI registered with each provider |
| `AUTH_BRAND_NAME` | `mudauth` | Name on the "you may close this tab" page |
| `AUTH_TRUSTED_PROXY_HOPS` | `1` | Proxies that append to `X-Forwarded-For` between the browser and the service |
| `AUTH_USER_AGENT` | `mudauth/<version>` | Outbound User-Agent; set it to name your game |
| `<PROVIDER>_CLIENT_ID` / `_CLIENT_SECRET` | — | Enables that provider |
| `<PROVIDER>_CALLBACK_URL` | `$AUTH_CALLBACK_URL` | Per-provider override |
| `STEAM_API_KEY` | — | Steam uses OpenID 2.0; the key is only for the persona lookup |

One more variable belongs to the *game* side, not the service: `AUTH_SERVICE_URL`
(default `http://127.0.0.1:7700`) names the loopback listener the game talks to.

Provider registration walkthroughs: [docs/providers.md](docs/providers.md).

## Security model

Random per-flow `state` (CSRF); client-generated `nonce` with a 10-minute TTL; the
identity is returned exactly once and forgotten; non-loopback pollers must come from
the IP that started the flow; provider secrets never leave the service. Loopback
callers are trusted — the listener must stay on loopback. `X-Forwarded-For` and
`X-Real-IP` are believed only from a loopback peer (your reverse proxy), and only
the rightmost `X-Forwarded-For` element — the hop your proxy appended — is read, so
a caller cannot name its own origin. If two proxies append to the header, set
`AUTH_TRUSTED_PROXY_HOPS=2`. Report vulnerabilities per [SECURITY.md](SECURITY.md).

## Test

    python -m unittest discover -s tests -v

## Credits and license

Originally built as the auth service for [StickMUD](https://stickmud.com), following
the pattern proven by [MUDdown](https://github.com/MUDdown/MUDdown). MIT licensed —
see [LICENSE](LICENSE).
