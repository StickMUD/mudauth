# Integrating a game with mudauth

The contract is plain HTTP over loopback, so any game server can adopt it. The
sequence every integration implements:

1. On connect, send `Char.Login.Default {"version":2,"type":["oauth","password-credentials"]}`.
2. When the player picks a provider on *your* sign-in screen, generate a UUID `nonce`
   and call `GET /auth/login/<provider>/<nonce>`. Do **not** follow the 302 — read
   the `Location` header (or build `public_base + /auth/login/<provider>/<nonce>`
   from `GET /auth/providers`) and send it to the client as
   `Char.Login.URL {"url":..,"nonce":..,"provider":..}`. Print it as a clickable
   link for clients without GMCP.
3. Poll `GET /auth/token-poll?nonce=<nonce>` every 2 seconds. `202
   {"status":"pending"}` means keep waiting; `200 {"provider","provider_id","username"}`
   is the verified identity. Stop on your own 10-minute timer: an expired or
   already-consumed nonce also answers `202`, not an error.
4. Map `provider:provider_id` to an account in your own store. Mint a reconnect
   token if you support `Char.Login.Token` / `Char.Login.Reconnect`.
5. If the player cancels, `POST /auth/login-cancel {"nonce":..}`.

The `nonce` must be a real UUID; anything else is rejected with 400. Only providers
that appear in `GET /auth/providers` are configured; show nothing else on the menu.
The response also carries `public_base`, so the game needs no URL configuration of
its own.

Full status-code contract: [protocol.md](protocol.md).

## LDMud

    pip install "mudauth[ldmud]"

registers the python efun `string auth_service_request(string method, string path, string body)`,
returning a JSON string `{"status": int, "body": string}` (status 0 when the service
is down — fall back to password login). Only `GET` and `POST` are accepted; any other
method also returns status 0. Set `AUTH_SERVICE_URL` in the driver's environment if
the listener is not on `http://127.0.0.1:7700`. Restart the driver after installing;
efuns load at start.

## Anything with an HTTP client (Evennia, Node, Go, ...)

Call the endpoints directly. `mudauth.client.request()` is a thin `urllib` wrapper
you can read as a reference; it is not required.

## Reference implementation

StickMUD (LDMud) implements the full flow including account linking and
reconnect tokens: <https://github.com/StickMUD/StickMUD> — see
`src/bin/daemons/oauth_d.c`, `src/bin/daemons/account_d.c`, `src/secure/login.c`.
