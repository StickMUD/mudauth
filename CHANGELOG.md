# Changelog

## Unreleased

- Improve: the browser page players see after signing in is redesigned for
  phones and desktops, follows the browser's light or dark setting, and
  says plainly whether the sign-in worked and what to do next. Error and
  cancelled sign-ins now get the same page instead of bare text.
- New optional env vars `AUTH_BRAND_URL`, `AUTH_BRAND_LOGO_URL` and
  `AUTH_BRAND_ACCENT` brand that page. An unusable value is ignored with a
  startup log line, and `mudauth check` reports it.

## 0.1.1 — 2026-08-30

- Fix: `--env-file` (on `serve` and `check`) no longer crashes with a raw
  traceback when the file is missing, unreadable, or a directory — it now
  reports `[auth] configuration error: ...` and exits 2, like every other
  bad configuration value. This matters for `brew services`: the tap's
  documented first-run path runs `mudauth serve --env-file ...` under
  `keep_alive true`, and a user who starts the service before creating that
  file previously got a crashloop instead of one clear, actionable error.

## 0.1.0 — 2026-08-30

First public release, extracted from the auth service of an existing LDMud game.

- Stateless `/auth/*` broker for Discord, GitHub, Google, Microsoft, Apple, Twitch, Facebook, Steam.
- `mudauth serve`, `mudauth check`, `mudauth apple-secret`.
- `mudauth.client.request()` and the optional LDMud `auth_service_request` efun.
- New optional env vars `AUTH_BRAND_NAME`, `AUTH_USER_AGENT` and
  `AUTH_TRUSTED_PROXY_HOPS`.
