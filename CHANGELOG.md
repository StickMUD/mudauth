# Changelog

## 0.1.0 — unreleased

(Dated at tag time.)

First public release, extracted from the auth service of an existing LDMud game.

- Stateless `/auth/*` broker for Discord, GitHub, Google, Microsoft, Apple, Twitch, Facebook, Steam.
- `mudauth serve`, `mudauth check`, `mudauth apple-secret`.
- `mudauth.client.request()` and the optional LDMud `auth_service_request` efun.
- New optional env vars `AUTH_BRAND_NAME` and `AUTH_USER_AGENT`.
