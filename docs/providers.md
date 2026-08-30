# Provider setup

Register `AUTH_CALLBACK_URL` (default `<AUTH_PUBLIC_BASE>/auth/callback`) as the
redirect URI in every console.

A provider is enabled only when **both** its `_CLIENT_ID` and `_CLIENT_SECRET` are
set — Steam is the exception and needs only `STEAM_API_KEY`. Anything half-configured
is silently skipped; `mudauth check` warns about it. Every provider also accepts a
`<PROVIDER>_CALLBACK_URL` override if that one app must redirect somewhere else.

`provider_id` is the stable key your game should store. It never changes when the
player renames themselves; `username` can.

## Discord

Console: <https://discord.com/developers/applications> — create an application, then
OAuth2 → add the redirect URI, and copy the Client ID and Client Secret.

    DISCORD_CLIENT_ID=
    DISCORD_CLIENT_SECRET=

Scope requested: `identify`. `provider_id` is the Discord user id; `username` is the
Discord username.

## GitHub

Console: <https://github.com/settings/developers> → OAuth Apps → New OAuth App. The
"Authorization callback URL" is your `AUTH_CALLBACK_URL`.

    GITHUB_CLIENT_ID=
    GITHUB_CLIENT_SECRET=

Scope requested: `read:user`. `provider_id` is the numeric user id; `username` is the
login handle.

## Google

Console: <https://console.cloud.google.com/apis/credentials> → Create credentials →
OAuth client ID → Web application. Add the redirect URI under "Authorized redirect
URIs". You will also have to fill in the OAuth consent screen before the app works
for anyone but you.

    GOOGLE_CLIENT_ID=
    GOOGLE_CLIENT_SECRET=

Scopes requested: `openid profile email`. `provider_id` is the OIDC `sub`;
`username` is the email address when Google returns one.

## Microsoft

Console: <https://entra.microsoft.com> → App registrations → New registration, with a
"Web" redirect URI. Take the Client Secret from Certificates & secrets — note the
expiry date Microsoft assigns it and set your own reminder.

    MICROSOFT_CLIENT_ID=
    MICROSOFT_CLIENT_SECRET=

`mudauth` authorizes against the `/common/` endpoint, so register the app for
"Accounts in any organizational directory and personal Microsoft accounts". A
single-tenant registration will reject the sign-in.

Scopes requested: `openid profile email User.Read`. `provider_id` is the Graph object
id; `username` is the mail address or user principal name.

## Twitch

Console: <https://dev.twitch.tv/console/apps>. **The Twitch account needs two-factor
authentication enabled before it may register applications at all** — turn on 2FA
first, then create the app.

    TWITCH_CLIENT_ID=
    TWITCH_CLIENT_SECRET=

No scopes are requested; Twitch's Helix `/users` endpoint returns the token owner's
public profile without any. `provider_id` is the Twitch user id; `username` is the
login name.

## Facebook

Console: <https://developers.facebook.com> — the App ID and App Secret are under
Settings → Basic.

    FACEBOOK_CLIENT_ID=
    FACEBOOK_CLIENT_SECRET=

**The app must be Live**, and Facebook will not let you switch it to Live until the
app settings carry a privacy policy URL and a data deletion instructions URL. Budget
for that: it means hosting two more pages.

Scope requested: `public_profile`. Facebook exposes no handle-style username, so the
profile name serves as both `username` and display name. `provider_id` is the
app-scoped user id — it differs between your app and anyone else's.

## Apple

Console: <https://developer.apple.com/account/resources/identifiers>. **Sign in with
Apple requires the paid Apple Developer Program**; there is no free tier for it.

    APPLE_CLIENT_ID=
    APPLE_CLIENT_SECRET=

`APPLE_CLIENT_ID` is the **Services ID**, not the App ID. `APPLE_CLIENT_SECRET` is
not a static secret at all: it is an ES256 JWT you generate from the `.p8` signing
key Apple issues.

    pip install "mudauth[apple]"
    mudauth apple-secret --team-id ABCDE12345 --key-id XYZ9876543 \
        --client-id com.example.mud.service --p8 AuthKey_XYZ9876543.p8

`--days` defaults to 180 and may not exceed it, because **Apple rejects a client
secret valid for more than six months**. The JWT therefore expires, and Apple logins
break the day it does — put a rotation reminder in your calendar.

Apple also **only accepts https return URLs**, so there is no local-development
callback: you need the real proxied host before you can test this provider at all.

`provider_id` is the Apple `sub` claim; `username` is the email claim when Apple
supplies one, otherwise the `sub`. `mudauth` validates the id_token's issuer,
audience, and expiry.

## Steam

Console: <https://steamcommunity.com/dev/apikey>.

    STEAM_API_KEY=

Steam is **OpenID 2.0, not OAuth2**: there is no client id and no client secret. The
Web API key is used only for the persona-name lookup after the identity is already
proven, so a bad or missing key does not break the login — the player's `username`
just falls back to the raw steamid64.

There is nothing to register with Steam beyond getting the key: the callback URL is
sent on each request rather than configured in a console. The CSRF `state` rides
inside the OpenID `return_to` URL, which Steam signs and echoes back, and `mudauth`
requires the echoed scheme, host, and path to equal `AUTH_CALLBACK_URL` (or
`STEAM_CALLBACK_URL`) exactly — so if your proxy rewrites the host, set the override.

`provider_id` is the steamid64.
