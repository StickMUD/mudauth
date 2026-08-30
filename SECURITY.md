# Security policy

Report vulnerabilities privately to support@stickmud.com or through GitHub's
"Report a vulnerability" form on this repository. Do not open a public issue.
You will get an acknowledgement within 7 days.

Scope notes: the loopback listener trusts requests from 127.0.0.1/::1 without
IP binding. Exposing `AUTH_BIND` beyond loopback is a misconfiguration, not a
vulnerability in mudauth.

Origin binding reads `X-Forwarded-For` and `X-Real-IP` only from a loopback peer
-- your own reverse proxy -- and takes only the rightmost `X-Forwarded-For`
element, the hop that proxy appended. It therefore assumes a proxy that
*appends* to the header, which both shipped configs do -- the Apache one relies
on `mod_proxy`'s `ProxyAddHeaders`, which it states must stay `On`. A proxy that
passes the client's header through untouched, or that sets only `X-Real-IP`,
lets the client choose its own recorded origin; count your appending proxies in
`AUTH_TRUSTED_PROXY_HOPS`.

Miscounting is a misconfiguration, not a vulnerability, but the service will not
fail open on one: a value that is not a whole number of at least 1 stops the
service at startup, and a request whose forwarding header does not match the
configured shape is refused and logged with an `[auth][security]` prefix rather
than falling back to the loopback peer address.

Without `AUTH_SERVICE_TOKEN`, the loopback exemption (see docs/protocol.md#security)
rests on the *absence* of forwarding headers, which is evidence of absence, not
evidence of presence: a proxy that stops adding them makes every internet request
indistinguishable from the game. Set `AUTH_SERVICE_TOKEN` (the same value in the
service's environment and the game's) to close that gap with a shared secret,
required alongside a loopback peer *and* the same absence of forwarding headers
-- the token alone does not grant the exemption, since neither shipped proxy
config lets a client-supplied copy of the header through, but the service does
not rely on the proxy for that; see docs/protocol.md#security for why. The
service never logs the token, on any path; the value is checked with
`hmac.compare_digest`. See docs/deploy.md for the migration order that avoids
taking logins down when you turn it on.
