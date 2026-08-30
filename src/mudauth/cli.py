"""``mudauth`` command line: serve, check, apple-secret."""

from __future__ import annotations

import argparse
import os
import sys
import time

from . import __version__, client, server
from .providers import SUPPORTED_PROVIDERS


def load_env_file(path: str) -> dict[str, str]:
    """Parse a KEY=VALUE file (comments, blank lines, ``export``, quotes)."""
    out: dict[str, str] = {}
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            if line.startswith("export "):
                line = line[7:].lstrip()
            key, _, value = line.partition("=")
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            out[key.strip()] = value
    return out


def _apply_env_file(args: argparse.Namespace) -> None:
    if getattr(args, "env_file", None):
        for k, v in load_env_file(args.env_file).items():
            os.environ.setdefault(k, v)


def _bind_host_port() -> tuple[str, int]:
    """Host and port the listener binds, from AUTH_BIND."""
    bind = os.environ.get("AUTH_BIND", "127.0.0.1:7700")
    host, _, port_s = bind.rpartition(":")
    return host or "127.0.0.1", int(port_s or "7700")


def build_server_from_env():
    return server.make_server(*_bind_host_port())


def serve(args: argparse.Namespace) -> int:
    _apply_env_file(args)
    if args.bind:
        os.environ["AUTH_BIND"] = args.bind
    httpd = build_server_from_env()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("[auth] shutting down")
        httpd.shutdown()
    return 0


def _service_url() -> str:
    """URL to probe: an explicit AUTH_SERVICE_URL wins, else the AUTH_BIND listener."""
    override = os.environ.get("AUTH_SERVICE_URL")
    if override:
        return override.rstrip("/")
    host, port = _bind_host_port()
    return f"http://{host}:{port}"


def check(args: argparse.Namespace) -> int:
    _apply_env_file(args)
    problems = 0
    base = server._public_base()
    print(f"AUTH_PUBLIC_BASE: {base}")
    if base.rstrip("/").endswith("/auth"):
        print("  WARNING: ends in /auth — the service adds /auth/* itself, so URLs would become /auth/auth/*")
        problems += 1
    configs = server._load_provider_configs()
    enabled = sorted(configs)
    print(f"providers enabled: {', '.join(enabled) or '(none)'}")
    for p in sorted(SUPPORTED_PROVIDERS):
        if p not in configs and (os.environ.get(f"{p.upper()}_CLIENT_ID") or os.environ.get(f"{p.upper()}_CLIENT_SECRET")):
            print(f"  WARNING: {p} has only one of CLIENT_ID / CLIENT_SECRET set; it is disabled")
            problems += 1
    for p in enabled:
        print(f"  {p}: callback {configs[p].callback_url}")
    url = _service_url()
    r = client.request("GET", "/auth/healthz", base_url=url, timeout=3)
    if r["status"] == 200:
        print(f"service at {url}: ok")
    else:
        print(f"service at {url}: unreachable ({r['body'] or r['status']}) — is `mudauth serve` running?")
        problems += 1
    return 1 if problems else 0


def apple_secret(args: argparse.Namespace) -> int:
    if not 0 < args.days <= 180:
        print("--days must be 1..180 (Apple rejects JWTs valid > 6 months)", file=sys.stderr)
        return 2
    try:
        import jwt
    except ImportError:
        print("PyJWT is required: pip install 'mudauth[apple]'", file=sys.stderr)
        return 1
    try:
        with open(args.p8) as fh:
            key = fh.read()
    except OSError as exc:
        print(f"cannot read --p8 file {args.p8}: {exc}", file=sys.stderr)
        return 1
    now = int(time.time())
    try:
        token = jwt.encode(
            {"iss": args.team_id, "iat": now, "exp": now + args.days * 86400,
             "aud": "https://appleid.apple.com", "sub": args.client_id},
            key, algorithm="ES256", headers={"kid": args.key_id},
        )
    except Exception as exc:  # noqa: BLE001 — PyJWT/cryptography raise various types
        print(f"--p8 file {args.p8} is not a usable Sign in with Apple key: {exc}", file=sys.stderr)
        return 1
    print(token.decode() if isinstance(token, bytes) else token)
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="mudauth", description="Stateless OAuth/OIDC sign-in broker for MUDs")
    ap.add_argument("--version", action="version", version=f"mudauth {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="run the loopback listener")
    s.add_argument("--env-file", help="KEY=VALUE file to load (values already in the environment win)")
    s.add_argument("--bind", help="host:port to listen on (default AUTH_BIND or 127.0.0.1:7700)")
    s.set_defaults(func=serve)

    c = sub.add_parser("check", help="validate configuration and reach the running service")
    c.add_argument("--env-file")
    c.set_defaults(func=check)

    a = sub.add_parser("apple-secret", help="generate the Sign in with Apple client secret JWT")
    a.add_argument("--team-id", required=True)
    a.add_argument("--key-id", required=True)
    a.add_argument("--client-id", required=True, help="Services ID (the OAuth client_id)")
    a.add_argument("--p8", required=True, help="path to AuthKey_<KID>.p8")
    a.add_argument("--days", type=int, default=180)
    a.set_defaults(func=apple_secret)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
