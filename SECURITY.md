# Security policy

Report vulnerabilities privately to support@stickmud.com or through GitHub's
"Report a vulnerability" form on this repository. Do not open a public issue.
You will get an acknowledgement within 7 days.

Scope notes: the loopback listener trusts requests from 127.0.0.1/::1 without
IP binding. Exposing `AUTH_BIND` beyond loopback is a misconfiguration, not a
vulnerability in mudauth.
