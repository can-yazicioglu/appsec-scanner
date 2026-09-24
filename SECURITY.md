# Security policy

This policy covers vulnerabilities in AppSec Scanner itself: scope bypasses,
credential disclosure, unsafe source execution, and dashboard injection.
Findings against other applications belong to their owners' disclosure processes.

## Reporting

If the repository Security tab offers **Report a vulnerability**, use that
private channel. If unavailable, open a minimal issue asking the maintainer to
arrange a private channel. Omit vulnerability details until one is established.
Do not post credentials, private evidence, or unpatched exploits publicly.

A private report should include the affected version/commit, impact, and a
minimal reproduction using synthetic data. No response-time or maintenance
guarantee is currently offered.

## Operational boundaries

Consult the verification record for known limits. Keep the dashboard on loopback
and scan authorized targets only. Hostname scoping is not DNS pinning or a network
firewall. A completed scan cannot certify that an application is secure.
