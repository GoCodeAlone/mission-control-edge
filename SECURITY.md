# Security Policy

## Supported versions

Mission Control Edge is pre-release software. Security fixes are made on the
latest release line and `main`; older pre-release versions may not receive
backports.

| Version | Supported |
| --- | --- |
| Latest release and `main` | Yes |
| Older pre-releases | No |

## Reporting a vulnerability

Report suspected vulnerabilities privately through the repository's
[GitHub security advisory form](https://github.com/GoCodeAlone/mission-control-edge/security/advisories/new).
Do not open a public issue with exploit details, credentials, transcripts,
terminal output, customer data, or local paths.

Include the affected version or commit, provider and gateway versions, platform,
impact, reproduction steps, and any suggested mitigation. Use synthetic data and
redact secrets. Maintainers will acknowledge the report and coordinate status
and disclosure through the private advisory.

## Trust model

Provider processes and native runtimes are outside the hosted control plane's
trust boundary. They must be independently installable, capability-scoped, and
run with the least local permissions available. Provider-supplied identifiers,
metadata, events, artifacts, and extension data are untrusted input. Secrets,
prompts, terminal output, credentials, and file content must not appear in logs
by default.

The public provider ABI is not the Workflow plugin ABI. A provider must never be
loaded into the Workflow control-plane process merely because it implements the
Mission protocol.
