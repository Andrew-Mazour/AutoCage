# Security policy

AutoCage is pre-1.0 research software with one validated Linux runtime configuration. It is not a production security boundary or a guarantee against kernel vulnerabilities, sandbox escapes, denial of service, malicious verifiers, or all forms of credential exposure. See [the threat model](docs/THREAT_MODEL.md) before using it with sensitive repositories or agents.

## Reporting a vulnerability

Please report suspected vulnerabilities through GitHub's private vulnerability reporting or a GitHub Security Advisory for this repository. Do not include credentials, private repository contents, or other secrets in a public issue. If private reporting is unavailable, open a public issue containing only a request for a private contact route and no exploit details.

There is no guaranteed response or remediation time. AutoCage currently supports only the latest pre-1.0 source state; no stable release branch or security service-level agreement exists.

## Safe reproduction

Use the disposable Ubuntu Lima environment described in [installation guidance](docs/INSTALL.md). Security tests use synthetic fixtures. Do not run adversarial scenarios on an ordinary host or weaken the mandatory namespace, AppArmor, or no-egress requirements.
