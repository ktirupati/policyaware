# Security Policy

PolicyAware deals with AI governance, sensitive data detection, local code scanning, provider routing, tool permissions, and audit traces. Please report security issues responsibly.

## Reporting A Vulnerability

Please do not open a public issue for a security vulnerability.

Report privately through one of these channels:

- GitHub private vulnerability reporting, if enabled for the repository.
- Contact the maintainer, Krishna Kishor Tirupati, through LinkedIn: https://www.linkedin.com/in/krishna-tirupati/

When reporting, include:

- A clear description of the issue.
- Steps to reproduce.
- Affected version.
- Expected impact.
- Any safe proof-of-concept details.

Do not include real secrets, customer data, PHI, PII, proprietary prompts, or confidential internal details.

## Supported Versions

PolicyAware is an early-stage open-source project. Security fixes are prioritized for the latest published version.

| Version | Supported |
| --- | --- |
| Latest PyPI release | Yes |
| Older releases | Best effort |

## Scope

Examples of security-relevant reports:

- Secret leakage in reports.
- Unsafe handling of scan evidence.
- Incorrect redaction behavior.
- Policy bypass.
- Tool governance bypass.
- Unsafe provider routing behavior.
- Audit trace exposure.

Out of scope:

- Vulnerabilities in third-party model providers.
- Vulnerabilities in optional third-party ML or guardrails packages.
- Reports containing real private data or credentials.

## Safe Testing

Use synthetic examples only.

Do not test PolicyAware with real credentials, patient data, customer records, production prompts, or proprietary documents unless you are authorized and the data remains in your own environment.
