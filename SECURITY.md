# Security Policy

uBix Vault is a secrets management system, so security is the project's first priority.
We take vulnerability reports seriously and appreciate responsible disclosure.

> **Project status:** uBix Vault is in pre-implementation design. There is no released
> software to attack yet; this policy is in place from day one so a reporting channel
> exists as soon as code lands.

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report privately through GitHub's **[Private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)**
feature (the **"Report a vulnerability"** button under this repository's **Security** tab).

If you cannot use that channel, contact the maintainer privately — see `SECURITY_CONTACT`
below.

<!-- SECURITY_CONTACT: replace with a monitored security contact (e.g. security@yourdomain)
     or rely solely on GitHub private vulnerability reporting above. -->

## What to include

- A description of the vulnerability and its impact.
- Steps to reproduce, or a proof of concept.
- Affected version / commit, and any relevant configuration.

## Our commitment

- We will acknowledge your report as promptly as we can.
- We will keep you informed as we investigate and work on a fix.
- We will credit reporters who wish to be credited once a fix is released.

## Scope

Reports concerning the confidentiality, integrity, or availability of secrets, the
encryption barrier, the seal/unseal mechanism, authentication, authorization (ACL
policies), or the audit log are especially in scope.
