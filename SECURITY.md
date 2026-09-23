# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | yes |

## Reporting a vulnerability

Please use the repository's private security reporting mechanism.

On GitHub this is **Security -> Advisories -> Report a vulnerability** ("private
vulnerability reporting"). If that option is not enabled for the repository, open a public
issue that says only that you have a security report and ask the maintainers to enable
private reporting - **do not include vulnerability details in public issues, pull requests
or discussions.**

Please include:

- a description of the issue and its impact;
- the affected version(s) and environment;
- steps to reproduce or a minimal proof of concept;
- any suggested fix.

We aim to acknowledge reports promptly, keep you informed while a fix is prepared and
credit you in the release notes if you wish. Please give us reasonable time to release a
fix before any public disclosure.

## Scope

In scope: bugs in HashCollider itself, for example

- verification that accepts an invalid collision file;
- unsafe file handling (e.g. writing outside the requested path);
- crashes or resource exhaustion that bypass the documented safety limits;
- documentation or output that misrepresents the cryptographic meaning of a result.

Out of scope:

- The known weaknesses of MD5 and SHA-1. They are documented deliberately; HashCollider
  supports them for education and comparison and warns users about them.
- The fact that truncated hashes collide easily. Demonstrating this is the purpose of the
  tool.

## Responsible use

HashCollider is intended for cybersecurity education, cryptographic experimentation and
authorized research. See [docs/security.md](docs/security.md).
