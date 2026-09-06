<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Security Policy

## Scope
Security-sensitive AIAP areas include:
- Owner Key and Avatar Key handling;
- ownership proof;
- Passkey/WebAuthn bindings;
- Transfer Certificate signatures;
- destination binding;
- nonce and replay protection;
- certificate consumption;
- key rotation, revocation, and recovery;
- protected Memory and Artifact export/import;
- Extension permissions.

## Reporting
For a public GitHub release, security issues should initially be reported through GitHub's private vulnerability reporting feature when enabled, rather than a public issue.

If private reporting is not enabled, the maintainer should configure a dedicated security contact before production deployment.

## Disclosure
The project aims for coordinated disclosure after a fix or mitigation is available.

## No private keys
Issue reports, logs, examples, and test cases MUST NOT contain real private keys, authentication cookies, recovery secrets, or production credentials.
