<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# AIAP Governance

**Project:** AI Avatar Protocol (AIAP)  
**Founding Author / Project Maintainer:** Wang Lu  
**Governance status:** v0.3 public-release governance

## 1. Purpose

AIAP governance exists to preserve interoperability, security, implementation neutrality, and the long-term stability of the Core protocol while allowing open community participation.

## 2. Roles

### Project Maintainer
The Project Maintainer coordinates releases, repository administration, security response, and acceptance of normative protocol changes.

For the v0.3 public release, the Project Maintainer is **Wang Lu**.

### Contributors
Any person or organization may propose issues, pull requests, test cases, documentation improvements, adapters, Extensions, or protocol changes under the repository contribution terms.

### Implementers
Implementers may build independent AIAP-compatible products without becoming project members.

## 3. Decision principles

Normative changes should be evaluated against:
1. interoperability benefit;
2. backward compatibility;
3. security and privacy impact;
4. implementation complexity;
5. vendor and model neutrality;
6. testability;
7. separation of Core and Extensions.

## 4. Change process

A material normative change SHOULD include:
- a problem statement;
- proposed normative text;
- compatibility analysis;
- security/privacy analysis;
- Schema changes where applicable;
- test vectors or conformance tests where practical.

Breaking Core changes require a new protocol version.

## 5. Versioning

AIAP uses semantic release identifiers for project releases and explicit protocol version identifiers for normative objects.

- Patch releases: editorial fixes, tests, non-breaking implementation fixes.
- Minor releases: backward-compatible capabilities or clarifications.
- Major releases: incompatible Core changes.

## 6. Transparency

Accepted normative changes SHOULD be visible in public version history. Security vulnerabilities may be handled privately until coordinated disclosure is safe.

## 7. Independence of implementation

Governance authority over the official AIAP specification does not give the project control over independent implementations. Implementers remain free to choose their own business model, runtime, model provider, infrastructure, and user experience.

## 8. Future governance transition

As independent implementations and contributors grow, AIAP MAY transition to a multi-maintainer technical steering model or a neutral standards organization. Any such transition SHOULD preserve open implementation rights and published protocol history.
