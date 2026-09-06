<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# AIAP Extension Specification v0.3

Status: Normative Draft  
Author / Project Maintainer: Wang Lu

Extensions add capabilities without changing AIAP Core semantics.

An Extension MUST declare:
- stable extension identifier
- namespace
- name and version
- capabilities
- required permissions
- dependencies where applicable
- publisher/integrity metadata where available

Extensions MUST NOT grant themselves permissions. Unknown extensions SHOULD be preserved when safely possible and MAY be ignored by runtimes that do not understand them.
