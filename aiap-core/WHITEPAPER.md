<!-- SPDX-License-Identifier: CC-BY-4.0 -->
AI Avatar Protocol (AIAP)

Whitepaper v0.3

An Open Protocol for User-Owned, Verifiable, Portable, and Extensible Personal AI Avatars

Author / Project Maintainer: Wang Lu
2026

# Abstract

The AI Avatar Protocol (AIAP) is an open protocol for interoperability of personal AI Avatars. It does not create a new foundation model, nor does it replace existing protocols such as MCP or A2A. Instead, above models, tools, agents, and compute infrastructure, AIAP defines the identity, ownership, long-term memory, capabilities, permissions, sessions, artifacts, secure transfer, and extension mechanisms of a user's AI Avatar. Its central objective is to prevent a person's AI Avatar from being locked to a single model or platform: models can be replaced, Skills can be extended, and Runtimes can be migrated, while the user retains continuous control over the Avatar's identity and core assets.

# 1. Background: From AI Assistants to Personal AI Avatars

In recent years, generative AI has evolved from one-shot question answering toward Agents capable of long-term memory, task planning, tool use, and complex execution. A 2026 survey of Personalized LLM-Powered Agents organizes this field around four interdependent components—Profile Modeling, Memory, Planning, and Action Execution—which closely correspond to AIAP's Profile, Memory, Planner/Workflow, and Skill Runtime layers.

At the same time, digital-twin research is moving from static digital representations toward cognitive and autonomous systems driven by foundation models and intelligent Agents. Research on LLM-driven digital twins also shows that current systems remain limited in modeling fine-grained individual differences and complex psychological characteristics. AIAP therefore does not define its goal as reproducing human consciousness. It defines an AI Avatar as a verifiable, authorizable, and portable personal AI digital agent.

# 2. Academic Foundations and Research Implications

- Personalized Agents: A 2026 survey identifies Profile, Memory, Planning, and Action as four core components of Personalized LLM Agents, providing direct theoretical support for AIAP's layered architecture.

- Personal Memory: EMG-RAG uses editable memory graphs and retrieval-augmented generation to build Personalized Agents from long-term user memories, reporting an improvement of roughly 10%. This suggests that editable and selectively portable long-term memory is a critical foundation for personal AI.

- Digital Avatars / Digital Twins: LLM-driven Digital Twins can reproduce some human attitudes and behaviors, but studies show limitations in fine-grained individual differences. AIAP therefore emphasizes verifiable user context and behavioral continuity rather than claiming complete personality replication.

- Digital Twin AI: A 2026 survey describes AI-driven digital twins progressing from modeling and mirroring toward intervention and autonomous management, while highlighting scalability, explainability, and trustworthiness. AIAP places trusted identity, permissions, and portability at the protocol core.

Together, these research directions point to a problem that has not yet been sufficiently standardized: how to turn a personalized Agent into a persistent digital object that is independent of a particular model or platform. AIAP defines this problem space as Personal AI Avatar Interoperability.

# 3. Definition of an AI Avatar

AI Avatar =
Identity + Ownership + Profile + Memory
+ Capability + Permission + Runtime

An AI Avatar is not merely a model, a chat window, or a simple user profile. The Runtime may change while the Avatar's identity and user-owned assets remain continuous.

# 4. Protocol Positioning

AIAP       → User ↔ Personal AI Avatar
MCP        → AI/Agent ↔ Tools / Data
A2A        → Agent ↔ Agent
Model API  → Intelligence Layer
Compute    → Infrastructure Layer

AIAP does not redefine tool invocation or Agent-to-Agent communication. It interoperates with these ecosystems through Adapters.

# 5. Overall Architecture

User
 │
 ├─ Human Identity
 └─ Owner Key / Passkey
          │
       AIAP Avatar
          │
 ┌────────┼────────┐
 Profile Memory Permission
          │
     Planner / Agent
          │
   Workflow Orchestrator
          │
      Skill Runtime
          │
 ┌────────┼────────┐
Models    MCP      A2A
          │
   Compute / APIs

# 6. Authentication and Ownership

AIAP strictly distinguishes the Avatar ID, Avatar ownership, and the identity of the current operator. A random Avatar ID alone cannot prove ownership. The protocol recommends mature public-key cryptography and Passkey/WebAuthn rather than custom cryptographic schemes.

- Human Identity: Real-world identity may optionally be established through OIDC, Verifiable Credentials, KYC, or equivalent mechanisms.

- Owner Key: Proves that the operator controls the Avatar.

- Avatar Key: Represents the Avatar's cryptographic identity and may be authorized by the Owner Key.

- Passkey/WebAuthn: Allows ordinary users to authorize signatures using fingerprint, Face ID, or operating-system security mechanisms.

- Challenge/Nonce: Prevents replay of transfer authorization.

- Key Rotation / Revocation: Supports key rotation, revocation, and recovery.

# 7. Secure Transfer: Cross-Platform Avatar Migration

Source Platform
  ↓ Transfer Challenge
User + Passkey
  ↓ Sign(avatar_id + source + destination + nonce + expiry)
Transfer Certificate
  ↓ Verify
Destination Platform
  ↓
Import Avatar

The Avatar file itself is not proof of ownership. AIAP proposes an AIAP Transfer Certificate that uses a one-time Challenge/Nonce to prove that the Owner explicitly authorized a specific transfer. Copying an avatar.aiap file must not by itself transfer ownership of the Avatar.

# 8. Memory: Persistent Personal Memory

- Semantic Memory: facts, knowledge, and preferences.

- Episodic Memory: past events and interactions.

- Procedural Memory: habitual ways of working.

- Project Memory: persistent context associated with a specific project.

Memory should support provenance, timestamps, confidence, editability, and permission controls. A system must not treat a remembered statement as permanently true merely because it was stored.

# 9. Capability: Skills and Workflows

Avatar
 ├─ Skills: Web Search / Excel / Coding / APIs
 └─ Workflows: Research / Report / Planning

A Skill describes what the Avatar can do; a Workflow describes how a complex task is completed. Complex capabilities are added through Extensions rather than hard-coded into the Core.

# 10. Permission: Behavioral Boundaries

READ       → AUTO
WRITE      → CONFIRM
FINANCIAL  → CONFIRM / DENY
ADMIN      → DENY by default

An Extension may declare the permissions it requires, but it cannot grant those permissions to itself. High-risk actions such as sending email, conducting financial transactions, or deleting data should support explicit human confirmation.

# 11. Extensions: Open-Ended Extensibility

- The Core remains stable while complex capabilities evolve through Extensions.

- The official namespace is aiap.*.

- Third parties may use reverse-domain namespaces or verifiable organization identifiers.

- Unknown Extensions must not break the Core Avatar.

- Extensions must declare version, dependencies, permissions, and compatibility.

Core → Extension Manifest → Capability Registry → Install → Authorize → Activate

# 12. Registry: An Internet of AI Capabilities

The Capability Registry provides capability discovery, versioning, dependencies, provenance, integrity information, and revocation status. Multiple Registries may coexist; AIAP does not require a single centralized global marketplace. Over time, this can support an ecosystem of Skills, Workflows, Agents, Data, and APIs.

# 13. Adapters: Compatibility with Existing Ecosystems

- MCP Adapter: tool and data capabilities.

- A2A Adapter: Agent collaboration.

- OpenClaw Adapter: mapping between OpenClaw and an AIAP Avatar.

- Model Adapter: GPT, Claude, Gemini, Qwen, DeepSeek, Llama, and other models as replaceable execution engines.

AIAP therefore does not need to train its own foundation model in order to function.

# 14. Avatar Portability

Platform A
 ↓ Export
AIAP Avatar Package
 ↓ Owner Verification
Platform B
 ↓ Import
Same Avatar Identity

Portable objects may include Profile, Preferences, Portable Memory, Skill/Workflow manifests, and Permission Policies. Platform-private keys and OAuth refresh tokens are excluded from export packages by default.

# 15. Trust Model

- Identity Trust: Who is the Owner?

- Integrity Trust: Has the Avatar Package been tampered with?

- Capability Trust: Who published the Skill/Extension, and has it been revoked?

- Execution Trust: Has the current platform been authorized to perform this operation?

These four trust dimensions are not interchangeable. Even a legitimately owned Avatar must not automatically authorize a malicious Skill.

# 16. Boundary Between an AI Avatar and a Digital Personality

AIAP does not claim to reproduce human consciousness, subjective experience, or a complete personality. Current research on LLM-driven Digital Twins shows that models can reproduce some population-level or behavioral patterns but remain limited in fine-grained psychological differences. AIAP therefore defines the Avatar as a persistent personal AI agent, not as a legal or metaphysical replica of a human personality.

# 17. Commercial Ecosystem

Users      → Own Avatar → Consume Capabilities
Developers → Skills / Workflows / Agents
Providers  → Runtime / Models / Compute

An open protocol does not eliminate commercial value. Potential business layers include Avatar Hosting, Capability Marketplaces, Model/Compute Routing, Enterprise Runtime, Security, Certification, and developer settlement.

# 18. Open Governance and Licensing

AIAP proposes a layered licensing model: protocol specifications and documentation under CC BY 4.0; Schemas, examples, SDKs, and reference implementations under Apache-2.0; and the AIAP / AI Avatar Protocol name and logo governed by a separate trademark policy. This approach is intended to support broad standards adoption and commercial use while preserving the integrity of official project identity.

# 19. Roadmap

- v0.1: Avatar Core, Identity/Ownership, Memory, Permission, Extension Manifest, Export/Import.

- v0.2: Secure Transfer, Memory API, Skill/Workflow API, MCP/A2A Adapter, Registry, Signature.

- v0.3: Integrated Core security specification, OpenClaw Reference Adapter direction, cross-platform migration testing, and Conformance Test preparation.

- v1.0: Stable Core, standardized Transfer Protocol, certification/compatibility program, and multiple independent implementations.

# 20. Research Agenda

- Personal Avatar Evaluation

- Memory Provenance

- Avatar Identity and Key Recovery

- Transfer Security

- Capability Trust / Reputation

- Human-Likeness Boundaries

- Multi-Model Continuity

# 21. Conclusion

The next stage of AI may not be everyone using the same super-AI, but each person owning a personal AI Avatar that can draw on an entire internet of AI capabilities. AIAP does not aim to create another foundation model. Its purpose is to provide the identity, memory, capability, permission, portability, and interoperability infrastructure required for such a future.

AIAP = Identity + Ownership + Memory + Capability + Permission + Portability + Interoperability

# Core Protocol Upgrade: Identity + Ownership + Secure Avatar Transfer

This section incorporates the v0.2 identity and secure-transfer work into the AIAP Core. It is not an optional security module. It addresses the foundational questions of cross-platform Avatar existence: who owns an Avatar, how control is proven, how transfer is authorized, and how replay and impersonation are prevented.

## A. Identity Model

- AIAP distinguishes the Human Owner, AI Avatar, and Custodian/Runtime. The Owner is the control principal; the Avatar is the controlled digital object; the Platform/Runtime is a hosting or execution service.

- Human Identity may be supported through OIDC, Verifiable Credentials, KYC, or equivalent external mechanisms, but it is not a mandatory AIAP Core dependency.

- Owner Identity establishes cryptographic control through a stable Owner ID and Owner Key.

- Avatar Identity establishes object-level identity through a unique Avatar ID and Avatar Key.

- Possession of Avatar data is not proof of ownership; copying Avatar data does not confer Owner privileges.

## B. Formal Identity Data Structure

The Core Identity Record contains at minimum schema_version, avatar_id, owner, avatar_key, and status; it may additionally contain created_at, updated_at, recovery, and revocation.

The Owner object contains owner_id, identity_assurance, and key_binding. The Avatar Key contains key_id, public_key, algorithm, and purpose.

Mature algorithms such as Ed25519, ES256, and RS256 are recommended, with Passkey/WebAuthn providing a practical signing interface for ordinary users.

## C. Ownership and Key Management

- The Owner Key proves user control; the Avatar Key represents the Avatar object's identity. They must remain logically separate.

- Key rotation, revocation, and recovery mechanisms must be supported.

- High-risk operations should use short-lived authorization, least privilege, and secondary confirmation.

- Recovery may use multi-key thresholds, recovery credentials, or controlled custody, but the process must be auditable.

## D. Secure Avatar Transfer

- Secure Avatar Transfer is an AIAP Core protocol, not ordinary file import/export.

- Transfer authorization must bind avatar_id, owner_id, source, destination, issued_at, expires_at, nonce, transfer_scope, and Owner proof.

- The Destination first generates a challenge/nonce. The Source presents the transfer target, destination platform, transfer scope, and permission implications to the user. The Owner signs using Passkey/WebAuthn or an Owner Key. Import is allowed only after Destination verification.

- A Transfer Certificate must be single-use. After successful import it becomes consumed; an expired certificate becomes expired; a revoked certificate becomes revoked.

- The certificate must be bound to a specific destination to prevent forwarding of authorization to a third-party platform.

## E. Transfer Certificate Example

{
  "schema_version": "0.3",
  "certificate_id": "aiap:transfer:tx-001",
  "avatar_id": "aiap:avatar:example-001",
  "owner_id": "aiap:owner:example-owner",
  "source": {
    "platform_id": "source",
    "endpoint": "https://source.example/aiap"
  },
  "destination": {
    "platform_id": "destination",
    "endpoint": "https://destination.example/aiap"
  },
  "issued_at": "2026-09-06T10:00:00Z",
  "expires_at": "2026-09-06T10:10:00Z",
  "nonce": "RANDOM_NONCE",
  "transfer_scope": {
    "mode": "selective",
    "include_memory": true,
    "include_profile": true,
    "include_skills": true,
    "include_workflows": true,
    "include_permissions": false
  },
  "constraints": {
    "single_use": true,
    "max_import_count": 1
  },
  "proof": {
    "type": "owner-signature",
    "key_id": "owner-key-01",
    "algorithm": "Ed25519",
    "challenge": "DESTINATION_CHALLENGE",
    "signature": "BASE64URL_SIGNATURE"
  }
}

## F. Security and Privacy Requirements

- Ownership must not be asserted solely by possession of an avatar.aiap file.

- The nonce must have sufficient entropy; the certificate must have an explicit validity period; consumed state must be persisted.

- Implementations should not sign arbitrary JSON text directly. They should use deterministic serialization or a defined canonicalization procedure.

- The Transfer Certificate proves authorization but does not itself provide data encryption. Sensitive Avatar Packages should be encrypted separately.

- Transfers should follow data minimization and selective-transfer principles and should not contain unnecessary personally identifiable information (PII).

## G. Relationship to MCP and A2A

AIAP operates at the Avatar object layer, governing Identity, Ownership, Portability, and Avatar-level authorization. MCP connects Agents/Models to tools, resources, and data sources. A2A supports Agent-to-Agent communication and collaboration. AIAP integrates MCP and A2A through Adapters rather than replacing them.

## H. Recommended v0.3 Core Specification Files

spec/
├── SPECIFICATION.md
├── EXTENSION-SPEC.md
├── IDENTITY-SPEC.md
├── OWNERSHIP-SPEC.md
├── TRANSFER-SPEC.md
└── KEY-MANAGEMENT.md

schemas/
├── avatar.schema.json
├── identity.schema.json
├── transfer-certificate.schema.json
├── memory.schema.json
├── permission.schema.json
└── extension.schema.json

## I. Version Evolution

v0.1 established the Core/Extensions/Adapters/Registry architecture, Skill/Workflow model, MCP/A2A interoperability, and ecosystem framework. v0.2 added Identity, Ownership, and Secure Transfer. v0.3 integrates the whitepaper and Core security specifications into a coherent protocol architecture. The next implementation priorities are a Reference Runtime, OpenClaw Adapter, Conformance Test Suite, and the path toward a stable v1.0 standard.

# References

1. Xu, Y. et al. Toward Personalized LLM-Powered Agents: Foundations, Evaluation, and Future Directions. arXiv:2602.22680, 2026.

1. Wang, Z. et al. Crafting Personalized Agents through Retrieval-Augmented Generation on Editable Memory Graphs. arXiv:2409.19401, 2024.

1. Wu, Y. et al. Assessing the Human-Likeness of LLM-Driven Digital Twins in Simulating Health Care System Trust. arXiv:2512.08939, 2025.

1. Zhou, R. et al. Digital Twin AI: Opportunities and Challenges from Large Language Models to World Models. arXiv:2601.01321, 2026.

1. Model Context Protocol (MCP) Specification.

1. Agent2Agent (A2A) Protocol Specification.

Note: The cited papers are used as academic background and related work. Their authors are not implied to participate in or endorse AIAP.

AI Avatar Protocol (AIAP) — Version 0.3
Author / Project Maintainer: Wang Lu
