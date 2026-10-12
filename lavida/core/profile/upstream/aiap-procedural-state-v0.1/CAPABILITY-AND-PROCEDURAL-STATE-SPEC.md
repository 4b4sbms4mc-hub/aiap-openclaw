# AIAP Capability & Procedural State Protocol v0.1

## Normative architecture

Capability is promoted to a first-class protocol object adjacent in architectural importance to Identity, State and Transfer.

### Invariants
- WorkflowDescriptor MUST reference Capability by `capability_id`.
- Portable WorkflowDescriptor MUST NOT require a vendor/runtime-specific Skill ID for semantic meaning.
- SkillDescriptor MAY declare one or more Capability IDs that it implements.
- RuntimeBinding MUST bind one Capability to a concrete implementation in a named runtime.
- RuntimeBinding mapping class MUST be one of exact, compatible, partial, composite, unresolved.
- An unresolved mapping MUST NOT be silently treated as exact.
- ExecutionTrace records observable execution metadata and summaries; it MUST NOT require chain-of-thought.
- Secrets/private keys MUST NOT be stored in these five procedural-state objects.
- Runtime-specific workflows are permitted only when explicitly marked `portability=runtime_specific`.

### Capability identity
Capability IDs use `aiap:capability:*`. Semantic namespaces SHOULD be vendor-neutral, e.g.
`academic.search.primary_sources`, `source.verify.cross_validate`, `document.generate.docx`.

### Portability semantics
A workflow remains semantically stable when its runtime changes. Migration resolves each required Capability against the target runtime and creates RuntimeBinding records. Partial/composite/unresolved mappings remain explicit so recovery quality is measurable.

### Relationship to AIAP Core
Identity answers WHO owns/continues the Avatar.
State answers WHAT portable state exists.
Capability answers WHAT the Avatar/user needs to be able to do independent of runtime.
Transfer answers HOW ownership/state moves safely.
Procedural State answers HOW the user works through Workflow + Capability semantics.
