# AIAP Runtime Adapter Specification v0.1

**Author:** Wang Lu  
**Status:** Protocol Baseline / Frozen v0.1  
**Schema dialect:** JSON Schema Draft 2020-12

## 1. Purpose

AIAP Runtime Adapter defines the interoperability boundary between a user-owned AIAP Avatar and heterogeneous AI runtimes. A runtime does not need native AIAP support. An adapter translates portable Avatar state, Workflow semantics and runtime-neutral Capability requirements into constructs the target runtime can consume, and returns auditable execution results and proposed state deltas.

## 2. Architectural boundary

AIAP defines portable facts and contracts. The Adapter translates them. The Runtime executes them.

`Person -> Avatar -> Workflow -> Capability -> Runtime Adapter -> Runtime -> Skill/Tool/Agent/API`

The Adapter MUST NOT become the owner of the Avatar.

## 3. Compatibility levels

### AIAP-L1 — Context Compatible
The adapter can select and compile task-relevant AIAP state into context/files/instructions consumable by a non-native runtime.

### AIAP-L2 — Capability Compatible
In addition to L1, the adapter can inspect runtime abilities, resolve AIAP Capability objects into explicit RuntimeBinding records, execute portable workflows, and emit ExecutionTrace records.

### AIAP-L3 — Native Avatar Compatible
The runtime natively understands AIAP Avatar/state semantics and can import/resolve state, resolve capabilities, execute workflows, emit traces, and participate in validated state synchronization.

A product MUST NOT claim a higher compatibility level unless all mandatory behavior of lower levels is also satisfied.

## 4. Normative interfaces

1. `inspect_runtime() -> RuntimeProfile`
2. `compile_context(AvatarCore, relevant_state, WorkflowDescriptor?) -> RuntimeContext`
3. `resolve_capability(Capability, RuntimeProfile) -> RuntimeBinding`
4. `execute_workflow(WorkflowDescriptor, RuntimeBindings, RuntimeContext) -> execution result`
5. `emit_trace(execution result) -> ExecutionTrace`
6. `export_delta(execution/interaction evidence) -> StateDelta`

## 5. Capability mapping

Every mapping MUST use exactly one class:
- `exact`
- `compatible`
- `partial`
- `composite`
- `unresolved`

Mappings MUST be explicit and auditable. `partial` or `unresolved` MUST NOT be silently represented as `exact`. Mapping records SHOULD preserve confidence, limitations and verification time.

## 6. Minimum State Disclosure

Adapters MUST request only state reasonably required for the task/workflow. StateRequest exists to make the purpose and requested domains explicit. Whole-history disclosure SHOULD NOT be the default.

## 7. Bidirectional state flow

Inbound: AIAP -> Runtime: Core/state slices, Workflow and Capability requirements.

Outbound: Runtime -> AIAP: ExecutionTrace and StateDelta candidates.

A Runtime MAY propose changes; it MUST NOT unilaterally rewrite protected Avatar state. StateDelta is a proposal until validated by AIAP policy and, where required, user confirmation.

## 8. Core promotion

Observed behavior MUST NOT automatically become Avatar Core. Recommended lifecycle:

Observation -> StateDelta Candidate -> confidence/evidence -> validation -> user/policy approval -> Personal/Procedural State -> later Core promotion if stable.

## 9. Security

Secrets, private keys, passwords and bearer credentials MUST NOT be embedded in RuntimeContext, WorkflowDescriptor, Capability, RuntimeBinding, ExecutionTrace or StateDelta. Implementations SHOULD use opaque credential references and a separate credential provider/store.

Adapters MUST respect ownership, authorization, state scope and revocation decisions made by the AIAP layer.

## 10. Runtime neutrality

Portable WorkflowDescriptor semantics MUST be expressed through Capability IDs rather than vendor-specific implementation IDs. Runtime-specific workflows are allowed only when explicitly declared runtime-specific.

## 11. Relationship to Procedural State v0.1

This package depends conceptually on:
- WorkflowDescriptor
- Capability
- SkillDescriptor
- RuntimeBinding
- ExecutionTrace

The invariant is:

`WorkflowDescriptor -> Capability -> RuntimeBinding -> Skill / Tool / Agent / API`

## 12. Extension policy

All protocol objects reserve `extensions` for namespaced data. Future domains such as `aiap.interface.*`, `aiap.account.*`, `aiap.identity.*` and `future.*` can be added without changing v0.1 core semantics.

## 13. Conformance target

A reference test SHOULD verify:
- schema validity;
- compatibility-level claims;
- minimum-state request behavior;
- all five mapping classes;
- no silent mapping upgrades;
- trace emission without requiring chain-of-thought;
- StateDelta validation before protected-state mutation;
- secret exclusion;
- cross-runtime workflow recovery.

## 14. Non-goals

v0.1 does not standardize model selection, prompt optimization, workflow-learning algorithms, cache scoring, memory engines, tool execution internals, marketplace/settlement, global capability taxonomy, or UI/embodiment layers.
