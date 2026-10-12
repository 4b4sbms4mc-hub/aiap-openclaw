# AIAP Procedural State Protocol v0.1 — Frozen Schema Set

Author: Wang Lu
Status: v0.1 protocol baseline

## First-class protocol objects

1. `Capability` — runtime-neutral semantic ability. This is a first-class AIAP protocol object, not a SkillDescriptor field.
2. `WorkflowDescriptor` — user-owned procedural semantics; workflow steps reference Capability IDs.
3. `SkillDescriptor` — runtime-specific implementation/package descriptor; declares capabilities it can provide.
4. `RuntimeBinding` — maps a Capability to a concrete Skill / Tool / Agent / API / composite implementation in a runtime.
5. `ExecutionTrace` — auditable execution summary used for continuity, evaluation and learning; it never requires private chain-of-thought.

## Frozen architectural rule

`Workflow -> Capability -> RuntimeBinding -> Skill/Tool/Agent/API`

A portable workflow MUST reference capabilities rather than concrete runtime skills, except when explicitly marked `runtime_specific`.

## Capability mapping classes

- `exact`
- `compatible`
- `partial`
- `composite`
- `unresolved`

## Extension rule

Every top-level object reserves `extensions` for namespaced future data. This allows later domains such as `aiap.interface.*`, `aiap.account.*`, `aiap.identity.*`, and `future.*` without changing the Core object model.

## Protocol boundary

AIAP defines portable facts/contracts. A runtime decides execution strategy, cache policy, workflow-learning algorithms, model selection, and tool implementation.
