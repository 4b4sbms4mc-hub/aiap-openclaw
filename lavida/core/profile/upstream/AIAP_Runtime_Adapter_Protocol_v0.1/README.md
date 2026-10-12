# AIAP Runtime Adapter Protocol v0.1

Author: Wang Lu

This protocol package defines how AIAP Avatars interoperate with heterogeneous AI runtimes without requiring native AIAP adoption.

## Compatibility
- L1 Context Compatible
- L2 Capability Compatible
- L3 Native Avatar Compatible

## Included schemas
- RuntimeAdapterDescriptor
- RuntimeProfile
- RuntimeContext
- StateRequest
- StateDelta

## Required interfaces
`inspect_runtime`, `compile_context`, `resolve_capability`, `execute_workflow`, `emit_trace`, `export_delta`.

## Dependency
Designed to pair with AIAP Procedural State Protocol v0.1:
`Workflow -> Capability -> RuntimeBinding -> Skill/Tool/Agent/API`.
