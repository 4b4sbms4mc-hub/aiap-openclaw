# AIAP Runtime Adapter Interface Contract v0.1

```text
inspect_runtime() -> RuntimeProfile

compile_context(
  avatar_core,
  relevant_state,
  workflow_descriptor = null
) -> RuntimeContext

resolve_capability(
  capability,
  runtime_profile
) -> RuntimeBinding

execute_workflow(
  workflow_descriptor,
  runtime_bindings,
  runtime_context
) -> RuntimeExecutionResult

emit_trace(
  runtime_execution_result
) -> ExecutionTrace

export_delta(
  runtime_execution_result,
  interaction_evidence
) -> StateDelta
```

## Required semantic guarantees
- Context compilation is task-scoped and minimizes disclosure.
- Capability resolution never hides degraded mappings.
- Execution uses the semantic Workflow as the stable source of intent.
- Trace output is auditable but never requires private chain-of-thought.
- Delta output is a proposal; protected Avatar state changes require validation.
