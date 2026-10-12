# AIAP State Schema v0.1

Author: Wang Lu  
Status: Draft  
JSON Schema dialect: Draft 2020-12

## Extensible state domains

The root object contains a `domains` registry.

Core domains:

- `aiap.identity`
- `aiap.preferences`
- `aiap.memory`
- `aiap.skills`
- `aiap.workflows`
- `aiap.permissions`

Third parties may add namespaced domains without modifying the root schema:

```json
"org.example.research-state": {
  "domain_id": "org.example.research-state",
  "schema_uri": "https://example.org/research-state.schema.json",
  "version": "1.0",
  "data": {}
}
```

Extension names SHOULD use reverse-DNS namespaces or `x-*`.

## Memory demotion policy

Automatic memory demotion is represented as portable policy, but executed by the runtime.

Default example:

- M0: 2 inactive days -> expire ephemeral representation.
- M1: 30 inactive days -> M3 Archive.
- M2: 180 inactive days -> M3 Archive.
- M3: remains archive.
- `pinned=true` or `decay_exempt=true`: no automatic demotion.
- `never_auto_delete=true`: durable content is not silently deleted.
- Archived memory MAY be promoted again after meaningful recall or explicit user confirmation.

Recommended inactivity clock:

`max(last_accessed_at, last_reinforced_at)`

### Why M2 archives to M3 instead of becoming M1

M1 means *working memory*, not simply “lower-value memory”.
An old long-term memory that is no longer actively useful belongs in Archive (M3).

## Safety invariant

> Time-based decay changes retrieval priority/storage tier, not truth or ownership.

Automatic demotion SHOULD reduce active recall pressure; it SHOULD NOT silently erase user-owned durable state.

## Runtime pseudocode

```text
for each memory:
    if memory.retention.pinned or memory.retention.decay_exempt:
        continue

    inactive_since = max(last_accessed_at, last_reinforced_at, created_at)
    rule = resolve_rule(memory.level, memory.retention.override, policy)

    if now - inactive_since >= rule.inactive_after_days:
        apply(rule.action)
        append transition history
        update updated_at

    if archived memory is later strongly recalled or user-confirmed:
        runtime MAY promote it back to M1 or M2
```

## Protocol boundary

JSON Schema validates the portable representation and policy semantics.
The runtime decides scheduling, scoring, retrieval indexes, embeddings, storage backend,
and the exact promotion/demotion algorithm.
