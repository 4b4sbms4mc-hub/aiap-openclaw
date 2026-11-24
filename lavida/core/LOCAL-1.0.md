# Core 1.0 for one owner on one computer

One local Core directory holds the Avatar identity, SQLite state and local Owner credentials. Give each runtime its own Adapter credential and bind it to the same Avatar and authorized space. Memory MCP 0.3.8 is the compatible stdio adapter. The Owner approves proposals independently. Pending proposals become searchable after approval. Grant expiry and revocation apply separately to each adapter.

The default local retrieval path works offline with SQLite. Optional embedding can change ranking. Check each search response for the method actually used. A retrieved memory can contain obsolete or incorrect business facts. The host must verify those facts before acting.

## Upgrading from 0.2.4

1. Stop all MCP processes and services accessing the local Core. Make a private, permission-preserving backup of the complete directory, including the database, key files and credentials. Protect that backup like the original.
2. Install the Core 1.0.0 wheel and compatible adapter in a separate Python environment. Point each runtime to its new executable, keeping the existing data directory, Avatar ID, space and its own credential. An existing Core does not need initialization or new grants for this upgrade.
3. Restart the runtimes. Check adapter status and search for a known approved record. Verify pending and archived records still have their expected visibility.
4. To roll back before further work, stop the new processes and point the old installation to the protected pre-upgrade copy. Preserve the post-upgrade directory separately if it contains newer changes.

The 1.x compatibility boundary includes reopening existing local state, independent adapter grants and the documented local memory interfaces. The documented MCP interface is versioned independently. Internal SQLite tables and private Python methods can change. Multi-device trust, network migration and multi-tenant isolation are outside this release's supported scope.

Mirror is currently shipped with Core as an Owner-only local CLI feature. Ordinary runtime retrieval does not consume its private output. Independent extension packaging is future work.
