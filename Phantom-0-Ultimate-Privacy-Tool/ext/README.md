# Extensibility & Plugin API (offline)

Plugins are simple executables placed in `ext/plugins.d/`.
They are invoked with environment variables and must not perform network calls
unless explicitly documented and enabled by the user.

**Contract (example):**
- Input env: `PH0_PHASE` (preflight|start|shutdown), `PH0_DRY_RUN` (0|1)
- Output: write human-readable notes to stdout; exit non-zero on failure.

See `examples/hello_plugin.sh`.
