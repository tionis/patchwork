# Future Considerations

This file tracks important design/implementation decisions intentionally deferred during early prototype work.

## Deferred for Later

1. **V1 invariants list**
   - Minimal rules that should not drift during implementation.

2. **Event envelope contract**
   - Exact payload shapes for SSE (`snapshot`, `update`, `heartbeat`, `error`) and pubsub events.

3. **Idempotency semantics**
   - `dedupe_key` scope, retention window, and duplicate behavior.

4. **Blob integrity and GC defaults**
   - Hash verification strategy at `complete-upload`.
   - Default GC grace period and delete safety checks.

5. **DB lifecycle policy**
   - DB creation/deletion authority and naming constraints.

6. **Secrets model**
   - Storage/rotation/access model for `token_ref` and upstream credentials.

7. **Backpressure and limits**
   - Watch limits, connection limits, outbox limits, and overload behavior.

8. **Legacy Patchwork compatibility matrix**
   - Explicit `kept / changed / dropped` decision per route/feature.

9. **Test strategy**
   - Concurrency/fencing tests, reactive query correctness, blob GC race coverage, and compatibility tests.

## Notes

- These items are intentionally deferred to keep prototype velocity high.
- Add concrete decisions here (or move them into `DESIGN.md`) when implementation pressure requires them.
