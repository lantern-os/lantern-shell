# lantern-shell — Status

**Phase:** 0 (Foundations) — design only.

## Done
- Shell-as-consent-broker role and responsibilities drafted ([ARCHITECTURE.md](./ARCHITECTURE.md)).
- Threat model drafted (consent integrity, trusted path).

## Next
- Design the consent UX and standard capability shapes (with [`lantern-ai-runtime`](https://github.com/lantern-os/lantern-ai-runtime) and [`lantern-sdk`](https://github.com/lantern-os/lantern-sdk)).
- Phase 2+: a minimal consent broker + capability inspector over the runtime.

## Blocked on
- Capability brokering + audit log ([`lantern-capabilities`](https://github.com/lantern-os/lantern-capabilities), [`lantern-ai-runtime`](https://github.com/lantern-os/lantern-ai-runtime)).
- Runtime app hosting ([`lantern-runtime`](https://github.com/lantern-os/lantern-runtime)).
