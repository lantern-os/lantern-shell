# lantern-shell — Threat Model

Inherits the [system threat model](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Threat-Model.md). The shell mediates
consent, so its integrity affects whether the capability model is *usable* safely (system
threats T4, T9).

## Assets
- Integrity of consent decisions (no grant without genuine user intent).
- Capabilities the shell holds on the user's behalf.
- Faithful presentation of held capabilities and the audit log.

## Threats and mitigations
| # | Threat | Mitigation |
| --- | --- | --- |
| SH1 | UI redress / spoofed consent prompt | Trusted-path presentation for consent; standard, recognisable capability shapes. |
| SH2 | Consent fatigue → over-granting | Least-privilege defaults; bounded/scoped grants; meaningful (not click-through) prompts. |
| SH3 | Compromised shell escalates authority | Shell is confined and cannot grant authority it doesn't hold; deny-by-default. The launch binder ([ADR-0025](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0025-launch-binder.md)) can mint any `ops` on any object in the services it holds, but can't read key material, and parses only signed input. |
| SH5 | Flash contents attack or mislead the policy store | Parsed in `policy-store`, not the binder, which holds mint authority. Anything malformed fails closed, and the store can only narrow the compiled-in policy ([ADR-0027](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0027-persistent-revocation-store.md)). **Offline tampering and rollback aren't mitigated:** erasing the flash restores every revoked role, until a hardware root of trust exists. |
| SH6 | The audit log misses or misreports a grant | A grant is recorded before it's attempted, and a log that can't take the record declines it. Records are hash-chained, so an edit that doesn't rewrite everything after it reads as corrupt ([ADR-0029](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0029-audit-log.md)). **Not mitigated:** a compromised binder or store, a consistent rewrite from outside, and anything a guest does with a grant. |
| SH4 | Whoever holds the binder's control capability withdraws grants | It can only withdraw: it can't create or widen a grant, sees no badges, and reaches no key material ([ADR-0026](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0026-grant-ledger-and-revocation.md)). v0 gives it to one scripted test program. Revocation isn't yet durable or user-driven. |
| SH4 | Misleading capability/audit display | Display derived from the actual held caps and the tamper-evident log, not self-reported. |
| SH5 | Cross-persona linkage in the surface | Persona separation surfaced clearly ([Identity](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Identity.md)). |

## Non-goals
- Protecting a user who deliberately grants broad authority after a truthful prompt.
- General GUI/compositor security beyond the consent trusted path (Phase 0 focus).
