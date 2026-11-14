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
| SH1 | UI redress / spoofed consent prompt | Trusted-path presentation for consent; standard, recognisable capability shapes. Since [ADR-0032](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0032-trusted-path-and-consent.md): the shell is the only program that reaches the console, the kernel stays off it once the shell runs, and app text is shown only sanitized, in quotes, after the shell's own label. |
| SH2 | Consent fatigue → over-granting | Least-privilege defaults; bounded/scoped grants; meaningful (not click-through) prompts. ADR-0032: requests outside the ceiling never prompt, and an "always" covers only the ops it allowed. Since [ADR-0033](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0033-deadlines-and-a-capability-clock.md), a prompt nobody answers is declined after 60 seconds. **Not mitigated in v0:** persuasive justifications. |
| SH3 | Compromised shell escalates authority | Shell is confined and cannot grant authority it doesn't hold; deny-by-default. The launch binder ([ADR-0025](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0025-launch-binder.md)) can mint any `ops` on any object in the services it holds, but can't read key material, and parses only signed input. |
| SH5 | Flash contents attack or mislead the policy store | Parsed in `policy-store`, not the binder, which holds mint authority. Anything malformed fails closed, and the store can only narrow the compiled-in policy ([ADR-0027](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0027-persistent-revocation-store.md)). **Offline tampering and rollback aren't mitigated:** erasing the flash restores every revoked role, until a hardware root of trust exists. |
| SH6 | The audit log misses or misreports a grant | A grant is recorded before it's attempted, and a log that can't take the record declines it. Records are hash-chained, so an edit that doesn't rewrite everything after it reads as corrupt ([ADR-0029](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0029-audit-log.md)). Each use of a grant is recorded by the service before it acts, and the store limits what each writer badge may append ([ADR-0030](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0030-audit-log-service-operations.md)). **Not mitigated:** a compromised binder, store or service omitting its own records, a consistent rewrite from outside, and a forged retirement. **Review rule:** every service that serves granted authority records through `lantern_abi::policy::audited`. |
| SH7 | App text injects terminal control sequences, or imitates the shell | Every byte an app supplied passes only as printable ASCII, with `"` and `\` replaced, so it can't move the cursor, start a line, or close its own quotation (ADR-0032). `console-matrix.sh` checks a hostile justification, and a mutation that disables the sanitizer fails it. |
| SH9 | The launcher runs what nobody asked for, or lets an app reach another's memory | Only the shell can ask it, so a person starts every app. It verifies every package, and the binder verifies each again from its own mapping; a registration names only a package the binder verified ([ADR-0035](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0035-a-confined-launcher.md)). Each slot's channel comes from system memory, is cleared between apps, and is served only to badges the binder's grant tied to that slot; the runtime refuses a channel that isn't clean. App memory is the slot's alone, and the kernel zeroes it. **Not mitigated:** a compromised launcher can give a runtime a different verified package than it registered. |
| SH8 | Someone at the console decides for the person | **Not mitigated in v0:** there's no login, and whoever is at the console is the person. Identity and personas come with `lantern-identity`. |
| SH4 | Whoever holds the binder's control capability withdraws grants | It can only withdraw: it can't create or widen a grant, sees no badges, and reaches no key material ([ADR-0026](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0026-grant-ledger-and-revocation.md)). v0 gives it to one scripted test program. Revocation isn't yet durable or user-driven. |
| SH4 | Misleading capability/audit display | Display derived from the actual held caps and the tamper-evident log, not self-reported. |
| SH5 | Cross-persona linkage in the surface | Persona separation surfaced clearly ([Identity](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Identity.md)). |

## Non-goals
- Protecting a user who deliberately grants broad authority after a truthful prompt.
- General GUI/compositor security beyond the consent trusted path (Phase 0 focus).
