# lantern-shell — Status

**Phase:** 3 (Privacy, identity, networking, and AI) — opened per [RFC-0017](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0017-phase-2-to-phase-3-transition.md)/[ADR-0021](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0021-phase-2-complete-phase-3-opened.md). Three confined programs exist, and `policy-store` now keeps the audit log too; the consent surface is still design only — see "Blocked on".

## Done
- **The launch binder v0 (2026-11-02), this repo's first code:** `launch-binder/`, per
  [RFC-0020](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0020-launch-binder.md)/[ADR-0025](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0025-launch-binder.md).
  A confined program, and the only holder of authority to request grants from a service. It verifies
  a package, reads its manifest, decides each request against a deny-by-default policy, and passes on
  a badge minted for exactly the manifest's `ops`. **The policy is a compiled-in table, not consent:
  no person is asked.** The decision logic is host-tested (`cargo test --lib --target
  x86_64-unknown-linux-gnu`, 12 tests). Both runtime demos run with it under QEMU, and
  `lantern-boot/scripts/binder-matrix.sh` checks 14 cases, including that a read-only request stops a
  guest writing. The first-caller grant is gone from the app path.
- **The grant ledger and revocation v0 (2026-11-02):** [RFC-0021](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0021-grant-ledger-and-revocation.md)/[ADR-0026](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0026-grant-ledger-and-revocation.md). The binder records what it granted, and the
  holder of a control capability can list entries and revoke one, naming them by index and never seeing a
  badge. `grant-control/` holds that capability, and **is a test script, not a user interface**. The owning
  service enforces revocation, so the kernel doesn't change. **A revocation lasts only until the next boot**,
  when the compiled-in policy grants the same thing again (the store below changes that), so this mustn't be
  described as a durable user decision. A revoked role can't be re-granted. 16 binder tests at the time.
- **The persistent policy store v0 (2026-11-03):** [RFC-0022](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0022-persistent-revocation-store.md)/[ADR-0027](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0027-persistent-revocation-store.md). `policy-store/` is a confined service, the only program with
  flash mapped, keeping an append-only log of revoked roles that the binder consults before every grant. A revocation
  now survives a reboot, tested across real QEMU boots of one image. **It can only narrow** the compiled-in policy, and a
  corrupt store or missing flash declines everything. **It doesn't resist offline tampering:** erasing the flash restores
  every revoked role, and `binder-matrix.sh` tests that so it stays visible. 13 log tests, including a power cut at
  every word of a record, and 19 binder tests.
- **The audit log v0 (2026-11-05):** [RFC-0024](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0024-audit-log.md)/[ADR-0029](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0029-audit-log.md). `policy-store` keeps a hash-chained log of every grant, decline and revocation
  in flash sectors 1 to 7. The binder records a grant **before** attempting it, so an unrecorded grant can't happen, and a log
  that can't take the record declines it. A revocation is never blocked by the log. Declines are recorded with their reason,
  though the runtime still hears only `DECLINED`. `grant-control` reads the log through a read-only capability and recomputes the
  chain in both demos, and `policy-store/examples/audit-dump.rs` prints and verifies a flash image's log. **It records the binder's
  decisions, not what a guest did with a grant** (v1 below records that). Without a hardware key,
  a consistent rewrite of the whole chain verifies; only a kept head reveals it, and `binder-matrix.sh` tests both. 23 store tests,
  20 binder tests.
- **The audit log v1 (2026-11-10):** [RFC-0025](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0025-audit-log-service-operations.md)/[ADR-0030](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0030-audit-log-service-operations.md). **Every use of a grant is now recorded, by the service, before it acts.** The
  store decides what each badge may append and stamps a service's interface; the binder adds `GRANTED`, linking a badge to its
  role. Each audit sector has its own header, and a full ring retires its oldest sector, recording `RETIRED`; every power cut
  recovers by a rule read from flash. A per-grant quota of 1,024 records per boot refuses the rest. `OLDEST` tells a reader where
  to start. `grant-control` checks each demo's uses against its grant, and `audit-dump` joins role, badge and uses, and has
  `--fill`. With the binder's records, this is what the exit criterion's "faithful audit log" asks for, for the services that
  exist. 36 store tests, 20 binder tests.
- Shell-as-consent-broker role and responsibilities drafted and reviewed ([ARCHITECTURE.md](./ARCHITECTURE.md)).
- Threat model drafted and reviewed (consent integrity, trusted path).

- **The shell, and consent (2026-11-11, [RFC-0026](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0026-trusted-path-and-consent.md)/[ADR-0032](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0032-trusted-path-and-consent.md)).** `shell/` is the only program that reaches the console: it alone maps the
  UART and holds its `IrqHandler`. It shows each request a person decides, sanitizing every byte an app supplied, and
  answers yes once, always, no or never. It lists grants (`grants`), revokes them (`revoke N`), shows the audit log after
  verifying its chain (`audit`), and lists and forgets remembered answers (`decisions`, `forget N`). It waits on one
  notification, whose badge bits are its inputs, so no kernel change was needed. The binder, launched `WITH_CONSENT`, treats
  its policy as a ceiling and asks within it, recording `CONSENTED` or the person's decline first. A console revoke forgets
  "always" so the next boot asks again; "never" is permanent until `forget`. `policy-store` keeps remembered decisions in
  sector 1 (`decisions.rs`), and the audit ring moves to sectors 2 to 7, format 3. 7 shell tests, 23 binder tests, 42 store
  tests. `lantern-boot`'s `console-matrix.sh` drives it under QEMU, 14 cases. No login: whoever is at the console decides.
- **Consent has a limit (2026-11-12, [RFC-0028](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0028-deadlines-and-a-capability-clock.md)/[ADR-0033](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0033-deadlines-and-a-capability-clock.md)).** The binder arms its own `Deadline` for each request: nobody answering within 60
  seconds is `NO_CONSENT`, so a person who walked away, or a shell that hung, can't hold grants forever. The binder confirms
  each outcome to the shell, which says what was decided only then, and reports a late answer as too late. The shell holds
  no clock.
- **A confined launcher (2026-11-14, [RFC-0029](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0029-a-confined-launcher.md)/[ADR-0035](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0035-a-confined-launcher.md)).** A new program, **`launcher/`**, builds an app's process from a signed
  package when the shell asks, through system calls alone, in one of 4 app slots, and reclaims it when it ends.
  - **How it builds an app:** it splits its `Untyped` into 18 MiB slots, verifies the package set with the binder's own
    code, and copies the runtime's ELF and a private copy of the package into the slot's Frames. It maps in the slot's
    channel, registers the slot with the binder, and starts the runtime.
  - **When an app ends:** a report or a fault makes it `UNREGISTER`, `Reset` the slot, clear its channels, and tell the
    shell.
  - **`launch-binder`** gains `WITH_LAUNCHER`: it verifies every package in the set itself, and `REGISTER`/`UNREGISTER`
    come from the launcher alone. Each app binds under its own slot's badge, in its own ledger range (`Registry`), and each
    grant names the slot's channel. `UNREGISTER` revokes the slot's grants and records `REVOKING` with `APP_ENDED`.
  - **The shell** gains `apps` and `run NAME`, through a page it shares with the launcher, and says when each app ends.
  - **Tests:** 4 launcher tests, 25 binder tests, 7 shell tests. `lantern-boot`'s `console-matrix.sh` now has 21 cases,
    and every app is started with `run`.
## Next
- A person-set consent limit and a visible countdown; and scoped, time-bounded grants with standard capability shapes, so
  prompts say what they mean (SH2).
- Stopping a running app from the console, and an app starting another app with its own consent (RFC-0029's future
  possibilities).
- A recovery path for a corrupt store.
- Design the consent UX and standard capability shapes (with [`lantern-ai-runtime`](https://github.com/lantern-os/lantern-ai-runtime) and [`lantern-sdk`](https://github.com/lantern-os/lantern-sdk)).

## Phase 4
- **A hardware root of trust**, so the log resists offline tampering and rollback, on
  [RFC-0023](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0023-hardware-key-custody-in-phase-4.md)'s checklist.

## Blocked on
- ~~Audit log ([`lantern-ai-runtime`](https://github.com/lantern-os/lantern-ai-runtime)).~~ v0 is here, in `policy-store` (RFC-0024), until
  `lantern-ai-runtime` has code. What a guest does with a grant is recorded too, since RFC-0025.
