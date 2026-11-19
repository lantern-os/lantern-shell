# lantern-shell

The **user shell**: session management, the user's surfaces, and — most importantly — the
**locus of consent**. The shell is where the user sees and grants capabilities to apps and
agents, and where the [AI](https://github.com/lantern-os/lantern-docs/blob/main/wiki/AI.md) audit log surfaces.

- **Layer:** userland (confined user space).
- **System context:** [wiki/Architecture](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Architecture.md), [wiki/AI](https://github.com/lantern-os/lantern-docs/blob/main/wiki/AI.md).
- **Long-term direction:** the shell is also the eventual home of the Intent Interface and
  Personal Agent surface described in [wiki/Intent-Model](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Intent-Model.md).
  Current scope stays limited to the consent-broker role below; see [`STATUS.md`](./STATUS.md).

> **Phase 4** ([RFC-0036](../lantern-rfcs/rfcs/0036-phase-3-to-phase-4-transition.md)): hardware and assurance. The launch
> binder, the launcher, the shell (the trusted path, where a person decides every grant),
> `policy-store` (remembered decisions and the audit log) and the `archiver`, which keeps audit history sealed before the
> log retires it ([RFC-0038](../lantern-rfcs/rfcs/0038-signed-models-and-kept-audit-history.md)), run confined in the
> system image. See [`STATUS.md`](./STATUS.md).

## In this repo
- [`ARCHITECTURE.md`](./ARCHITECTURE.md), [`THREAT_MODEL.md`](./THREAT_MODEL.md), [`STATUS.md`](./STATUS.md).

## Why the shell matters to security
Capabilities are only as good as the moment they are granted. The shell makes granting
**visible, intentional, and revocable**, turning the capability model into something a human
can actually reason about.
