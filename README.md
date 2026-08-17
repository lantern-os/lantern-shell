# lantern-shell

The **user shell**: session management, the user's surfaces, and — most importantly — the
**locus of consent**. The shell is where the user sees and grants capabilities to apps and
agents, and where the [AI](https://github.com/lantern-os/lantern-docs/blob/main/wiki/AI.md) audit log surfaces.

- **Layer:** userland (confined user space).
- **System context:** [wiki/Architecture](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Architecture.md), [wiki/AI](https://github.com/lantern-os/lantern-docs/blob/main/wiki/AI.md).
- **Long-term direction:** the shell is also the eventual home of the Intent Interface and
  Personal Agent surface described in [wiki/Intent-Model](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Intent-Model.md).
  Current scope stays limited to the consent-broker role below; see [`STATUS.md`](./STATUS.md).

> ⚠️ **Phase 0.** Design only; no code. See [`STATUS.md`](./STATUS.md).

## In this repo
- [`ARCHITECTURE.md`](./ARCHITECTURE.md), [`THREAT_MODEL.md`](./THREAT_MODEL.md), [`STATUS.md`](./STATUS.md).

## Why the shell matters to security
Capabilities are only as good as the moment they are granted. The shell makes granting
**visible, intentional, and revocable**, turning the capability model into something a human
can actually reason about.
