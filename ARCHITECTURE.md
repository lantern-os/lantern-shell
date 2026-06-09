# lantern-shell — Architecture

Companion to [wiki/Architecture](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Architecture.md). The shell is an
ordinary confined component — it has no special kernel privilege. Its power comes from being
the component the user *trusts to mediate consent*, holding the capabilities it brokers on the
user's behalf.

## Responsibilities
- **Session & surfaces** — launch, switch, and present apps/agents (UI surfaces are out of
  scope to specify here; the security role is the focus at Phase 0).
- **Consent broker** — when an app/agent requests authority (per its SDK manifest), the shell
  presents a comprehensible prompt and, on approval, mints an **attenuated** capability and
  grants it. Denial is the default.
- **Capability inspector** — show the user what each app/agent currently holds, and let them
  **revoke** with one action.
- **Audit surface** — present the [AI runtime](https://github.com/lantern-os/lantern-ai-runtime) audit log: what each
  agent did, under which capability, when.

## Design principles
- **Deny by default; least privilege.** Grants are explicit, minimal, time- or scope-bounded.
- **Comprehensible consent.** Standard capability *shapes* (read-this-folder, send-to-this-
  address) so prompts are meaningful, not click-through ([AI](https://github.com/lantern-os/lantern-docs/blob/main/wiki/AI.md)).
- **No ambient escalation.** The shell cannot grant authority it does not itself hold.

## Open questions
- The consent UX that resists fatigue while staying truthful.
- How much the shell holds vs. delegates immediately.
- Representing revocation consequences understandably to users.
- Multi-persona ([Identity](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Identity.md)) presentation in the surface.
