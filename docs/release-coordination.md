# Release coordination

## Compatibility contract

| Component | Version/status |
|---|---|
| Hermes | Tested target `v2026.7.7.2` / `v0.18.2` |
| Python | `>=3.11,<3.14` |
| Phoenix feature floor | `v0.15.2` for health/policy/list/resolve, sealed envelopes/dry-run, and role-session mint/renew |
| Phoenix Hermes audit capture | Required coordinated release after B6; version not assigned yet |

The plugin may be tested against Phoenix v0.15.2, but a public release claiming first-class Hermes audit metadata must wait for the Phoenix tag containing B6. Until then Phoenix safely ignores `X-Hermes-*`; those headers are audit-only and never participate in authentication, ACL, policy, sealing, or attestation.

## Release gate

1. B4/B5 plugin commits pass offline pytest, compileall, diff checks, and fresh security review.
2. The real-server integration tier passes against the intended Phoenix release binary. A local development skip is acceptable evidence of unavailability, not release evidence.
3. Phoenix B6 lands with shared metadata sanitization/capping, `X-Phoenix-Tool` coexistence, scenario-20, docs, and a tagged minimum release.
4. Re-run `hermes phoenix verify` and a Hermes v0.18.2 host smoke using a scratch profile.
5. Confirm `enable_resolve` remains default false and Hermes toolset defaults cannot expose it.
6. Confirm no plugin, SecretSource, scrub, or role-session plaintext cache file is created.
7. Update the README minimum Phoenix line from the feature floor to the coordinated B6 release before publication if first-class audit capture is part of the release claim.

## Path ownership

- Phoenix Path A owns gateway bootstrap (`env-exec`).
- `hermes-phoenix` SecretSource owns mapped startup fetches after plugin registration; no disk cache.
- `hermes-phoenix` tools own runtime status/list/resolve and opaque sealed output.
- Phoenix core owns trustworthy storage/audit of the plugin's untrusted `X-Hermes-*` hints.

## Rollback

Disable the plugin per profile by removing `phoenix` from `plugins.enabled`. Because the plugin stores no values or role sessions on disk, no cache cleanup is required. Path A remains independent. Removing `enable_resolve` or setting it false removes resolve registration after restart without affecting status/list.
