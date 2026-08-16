# Release coordination

## Compatibility contract

| Component | Version/status |
|---|---|
| Hermes | Tested target `v2026.7.7.2` / `v0.18.2` |
| Python | `>=3.11,<3.14` |
| Phoenix server | `v0.16.0` or newer, including health/policy/list/resolve, sealed envelopes/dry-run, role-session mint/renew, and Hermes audit capture |
| Phoenix Hermes audit capture | Included in Phoenix `v0.16.0`, the minimum supported server |

Phoenix `v0.16.0` or newer is the minimum compatibility floor, not a paired release. Phoenix ships on its own schedule; this plugin releases separately against that floor, and neither release waits for the other. Older Phoenix versions are unsupported: they safely ignore `X-Hermes-*`, but do not provide the coordinated audit contract. Those headers remain audit-only and never participate in authentication, ACL, policy, sealing, or attestation.

## Release gate

1. Plugin commits pass offline pytest, compileall, diff checks, and fresh security review.
2. The real-server integration tier passes against the intended Phoenix release binary. A local development skip is acceptable evidence of unavailability, not release evidence.
3. The Phoenix release carrying Hermes audit capture (shared metadata sanitization/capping, `X-Phoenix-Tool` coexistence, its e2e audit scenario, and docs) is tagged at `v0.16.0` or newer.
4. Run the scripted Tier 3 host smoke with `HERMES_SMOKE_REQUIRED=1` (`scripts/host_smoke.py`): a real Hermes v0.18.2 venv at the pinned tag, scratch profile, pip and directory installs, `plugins.enabled` gating, and `hermes phoenix status`/`verify` reporting `ok: true`.
5. Confirm `enable_resolve` remains default false and Hermes toolset defaults cannot expose it.
6. Confirm no plugin, SecretSource, scrub, or role-session plaintext cache file is created.
7. Confirm all compatibility docs state Phoenix `v0.16.0` or newer as the minimum floor and do not claim a simultaneous release.

## Path ownership

- Phoenix Path A owns gateway bootstrap (`env-exec`).
- `hermes-phoenix` SecretSource owns mapped startup fetches after plugin registration; no disk cache.
- `hermes-phoenix` tools own runtime status/list/resolve and opaque sealed output.
- Phoenix core owns trustworthy storage/audit of the plugin's untrusted `X-Hermes-*` hints.

## Rollback

Disable the plugin per profile by removing `phoenix` from `plugins.enabled`. Because the plugin stores no values or role sessions on disk, no cache cleanup is required. Path A remains independent. Removing `enable_resolve` or setting it false removes resolve registration after restart without affecting status/list.
