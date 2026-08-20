# Integrations

## Hermes

Hermes + Phoenix has three complementary planes. Use Phoenix's own CLI bootstrap path for secrets the gateway process needs before Hermes starts, and use this `hermes-phoenix` plugin package for everything at and after plugin registration: mapped startup injection (SecretSource), agent runtime tools, transcript scrubbing, and operator diagnostics.

Start here:
- [Hermes operator guide](./hermes-guide.md)
- [Release coordination checklist](./release-coordination.md)

| Plane | Owner | Use it for |
|---|---|---|
| Path A bootstrap (`phoenix env-exec`) | Phoenix CLI | Gateway-process secrets that must exist before Hermes starts (bot tokens, provider keys) |
| SecretSource (`secrets.phoenix`) | this plugin | Mapped `ENV_VAR: phoenix://...` credentials for subsequently spawned Hermes processes and re-pulls |
| Runtime tools | this plugin | Agent-initiated `phoenix_status` / `phoenix_list` / `phoenix_resolve` with per-request ACL, attestation, sealing, and audit |

Transport applies to all three planes identically: Phoenix is LAN-scoped by design (internet/WAN exposure is out of scope and unsupported), and a LAN is not a trust boundary. Plaintext `http://` to loopback is the supported default; enable TLS on the Phoenix server and use `https://` whenever a request crosses a wire. The plugin warns loudly — never refuses — on non-loopback `http://`, in the gateway log, `phoenix_status` notes, and the `transport` check of `hermes phoenix verify`.

### Plugin package path — runtime tools

Use the plugin package when you want:

- health/connectivity diagnostics through `phoenix_status`, `hermes phoenix status`, and `/phoenix status`
- visible-path discovery through `phoenix_list` (paths only, never values)
- runtime resolution through `phoenix_resolve` — sealed by default wherever a seal key exists, plaintext only for explicitly opted-in profiles
- Phoenix ACL, role, and attestation policy evaluated on every runtime request
- sealed responses that keep values out of model-visible tool output and session JSONL
- value-aware scrubbing of terminal and tool output for values the plugin has handled
- warning-only startup diagnostics that never block the Hermes gateway
- machine-readable `hermes phoenix verify` (including `--all-profiles` duplicate-identity checks)

Install into the Hermes venv (pip shape):

```bash
python -m pip install hermes-phoenix
```

Or install as a directory plugin (`plugin.yaml` plus the package files in `$HERMES_HOME/plugins/phoenix/` — see the README). Either way, enablement is per profile:

```yaml
plugins:
  enabled: [phoenix]
```

Conservative rollout: start with `phoenix_status` only. `phoenix_list` reveals path inventory, and `phoenix_resolve` is not even registered until the profile sets `enable_resolve: true`, so the default posture is already status/list-only. Before enabling resolve, decide sealed versus explicitly unsealed behavior per profile, and put `require_sealed: true` in Phoenix attestation policy on any path that must never leave the server as plaintext — that server-side check binds every client regardless of plugin configuration and is the real enforcement point, not the plugin gate.

### SecretSource path — mapped startup injection

On Hermes hosts exposing SecretSource API v1, the plugin registers a `phoenix` source configured under `secrets.phoenix`:

```yaml
secrets:
  phoenix:
    enabled: true
    env:
      EXAMPLE_APP_PASSWORD: "phoenix://services/hermes/my-profile/example-app-password"
    timeout_seconds: 20
```

Two contract points to plan around:

- The source keeps **no plaintext disk cache** — a deliberate divergence from bundled Hermes sources, because Phoenix doctrine forbids resolved values at rest. Expect a resolve round-trip per process start.
- The source explicitly requests **plaintext** (Hermes needs usable environment values and this plugin never decrypts envelopes). A Phoenix policy or role with `require_sealed` on those paths fails the source closed; give SecretSource paths their own least-privilege unsealed identity/role if needed.

SecretSource registration happens after the discovering process's first environment load, so it does **not** replace Path A for the gateway's own bootstrap.

### Bootstrap path — Path A

Path A (`phoenix env-exec`) is a Phoenix CLI feature, not part of this repository: it injects secrets from a refs-only spec file into the gateway process environment before Hermes starts. See the Phoenix documentation for its availability and usage. This plugin touches the spec file only in two read-only ways:

- `hermes phoenix verify` dry-runs every `phoenix://` ref found in the configured `spec_path`;
- the scrubber reads the spec for variable **names**, then registers the current process-environment values of those names. Literal right-hand sides in the spec are never treated as secret values.

### Refs, prefixes, and what this plugin does not do

- Plugin refs are `phoenix://namespace/path` strings; bare refs and bare list prefixes are relative to the profile's `default_namespace`.
- Phoenix ACL `*` matches one path segment, `**` matches recursively — nested namespaces normally need a `.../**:read` grant to list.
- Installing this plugin does not make `phoenix://...` strings inside arbitrary Hermes config values resolve through Phoenix. Config-level interpolation is not part of this integration; use Path A for pre-start secrets and `secrets.phoenix.env` for mapped startup injection.
