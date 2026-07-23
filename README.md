# hermes-phoenix

Hermes plugin for [Phoenix Secrets Manager](https://github.com/phoenixsec-dev/phoenix). The current Path B foundation provides profile-local identity, hardened diagnostics, audited status/list calls, and an explicitly opt-in plaintext resolve tool.

## Compatibility and status

- Hermes: `v2026.7.7.2` / `v0.18.2`
- Python: `>=3.11,<3.14`
- Minimum Phoenix server: `v0.15.2`

The current foundation includes:

- pip and directory-plugin manifests
- strict profile-local configuration parsing
- bearer-token-file and optional mTLS client foundations
- `phoenix_status`, warning-only session preflight, `hermes phoenix status`, and `/phoenix status`
- `phoenix_list` path discovery
- default-off, unsealed `phoenix_resolve`
- fail-closed token-file validation and identity-fingerprint groundwork
- offline tests against a stub Phoenix server

Sealed responses, value-aware scrub hooks, cross-profile identity deduplication, role-scoped session minting, SecretSource registration, and `hermes phoenix verify` are not implemented yet.

## Security posture

- Runtime calls never read a bearer from `PHOENIX_TOKEN`; configure `token_file` or client-certificate mTLS.
- `token_file` must be an owner-only (`0600` or `0400`) regular file owned by the Hermes process user. It is opened with `O_NOFOLLOW`; symlink-based token delivery is unsupported.
- Session tokens (`phxs_...`) are rejected as persistent profile identity.
- Bearer-authenticated non-loopback servers must use HTTPS. Redirects and ambient HTTP proxies are disabled.
- A custom `ca_file` is used as the only TLS root bundle for Phoenix requests. TLS 1.2 or newer is required.
- Phoenix response bodies are never copied verbatim into parse or HTTP errors. Server-controlled per-ref error text is not copied into tool results.
- `X-Hermes-*` and `X-Phoenix-Tool` headers are audit hints only. Credentials and Phoenix policy remain the authorization boundary.
- Plugin discovery performs no network I/O. The once-per-session diagnostic uses a two-second timeout and never replaces runtime enforcement.
- Role-scoped runtime session minting remains deliberately fail-closed.

Path A bootstrap injection (`phoenix env-exec`) is a separate Phoenix CLI feature. This repository implements only the Path B Hermes runtime plugin.

## Development install

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[test]'
pytest
```

## Profile configuration

```yaml
plugins:
  enabled: [phoenix]
  entries:
    phoenix:
      server: "https://192.168.0.118:9090"
      token_file: "~/.config/phoenix/token-my-profile"
      ca_file: "~/.config/phoenix/ca.crt"
      default_namespace: "services/hermes/my-profile"
      timeout_seconds: 10
      enable_resolve: false
```

`ca_file` is needed when Phoenix uses its generated internal CA. On the Phoenix server, `auth.mtls.enabled: true` enables TLS; `auth.mtls.require: false` is sufficient for HTTPS with bearer-token clients and does not require a client certificate. Phoenix server certificates include IP SANs, so a LAN-IP server URL can validate against the generated CA.

`ca_cert` remains a deprecated alias for `ca_file`. Do not configure both.

### Plaintext resolve is plugin-gated

Hermes **default-enables previously unknown plugin toolsets**. A host toolset setting is therefore not a safe default-deny boundary for a new plaintext tool.

For that reason, `hermes-phoenix` does not register `phoenix_resolve` at all unless the profile explicitly sets:

```yaml
plugins:
  entries:
    phoenix:
      enable_resolve: true
```

Restart Hermes after changing this gate. The handler also rechecks the setting at call time and fails closed if it is disabled.

This B1–B3 resolve implementation is unsealed: successful values appear as plaintext in the model-visible tool result and session JSONL. Enable it only when that exposure is explicitly accepted. B4 sealed responses and scrub hooks are not present yet.

`phoenix_status` and `phoenix_list` never return secret values.

### List prefixes and ACL globs

Bare list prefixes are relative to `default_namespace`, including nested prefixes such as `calendar/2026`. Use a full `phoenix://namespace/prefix` value for an explicit absolute prefix. Root listing is rejected.

Phoenix ACL `*` matches one path segment; `**` matches recursively. Because the default namespace and typical secret paths are nested, a grant such as:

```text
services/hermes/my-profile/**:read
```

is normally required to list nested paths. `services/hermes/my-profile/*:read` grants only direct children and may produce an empty list.

## Diagnostics and CLI exit status

`hermes phoenix status` prints JSON. Treat its top-level `"ok"` field as the machine-readable result.

Hermes v0.18.2 discards plugin CLI handler return codes, so the process may exit with status 0 even when the printed Phoenix payload has `"ok": false`. The plugin cannot correct that host behavior.

Configured `scrub.*`, `seal_key_file`, and `spec_path` options do not provide their planned B4 behavior yet. `seal_mode: true` likewise provides no sealed output in B1–B3: resolve fails closed instead. The plugin logs warnings and includes them in successful status output until B4 implements those features.

## Directory-plugin install

Hermes directory plugins need `plugin.yaml` and `__init__.py` in the same directory:

```bash
mkdir -p "$HERMES_HOME/plugins/phoenix"
cp plugin.yaml "$HERMES_HOME/plugins/phoenix/plugin.yaml"
cp -R src/hermes_phoenix/. "$HERMES_HOME/plugins/phoenix/"
```

Then add `phoenix` to `plugins.enabled` in that profile's `config.yaml`.

The plugin does not write credentials, resolved values, or caches to disk.

## License

MIT
