# hermes-phoenix

Hermes plugin for [Phoenix Secrets Manager](https://github.com/phoenixsec-dev/phoenix). The current status-first foundation provides secure bootstrap-token-file/mTLS client handling, diagnostics, and audited status calls; scoped role sessions, secret tools, and sealed/scrubbed responses are planned follow-up work.

## Status

Early development scaffold targeting Hermes `v2026.7.7.2` / `v0.18.2` and Python `>=3.11,<3.14`.

The current foundation includes:

- pip and directory-plugin manifests
- strict profile-local configuration parsing
- bearer-token-file and mTLS client foundations
- `phoenix_status`, warning-only startup/session preflight, `hermes phoenix status`, and `/phoenix status`
- offline tests against a stub Phoenix server

`phoenix_resolve`, `phoenix_list`, sealed responses, value-aware scrub hooks, identity deduplication, SecretSource registration, and `hermes phoenix verify` are not implemented yet.

## Security posture

- Runtime calls never read a bearer from `PHOENIX_TOKEN`; use a mode-`0600`/`0400` token file or mTLS.
- Token files and mTLS private keys must be regular, non-symlink files owned by the Hermes process user with no group/other permissions.
- Session tokens (`phxs_...`) are rejected for persistent profile identity.
- Phoenix response bodies are never copied verbatim into parse or HTTP errors, and status output exposes only allowlisted health fields.
- Bearer-authenticated servers must use HTTPS; plain HTTP is accepted only for loopback development addresses. Redirects and ambient HTTP proxies are disabled.
- `X-Hermes-*` headers are audit hints only. Phoenix credentials and policy remain the authorization boundary.
- Role-scoped runtime session minting is reserved by the config schema but deliberately fails closed in this initial scaffold.

Path A bootstrap injection (`phoenix env-exec`) is a separate Phoenix CLI feature. This repository implements only the Path B Hermes runtime plugin.

## Development install

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[test]'
pytest
```

Enable the pip plugin in the active Hermes profile:

```yaml
plugins:
  enabled: [phoenix]
  entries:
    phoenix:
      server: "https://phoenix.example:9090"
      token_file: "~/.config/phoenix/token-my-profile"
      default_namespace: "services/hermes/my-profile"
      timeout_seconds: 10
```

Hermes toolsets remain independently allowlisted. Begin with `phoenix_status` only.

## Directory-plugin install

Hermes directory plugins need `plugin.yaml` and `__init__.py` in the same directory. Copy the manifest and package source together:

```bash
mkdir -p "$HERMES_HOME/plugins/phoenix"
cp plugin.yaml "$HERMES_HOME/plugins/phoenix/plugin.yaml"
cp -R src/hermes_phoenix/. "$HERMES_HOME/plugins/phoenix/"
```

Then add `phoenix` to `plugins.enabled` in that profile's `config.yaml`.

## Authentication foundations

Supported by the status/preflight client:

- scoped bearer in `token_file`
- mTLS via `ca_cert`, `client_cert`, and `client_key`
- bearer + mTLS together

The plugin does not write credentials, resolved values, or caches to disk.

## License

MIT
