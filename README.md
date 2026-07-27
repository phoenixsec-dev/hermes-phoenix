# hermes-phoenix

Hermes plugin for [Phoenix Secrets Manager](https://github.com/phoenixsec-dev/phoenix). The current Path B implementation provides profile-local identity, hardened diagnostics, audited status/list calls, explicitly gated sealed or unsealed resolution, and value-aware output scrub hooks.

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
- default-off `phoenix_resolve`, with opaque sealed responses when configured
- strict X25519 seal-key and envelope validation; the plugin never decrypts
- process-local value-aware scrubbing for terminal and generic tool results
- runtime bearer and Path A spec-derived environment registration
- fail-closed token/seal/mTLS-key identity validation and `verify --all-profiles` duplicate checks
- process-local non-step-up role session mint/renewal
- Hermes SecretSource API v1 registration with no plaintext disk cache
- machine-readable `hermes phoenix verify`
- offline stub-server tests plus an optional real-Phoenix integration tier

The plugin and the Phoenix patch that captures `X-Hermes-*` metadata are a coordinated release: publish the plugin alongside the Phoenix version containing that patch. The plugin already emits these headers, but older Phoenix versions such as v0.15.2 safely ignore them.

## Security posture

- Runtime calls never read a bearer from `PHOENIX_TOKEN`; configure `token_file` or client-certificate mTLS.
- `token_file` must be an owner-only (`0600` or `0400`) regular file owned by the Hermes process user. It is opened with `O_NOFOLLOW`; symlink-based token delivery is unsupported.
- Session tokens (`phxs_...`) are rejected as persistent profile identity.
- Bearer-authenticated non-loopback servers must use HTTPS. Redirects and ambient HTTP proxies are disabled.
- A custom `ca_file` is used as the only TLS root bundle for Phoenix requests. TLS 1.2 or newer is required.
- Phoenix response bodies are never copied verbatim into parse or HTTP errors. Server-controlled per-ref error text is not copied into tool results.
- Plugin discovery performs no network I/O. The once-per-session diagnostic uses a two-second timeout and never replaces runtime enforcement.
- Sealed HTTP 200 responses must contain complete, matching envelopes. Plaintext is discarded and missing/malformed envelopes fail closed.
- Seal private keys are owner-only regular non-symlink files containing standard-base64 encoded 32-byte X25519 keys. The plugin derives the public key with PyNaCl and never decrypts an envelope.
- Output scrub values exist only in process memory. The plugin writes no secret or scrub cache.
- Configured non-step-up roles mint and renew scoped `phxs_` sessions in memory only. Step-up/approval-required roles return a structured failure and never poll or block.
- Persistent profile token files may never contain `phxs_` session tokens.

Path A bootstrap injection (`phoenix env-exec`) is a separate Phoenix CLI feature. This repository implements only the Path B Hermes runtime plugin.

### Caller headers: audit metadata versus tool policy

The plugin emits both header types, but Phoenix uses them differently:

| Header | Phoenix use | Security effect |
|---|---|---|
| `X-Hermes-Profile`, `X-Hermes-Session-Id`, `X-Hermes-Channel`, `X-Hermes-Tool`, `X-Hermes-Task-Id` | Sanitized, capped, untrusted caller metadata for audit records | **Audit-only.** They never affect authentication, ACLs, roles, sealing, session identity, or attestation policy. In particular, `X-Hermes-Tool` cannot satisfy tool policy. |
| `X-Phoenix-Tool` | Tool-attestation policy input evaluated against Phoenix `allowed_tools` / `deny_tools` rules | **Policy-relevant.** It can affect the access decision, but it does not replace credential authentication or grant access beyond the credential's ACL. It is not recorded as `X-Hermes-*` caller metadata. |

A request may carry both `X-Hermes-Tool` and `X-Phoenix-Tool`. Only `X-Phoenix-Tool` participates in tool policy; the Hermes value remains an audit hint even when the two values conflict.

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
      role: "hermes-my-profile-runtime"  # optional non-step-up role
      ca_file: "~/.config/phoenix/ca.crt"
      default_namespace: "services/hermes/my-profile"
      timeout_seconds: 10
      enable_resolve: false
      seal_mode: true
      seal_key_file: "~/.config/phoenix/seal-my-profile.key"
      spec_path: "/etc/hermes/phoenix-env/my-profile.spec"
      scrub:
        enabled: true
        placeholder: "[PHOENIX-SCRUBBED:{name}]"
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

With `seal_mode: true`, successful values are opaque `PHOENIX_SEALED:<base64-envelope-json>` tokens. The plugin sends the derived public key in `X-Phoenix-Seal-Key`, validates every returned envelope, and never decrypts it. A missing, unreadable, insecure, or malformed key—or a plaintext/incomplete/mismatched response—fails resolve closed. `phoenix_status` remains available and reports only a safe seal-key state.

With `seal_mode: false`, a successful direct `phoenix_resolve` result intentionally contains plaintext and that session JSONL entry is plaintext. Enable this only when that exposure is explicitly accepted. Each returned value is registered for scrubbing from subsequent terminal and generic tool results.

`phoenix_status` and `phoenix_list` never return secret values.

### List prefixes and ACL globs

Bare list prefixes are relative to `default_namespace`, including nested prefixes such as `calendar/2026`. Use a full `phoenix://namespace/prefix` value for an explicit absolute prefix. Root listing is rejected.

Phoenix ACL `*` matches one path segment; `**` matches recursively. Because the default namespace and typical secret paths are nested, a grant such as:

```text
services/hermes/my-profile/**:read
```

is normally required to list nested paths. `services/hermes/my-profile/*:read` grants only direct children and may produce an empty list.

## Value-aware output scrubbing

When `scrub.enabled` is true (the default), the plugin registers values of at least eight characters and their standard-base64 and URL-encoded forms. Sources in B4 are:

- plaintext values returned by explicitly unsealed `phoenix_resolve` calls;
- the profile's Phoenix runtime bearer token;
- current process-environment values for variable names found in the Path A `spec_path` file.

The spec is read only for variable names and `phoenix://` refs; literal right-hand sides are never treated as secret values. Matches become the configured placeholder. The `transform_terminal_output` and `transform_tool_result` hooks return transformed strings before Hermes sends results to the model or persists them to session context.

Scrubbing is defense in depth, not secret isolation: it cannot remove a value from the raw subprocess environment, historical output emitted before registration, arbitrary encodings, files, external process logs, or the deliberately plaintext direct unsealed resolve result. Keep Hermes `security.redact_secrets` enabled and prefer sealed resolution. Registry contents are process-local, never persisted, and exposed through no tool.

## Diagnostics and CLI exit status

`hermes phoenix status` and `hermes phoenix verify` print JSON. Verify validates config, health/authentication, refs from `spec_path` and `secrets.phoenix.env`, default-namespace visibility, and the sealed dry-run handshake without printing resolved values. `--all-profiles` inspects only the default Hermes config and direct valid sibling `profiles/<name>/config.yaml` files, then fails closed on unreadable/insecure or duplicate token/seal/mTLS-key identity material without printing fingerprints or credential paths.

Hermes v0.18.2 discards plugin CLI handler return codes, so the printed top-level `"ok"` field—not the process exit status—is authoritative for both commands.

## Phoenix SecretSource

On Hermes versions exposing SecretSource API v1, the plugin registers:

```yaml
secrets:
  phoenix:
    enabled: true
    env:
      NEXTCLOUD_CALDAV_APP_PASSWORD: "phoenix://services/my-profile/caldav-password"
    timeout_seconds: 20
    override_existing: false
```

The source is named `phoenix`, has mapped shape and `phoenix://` scheme, reuses the hardened profile identity/client, and registers fetched plaintext with the scrubber. `fetch()` never prompts or raises. It performs no disk or value cache under any circumstances.

SecretSource intentionally requests plaintext because Hermes injects usable environment values and this plugin never decrypts envelopes. A Phoenix policy or role that requires sealed responses will therefore fail this source closed; use a separate unsealed least-privilege identity/role for SecretSource if needed.

Plugin registration occurs after the discovering process's initial environment load. Therefore SecretSource **does not replace Path A** for the gateway process that discovers the plugin. It supplies subsequently spawned Hermes processes and re-pulls; Path A remains the bootstrap plane, SecretSource is startup-time mapped child-process injection, and runtime tools are the agent-initiated plane.

## Role sessions

When `role` is configured, the secure token file or mTLS identity is used only to mint a scoped session. Session tokens and expiry are kept in a lock-protected process-memory cache, renewed near expiry, and never written to disk. Expired sessions re-mint. Mint/renew denial fails closed without falling back to broader bootstrap access for that operation. Approval-required roles return `PHOENIX_APPROVAL_REQUIRED` (with a safe approval id/expiry when valid) and never perform blocking approval polling.

## Integration tests

The default `pytest` tier is offline and excludes `integration`. Run the real-server tier with:

```bash
python3 -m pytest -q -m integration
```

Set `PHOENIX_SERVER_BIN` and optionally `PHOENIX_CLI_BIN` for prebuilt binaries, or provide `PHOENIX_SRC` plus a runnable Go toolchain. The harness builds only into a temporary directory, uses localhost/synthetic values/throwaway state, and never modifies the Phoenix checkout. It skips cleanly when requirements are unavailable; set `PHOENIX_INTEGRATION_REQUIRED=1` to turn unavailability into failure.

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
