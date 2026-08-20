# Hermes operator guide

## Compatibility

- Hermes: tested against `v2026.7.7.2` / `v0.18.2`.
- Python: `>=3.11,<3.14`.
- Phoenix server: `v0.16.0` or newer supplies the status/list/resolve, sealed-response, dry-run, role-session, and coordinated `X-Hermes-*` audit APIs used by the plugin.
- Phoenix `v0.16.0` is a minimum compatibility floor, not a paired release: Phoenix ships on its own schedule, and this plugin requires a server at or above that floor. Older servers are unsupported; they ignore the audit hints and never grant authority from them.

## Three secret planes

| Plane | Purpose | Timing | Plaintext destination |
|---|---|---|---|
| Path A `phoenix env-exec` | Bootstrap the discovering gateway | Before Hermes starts | Gateway environment |
| Phoenix SecretSource | Mapped startup credentials for subsequently spawned Hermes processes/re-pulls | After plugin registration | Hermes orchestrator environment |
| Runtime tools | Agent-initiated status/list/resolve | During a session | Opaque tokens in sealed mode; direct tool result in explicitly unsealed mode |

SecretSource registration happens after the discovering process's first environment load. It **does not replace Path A** for that process.

## Profile identity and resolution

```yaml
plugins:
  enabled: [phoenix]
  entries:
    phoenix:
      server: "https://phoenix.example:9090"
      token_file: "~/.config/phoenix/token-my-profile"
      role: "hermes-my-profile-runtime"  # optional, non-step-up
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

`enable_resolve` is plugin-owned and defaults to false. Hermes default-enables unknown plugin toolsets, so toolset configuration is not a safe replacement for this gate. `seal_mode` never registers resolve implicitly.

Token, seal-key, and mTLS private-key files must be owner-only regular non-symlink files. A persistent `token_file` must contain bootstrap material, never a `phxs_` session token.

### Sealed mode

A seal key file contains one standard-base64 encoded 32-byte X25519 private key. The plugin derives the public key with PyNaCl and sends it as `X-Phoenix-Seal-Key`. Successful resolve output is only:

```text
PHOENIX_SEALED:<base64-envelope-json>
```

Every envelope must have exact version/algorithm/fields, matching normalized ref/path, a 32-byte ephemeral key, a 24-byte nonce, and valid ciphertext encoding. Plaintext is discarded. Missing or invalid envelopes fail closed. The plugin never decrypts.

### Explicitly unsealed mode

With `seal_mode: false` and `enable_resolve: true`, the direct `phoenix_resolve` response and its session entry contain plaintext by design. Returned values are registered for subsequent output scrubbing. Use only when that exposure is accepted.

This posture is deliberate: the plugin does not make a seal key a precondition for `phoenix_resolve`, matching openclaw-phoenix. Paths that must never resolve to plaintext belong under a Phoenix attestation policy with `require_sealed: true` — that check runs server-side per path for every client and credential, so it cannot be bypassed by plugin configuration, a different client, or a missing plugin-side gate. Treat `seal_mode` as client-side hygiene and `require_sealed` as the enforcement point.

## Transport

Phoenix is LAN-scoped by design — internet/WAN exposure is out of scope and unsupported — and a LAN is **not** a trust boundary: one sniffed bearer token yields everything its ACL permits. Concretely:

- `http://` to loopback (`127.0.0.1`, `localhost`, `[::1]`) is the supported default for single-machine deployments; that traffic never reaches a NIC.
- Whenever requests cross a wire — another LAN host, a container bridge — enable TLS on the Phoenix server and use `https://` with `ca_file` pointing at the Phoenix CA certificate. On current Phoenix servers, `auth.mtls.enabled: true` with `auth.mtls.require: false` serves HTTPS for bearer clients without requiring client certificates, and server certificates carry IP SANs, so `https://<lan-ip>:9090` validates against the generated CA.
- Non-loopback `http://` is warned about loudly and never refused: the warning appears in the gateway log at registration, in `phoenix_status` notes, and as the `transport` check in `hermes phoenix verify`. Treat it as a to-do, not noise. The warn-only posture is deliberate and shared with the Phoenix server and openclaw-phoenix; see the Transport posture section of `DESIGN.md`.

## Value-aware scrubbing

The process-local registry stores values of at least eight characters plus standard-base64 and URL-encoded forms. Sources are runtime bearer/session tokens, unsealed resolve/SecretSource values, and current environment values for names in `spec_path`.

The Path A spec is read for names and refs. Literal right-hand-side text is never registered as a value. `transform_terminal_output` and `transform_tool_result` return transformed strings before model/session-context delivery; the direct `phoenix_resolve` result is intentionally exempt.

Scrubbing cannot remove secrets from raw subprocess environments, historical output, files, arbitrary encodings, external logs, or the direct unsealed result. Keep Hermes regex redaction enabled. No registry contents are exposed by a tool or persisted.

## SecretSource

```yaml
secrets:
  phoenix:
    enabled: true
    env:
      EXAMPLE_CALDAV_APP_PASSWORD: "phoenix://services/my-profile/caldav-password"
    timeout_seconds: 20
    override_existing: false
```

The source follows `SECRET_SOURCE_API_VERSION == 1` exactly (`name=phoenix`, label `Phoenix Secrets Manager`, mapped shape, `phoenix` scheme). `fetch()` never raises or prompts and returns Hermes `FetchResult`/`ErrorKind` outcomes. The host orchestrator enforces its wall-clock timeout and applies precedence.

There is **no plaintext disk cache**. SecretSource explicitly asks Phoenix for plaintext because Hermes needs usable environment values and this plugin never decrypts. A `require_sealed` policy/role therefore rejects SecretSource; use a separate least-privilege unsealed identity/role where needed.

On older Hermes versions without `register_secret_source`, the plugin skips this feature with one informational log.

## Role sessions

A configured non-step-up role mints via `/v1/session/mint`. The bootstrap token or mTLS identity is not used for subsequent runtime requests. Scoped session tokens and RFC3339 expiry live only in a process-memory cache; near-expiry sessions renew, expired sessions re-mint, and no session cache file exists.

Mint or renewal denial fails closed. HTTP 202 approval-required responses produce structured `PHOENIX_APPROVAL_REQUIRED` output with a safe approval id/expiry when valid. The plugin never prompts, polls, or blocks for approval. Step-up roles must be handled by an operator outside Hermes and retried.

## Verification

```bash
hermes phoenix status
hermes phoenix verify
hermes phoenix verify --all-profiles
```

Verify checks config, health, authentication/role mint, Path A and SecretSource refs through `POST /v1/resolve?dry_run=true`, sealed handshake, and default-namespace visibility. It prints refs and counts, never values or visible paths.

`--all-profiles` visits only the default config and direct valid sibling profile configs. It fingerprints token contents, seal public keys, and mTLS private-key material internally; it fails on duplicate/unreadable/insecure material and reports profile names rather than credential paths/fingerprints.

Hermes v0.18.2 discards plugin CLI return codes. The printed top-level `ok` field is authoritative.

## Integration tier

```bash
python3 -m pytest -q                  # offline
python3 -m pytest -q -m integration   # real Phoenix or clean skip
python3 scripts/host_smoke.py         # Tier 3 host smoke (real Hermes venv)
```

Provide `PHOENIX_SERVER_BIN`/`PHOENIX_CLI_BIN`, or a read-only `PHOENIX_SRC` with a runnable Go toolchain. Builds, state, credentials, and synthetic values live in throwaway directories. The harness binds localhost and cleans up child processes. Set `PHOENIX_INTEGRATION_REQUIRED=1` when a skip should fail CI.

The Tier 3 host smoke additionally needs a Hermes checkout (`HERMES_SRC`, default: a sibling `hermes` directory) containing the pinned tag `v2026.7.7.2` (`HERMES_SMOKE_TAG` overrides). It exports that tag into a temporary directory, builds a fresh venv, installs the plugin as a pip package and as a directory plugin, checks `plugins.enabled` gating, and requires the printed `"ok": true` from `hermes phoenix status` and `verify`. Missing prerequisites skip cleanly; `HERMES_SMOKE_REQUIRED=1` turns a skip into a failure.

## Troubleshooting

- `PHOENIX_RESOLVE_DISABLED`: set `enable_resolve: true` only after choosing sealed or accepted-unsealed behavior, then restart Hermes.
- `PHOENIX_SEAL_KEY_INVALID`: fix the owner-only key file and registered public key.
- `PHOENIX_SEALED_VALUES_MISSING` / `INVALID`: server/plugin sealed contract mismatch; no plaintext was accepted.
- `PHOENIX_APPROVAL_REQUIRED`: operator action is required; the plugin will not poll.
- `PHOENIX_DUPLICATE_IDENTITY_MATERIAL`: issue unique token and seal material per profile.
- SecretSource `timeout`/`network`/`auth_failed`: use `hermes phoenix verify`, then inspect safe Phoenix audit/server logs.
- Transport warning in the log, status notes, or the verify `transport` check: the profile's server URL is non-loopback `http://`. Enable TLS on the Phoenix server and switch the URL to `https://`; the plugin warns but never refuses.
