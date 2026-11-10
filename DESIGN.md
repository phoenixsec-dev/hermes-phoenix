# hermes-phoenix — Design

**Status:** current. This document describes the shipped design of the
`hermes-phoenix` plugin. The [README](./README.md) and [`docs/`](./docs/)
are authoritative for operator instructions; this document explains what
the plugin is, where its trust boundaries sit, and why it is shaped the
way it is.

---

## 1. Role

Phoenix Secrets Manager's doctrine is that agents see references, never
values. A Hermes deployment touches secrets on three distinct planes, and
this plugin implements exactly one of them:

| Plane | Owner | Purpose | Timing |
|---|---|---|---|
| Path A — `phoenix env-exec` | Phoenix CLI (separate feature) | Bootstrap the discovering gateway process from a refs-only spec file | Before Hermes starts |
| SecretSource | this plugin (§9) | Mapped startup credentials for subsequently spawned Hermes processes and re-pulls | After plugin registration |
| Runtime tools | this plugin (§4) | Agent-initiated status/list/resolve with per-request policy, sealing, and audit | During a session |

Path A gets secrets *into* the gateway process; this plugin is the
**runtime plane**: agent-visible Phoenix tools, per-profile identity,
sealed responses, value-aware transcript scrubbing, and operator
diagnostics (`hermes phoenix status|verify`). It mirrors the sibling
[openclaw-phoenix](https://github.com/phoenixsec-dev/openclaw-phoenix)
plugin feature-for-feature where the host platforms overlap, adapted to
Hermes's plugin API, plus one Hermes-only surface OpenClaw has no
analogue for: a registered Phoenix SecretSource.

## 2. Design principles

- **References, never values.** No tool returns plaintext unless the
  operator has explicitly opted the profile into unsealed resolution.
  Sealed output is opaque; the plugin cannot decrypt it (§5).
- **Fail closed at runtime, warn-only at startup.** A broken Phoenix must
  never take down a Hermes gateway, so registration and preflight only
  log warnings. Runtime operations are the opposite: any identity, seal,
  or contract problem aborts the operation with a structured error.
  A missed warning can never silently widen trust.
- **No secret state on disk.** The plugin writes no credential, resolved
  value, session token, or scrub-registry cache to disk, ever.
- **Minimal dependency surface.** Stdlib plus PyNaCl (X25519 sealed-box
  primitives) only. No HTTP or validation frameworks, so the plugin is
  importable in any supported Hermes venv without dependency drift.
- **Untrusted metadata stays metadata.** Caller correlation headers are
  audit hints; nothing the plugin sends in a header can change an access
  decision except the explicitly policy-relevant `X-Phoenix-Tool` (§11).

## 3. Identity model

**One Phoenix identity per Hermes profile.** Hermes runs one gateway per
profile and plugin configuration lives in that profile's own
`config.yaml` (`plugins.entries.phoenix`), so the profile *is* the
identity boundary. There is no in-process multi-agent identity map, and
nothing in a tool call can select a different identity: the OpenClaw
plugin needs a per-agent `agents:{}` mapping because one gateway hosts
many agent ids; Hermes does not.

Identity material rules, enforced on every read:

- Runtime authentication is `token_file` (bearer) or an mTLS client
  certificate/key pair. Reading a bearer from `PHOENIX_TOKEN` is
  intentionally unsupported at runtime, so a Path-A-cleaned environment
  remains the baseline.
- Token, seal-key, and mTLS private-key files must be owner-only
  (`0600`/`0400`) regular files owned by the Hermes process user, opened
  with `O_NOFOLLOW`; symlink delivery is rejected.
- A persistent `token_file` containing a `phxs_` session token is
  rejected: short-lived session material is not durable profile identity.
- Redirects and ambient HTTP proxies are disabled; a configured
  `ca_file` becomes the only TLS root for Phoenix requests, TLS 1.2
  minimum. Plain `http://` to a non-loopback address is loudly warned
  about but never refused (§7).

**Cross-profile uniqueness.** Because profiles are separate processes,
duplicate-credential detection cannot happen in-process. The operator
command `hermes phoenix verify --all-profiles` fingerprints token
contents, derived seal public keys, and mTLS private-key material
(SHA-256, internal only) across the default config and direct sibling
profile configs, and fails closed on duplicates or unreadable/insecure
material — reporting profile names, never paths or fingerprints.

**Role sessions.** When a `role` is configured, the bootstrap identity is
used only to mint a scoped `phxs_` session (`/v1/session/mint`); runtime
requests then use the session token. Sessions live in a lock-protected
in-memory cache keyed by server/profile/role/identity/seal-key, renew
near expiry, and re-mint after expiry. Mint or renewal denial fails
closed — there is no fallback to broader bootstrap access for that
operation. Approval-gated roles surface a structured
`PHOENIX_APPROVAL_REQUIRED` result; the plugin never polls or blocks for
approval.

## 4. Tool surface

Three tools, each returning JSON strings per the Hermes handler contract:

- **`phoenix_status`** — reachability, authenticated preflight of the
  bootstrap identity, seal-key state, auth mode. Never returns secret
  material; the safe first tool to enable.
- **`phoenix_list`** — visible secrets under the profile namespace or a
  given folder, each with its description. Never values. The folder may be
  written `x/y`, `x/y/` or `x/y/*` (the Phoenix CLI's forms; a lone `*`
  is the default folder, as in the CLI); any other wildcard is refused
  before a request. It asks `GET /v1/metadata/` and
  keeps only `path` and `description`; a server too old for that route
  answers a plain-text 404, and the plugin then lists bare paths from
  `GET /v1/secrets/` with a `note` saying descriptions are unavailable.
  Responses are validated: paths outside the requested prefix, control
  characters, or dot segments fail the call.
- **`phoenix_resolve`** — resolve up to 50 refs per call. Sealed
  profiles return opaque `PHOENIX_SEALED:` tokens (§5); explicitly
  unsealed profiles return plaintext in the direct result (§6).

**Resolve is gated at registration, not just at call time.** Hermes
default-enables previously unknown plugin toolsets, so a host toolset
setting is not a safe default-deny boundary for a new plaintext-capable
tool. `phoenix_resolve` is therefore not registered at all unless the
profile sets `enable_resolve: true`; the handler also re-checks the
setting on every call and fails closed if it is off. Status and list
never resolve values, so they register unconditionally.

Operator surfaces: `hermes phoenix status` and `hermes phoenix verify`
(CLI, machine-readable JSON), and an in-session `/phoenix status` slash
command (status only — no resolve from the slash surface). Hermes
v0.18.2 discards plugin CLI handler return codes, so the printed
top-level `"ok"` field is authoritative for both commands.

## 5. Sealed mode

With `seal_mode: true`, the plugin reads an owner-only file containing
one standard-base64 32-byte X25519 private key, derives the public key
with PyNaCl, and sends it as `X-Phoenix-Seal-Key` on resolve. Successful
values come back only as:

```text
PHOENIX_SEALED:<base64-envelope-json>
```

Every envelope is validated against the wire contract before the token
is produced: exact field set (`version`, `algorithm`, `path`, `ref`,
`ephemeral_key`, `nonce`, `ciphertext`), exact version and algorithm,
`path`/`ref` matching the normalized request, canonical base64, a
32-byte ephemeral key, a 24-byte nonce, and non-empty authenticated
ciphertext. Violations fail closed:

- An HTTP 200 that carries plaintext `values` while sealed is a contract
  violation. The plaintext is discarded unread and never reaches the
  model.
- Missing or partial `sealed_values` → `PHOENIX_SEALED_VALUES_MISSING`.
- Any malformed envelope → `PHOENIX_SEALED_VALUES_INVALID`.
- A missing, unreadable, insecure, or malformed seal key fails all
  resolve-class operations with remediation; `phoenix_status` stays
  available and reports only a safe seal-key state.

The plugin never decrypts an envelope. Unsealing is the consumer's job
(Phoenix CLI / injection flows), which keeps plaintext out of the model
plane entirely: on sealed profiles, session transcripts and downstream
ingestion only ever see opaque tokens — before scrubbing even applies.

## 6. Unsealed resolve posture

Unsealed `phoenix_resolve` ships, default-off. With `seal_mode: false`
and `enable_resolve: true`, the direct tool result and its session JSONL
entry contain plaintext by design; each returned value is immediately
registered with the scrubber so it cannot resurface un-scrubbed in later
output (§8).

The plugin deliberately does not make a seal key a precondition for
resolve, matching openclaw-phoenix, where sealed mode is per-config
behavior rather than a prerequisite. The authoritative "never plaintext"
control is server-side: Phoenix attestation policy supports
`require_sealed: true` per path, which rejects any resolve lacking a
valid `X-Phoenix-Seal-Key` — for every client and credential, regardless
of plugin configuration. A plugin-side prohibition would be a weaker
duplicate of that control, binding only clients that chose to implement
it, and would push operators toward assuming a client-side gate is a
security boundary. It is not; `require_sealed` is.

## 7. Transport posture

Phoenix is **LAN-scoped by design**: internet/WAN exposure is out of
scope and unsupported. Being in scope does not make the LAN trusted —
a LAN includes containers on shared bridges, IoT devices, guest WiFi,
and anything that has compromised one host, and Phoenix is a credential
concentrator: sniffing one bearer token yields everything that token's
ACL permits. The consequences for this plugin:

- **Plaintext loopback is the supported default.** Loopback traffic
  never reaches a NIC, and the dominant deployment is single-machine.
- **Crossing a wire means TLS.** Any non-loopback server URL should be
  `https://` with `ca_file` set to the Phoenix CA certificate.
- **Non-loopback `http://` warns loudly and never refuses.** The
  warning names the exposure (bearer tokens and secret values in
  cleartext on that specific address) and is surfaced structurally, not
  just on a console: in the gateway log at registration, in
  `phoenix_status` notes, and as the `transport` check in
  `hermes phoenix verify` output.

This is a deliberate posture change made knowingly: earlier revisions
hard-failed on non-loopback `http://`, which made hermes-phoenix the
only one of the three Phoenix packages (server, openclaw-phoenix,
hermes-phoenix) that failed closed — stricter than the Phoenix server
itself, and unusable against a stock Phoenix on a LAN address. A
client-side refusal here is not a security boundary (any other client
could still connect in plaintext); the real controls are enabling TLS
on the server for the wire and `require_sealed` policy for values
(§6). Consistency of signal across all three packages — warn loudly
on non-loopback plaintext, never refuse — is the point. The server's
own startup warning and its first-class `tls:` block ship in Phoenix
`v0.17.0`; this plugin's warning is client-side and is emitted against
any supported server, including ones that stay silent themselves.

## 8. Value-aware output scrubbing

Hermes's built-in redaction is pattern-based, and session JSONL is
written before redaction applies, so a secret that matches no vendor
pattern can reach transcripts. This plugin adds the missing value layer:
a process-local registry mapping known secret values (and their
standard-base64 and URL-encoded forms; minimum length 8) to safe labels.

Registered sources:

1. plaintext values returned by explicitly unsealed `phoenix_resolve`;
2. values fetched by the SecretSource (§9);
3. the profile's Phoenix runtime bearer token and minted session tokens;
4. current process-environment values for variable names found in the
   Path A `spec_path` file — the spec is read for **names and refs
   only**; literal right-hand sides are never treated as secret values.

The `transform_terminal_output` and `transform_tool_result` hooks replace
each occurrence with the configured placeholder before Hermes sends the
string to the model or persists it to session context. The direct
unsealed `phoenix_resolve` result is intentionally exempt (§6); existing
placeholders are never re-scrubbed.

Scrubbing is defense in depth, not secret isolation. It cannot remove a
value from the raw subprocess environment, historical output emitted
before registration, arbitrary encodings, files, or external process
logs. It complements — never replaces — Hermes's own regex redaction,
and sealed resolution remains the recommended default wherever a seal
key exists. Registry contents are process-local, never persisted, and
exposed through no tool.

## 9. SecretSource

On Hermes versions exposing SecretSource API v1
(`register_secret_source`, feature-detected), the plugin registers a
`phoenix` source: mapped shape, `phoenix://` scheme, configured under
`secrets.phoenix.env` as `ENV_VAR: phoenix://...` bindings. It reuses
the same hardened profile identity and client as the tools, registers
every fetched value with the scrubber, and honors the orchestrator
timeout. `fetch()` never raises and never prompts.

Two deliberate divergences from the bundled Hermes sources:

- **No disk value cache.** Bundled sources may cache resolved plaintext
  on disk; Phoenix doctrine forbids resolved values at rest, so this
  source performs a resolve round-trip per process start instead. This
  is intentional — do not "optimize" it away.
- **Explicitly unsealed requests.** SecretSource exists to inject usable
  environment values and this plugin never decrypts envelopes, so the
  source requests plaintext. A Phoenix policy or role that requires
  sealed responses therefore fails this source closed; use a separate
  least-privilege unsealed identity/role for SecretSource paths if
  needed.

Timing caveat: plugin-registered sources are not consulted by the
initial environment load of the process that discovers the plugin, so
SecretSource does **not** replace Path A for the gateway's own
bootstrap. It covers subsequently spawned Hermes processes and re-pulls.

## 10. Preflight and verify

Registration runs a warning-only preflight and re-checks once per
session on `on_session_start` (with a capped 2-second timeout): server
reachability, authentication, seal-key well-formedness. Warnings go to
the gateway log; registration never raises, and every registration step
is individually wrapped so a partial failure degrades that feature only.

`hermes phoenix verify` is the strict operator gate: config validation,
identity checks, health, authenticated probe, seal configuration, a
sealed dry-run handshake, dry-run resolution of every ref collected from
the Path A `spec_path` and `secrets.phoenix.env`, and default-namespace
visibility. It prints refs and counts, never values. Diagnostics never
copy server-controlled response bodies or per-ref error text into tool
results.

## 11. Audit header contract

Every Phoenix API call carries caller metadata, sanitized (control and
format characters stripped, whitespace collapsed) and capped at 256
characters per value:

| Header | Source | Phoenix use |
|---|---|---|
| `X-Hermes-Profile` | profile name | audit metadata only |
| `X-Hermes-Session-Id` | session id, when known | audit metadata only |
| `X-Hermes-Channel` | platform/channel, when known | audit metadata only |
| `X-Hermes-Tool` | invoking tool (`phoenix_resolve`, `secret-source`, `verify`, …) | audit metadata only |
| `X-Hermes-Task-Id` | task id, when known | audit metadata only |
| `X-Phoenix-Tool` | same operation name | tool-attestation policy input |

`X-Hermes-*` values are untrusted hints recorded for audit correlation.
They never affect authentication, ACLs, roles, sealing, session
identity, or attestation, and spoofing them cannot elevate access.
`X-Phoenix-Tool` is the one policy-relevant header: Phoenix evaluates it
against `allowed_tools`/`deny_tools` attestation rules, but it cannot
replace credential authentication or expand a credential's ACL. No
header in the set carries secret material, and no session-key-class
header exists.

## 12. Compatibility

- Hermes: designed and tested against `v2026.7.7.2` / `v0.18.2`.
  Features missing on older hosts (notably `register_secret_source`)
  are feature-detected and skipped with a log line; nothing below the
  tested tag is claimed or tested.
- Python: `>=3.11,<3.14`, following the host.
- Phoenix server: `v0.16.0` or newer — the minimum floor that provides
  sealed responses, dry-run resolve, role sessions, and `X-Hermes-*`
  audit capture. Phoenix releases ship independently of this plugin.

## 13. Testing

- **Tier 1 — offline unit tier** (default `pytest`): stub Phoenix HTTP
  server, no network, no Hermes install required. Covers config
  validation, ref parsing, identity file checks, sealed fail-closed
  paths (including 200-plaintext-while-sealed), scrubbing, tool
  handlers, SecretSource contract, and verify.
- **Tier 2 — integration** (`pytest -m integration`): boots a real
  throwaway `phoenix-server` (prebuilt binary or a Go build from a
  read-only checkout) on localhost with synthetic values, and proves the
  sealed/scrub/fail-closed behavior end to end. Skips cleanly when a
  server or toolchain is unavailable; `PHOENIX_INTEGRATION_REQUIRED=1`
  turns that skip into a failure for release gates.
- **Tier 3 — host smoke** (`scripts/host_smoke.py`, not in the default
  matrix): a real Hermes venv at the pinned tag with a scratch profile,
  the plugin installed both ways (pip and directory), `plugins.enabled`
  gating verified, and `hermes phoenix verify` run against a throwaway
  Phoenix. Skips cleanly when prerequisites are missing;
  `HERMES_SMOKE_REQUIRED=1` turns a skip into a failure. See
  `docs/release-coordination.md` for where it gates a release.
