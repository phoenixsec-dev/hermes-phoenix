# Hermes plugin config example

A minimal, complete Hermes profile configuration for the Phoenix plugin, plus a refs-only Path A spec sample.

Every value in this folder is a synthetic placeholder. Do not commit real tokens, certificates, or seal private keys.

## Files

- `config.yaml` — plugin enablement, profile identity, sealed mode, scrubbing, and SecretSource configuration
- `phoenix-env.spec.example` — a refs-only Path A env spec; the plugin reads it for names and refs only

## Install

pip shape (into the Hermes venv):

```bash
python -m pip install hermes-phoenix
```

Directory shape (`plugin.yaml` and the package files in the same directory):

```bash
mkdir -p "$HERMES_HOME/plugins/phoenix"
cp plugin.yaml "$HERMES_HOME/plugins/phoenix/plugin.yaml"
cp -R src/hermes_phoenix/. "$HERMES_HOME/plugins/phoenix/"
```

Either way, the plugin loads only for profiles that list it in `plugins.enabled` — enablement is a per-profile allowlist.

## Provision the profile identity (synthetic example)

One Phoenix identity per Hermes profile; the profile is the identity boundary. Never share a token or seal key between profiles.

```bash
phoenix agent create hermes-example-profile -t synthetic-token-not-real \
  --acl 'services/hermes/example-profile/**:read'
phoenix keypair generate hermes-example-profile \
  -o ~/.config/phoenix/seal-example-profile.key
printf '%s' 'synthetic-token-not-real' > ~/.config/phoenix/token-example-profile
chmod 600 ~/.config/phoenix/token-example-profile ~/.config/phoenix/seal-example-profile.key
```

Token, seal-key, and mTLS private-key files must be owner-only (`0600`/`0400`) regular non-symlink files owned by the Hermes process user. A persistent token file must contain bootstrap material, never a `phxs_` session token.

Note the ACL glob: `*` matches one path segment and `**` matches recursively, so nested namespaces normally need the `/**:read` form to list.

## Transport

Phoenix is LAN-scoped by design (internet/WAN exposure is out of scope and unsupported), and a LAN is not a trust boundary. The example `server` URL is `https://` because it names a non-loopback host: enable TLS on the Phoenix server and set `ca_file` whenever requests cross a wire. `http://` is the supported default only for loopback (`127.0.0.1`, `localhost`, `[::1]`) single-machine setups; non-loopback `http://` draws a loud plugin warning — in the gateway log, `phoenix_status` notes, and the verify `transport` check — but is never refused.

## Verify

```bash
hermes phoenix status
hermes phoenix verify
hermes phoenix verify --all-profiles   # fails closed on duplicate identity material
```

Both commands print JSON; Hermes discards plugin CLI exit codes, so the printed top-level `"ok"` field is authoritative.

## Rollout order

1. Ship with `enable_resolve: false` (the default). `phoenix_status` and `phoenix_list` never return secret values, and `phoenix_resolve` is not even registered.
2. Decide sealed versus explicitly-unsealed behavior for the profile. Prefer `seal_mode: true` wherever a seal key exists — tool output stays opaque (`PHOENIX_SEALED:*`) and the plugin never decrypts.
3. For any path that must never leave the server as plaintext, set `require_sealed: true` in Phoenix attestation policy. That server-side check binds every client and credential regardless of plugin configuration; the plugin-side gate is convenience, not the enforcement point.
4. Only then set `enable_resolve: true` and restart Hermes.
