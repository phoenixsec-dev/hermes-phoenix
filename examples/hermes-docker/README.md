# Hermes + Phoenix Docker example

This folder shows a containerized Hermes gateway using the Phoenix plugin, in three patterns:

- bearer token over TLS (`docker-compose.bearer.yml`)
- mTLS client certificate (`docker-compose.mtls.yml`)
- bearer token over plain HTTP, dev only (`docker-compose.plaintext.yml`) — the counterpart of the openclaw-docker bearer example

Every value in this folder is a synthetic placeholder. Do not commit real tokens, certificates, or seal private keys — here or anywhere.

## Files

- `docker-compose.bearer.yml`
- `docker-compose.mtls.yml`
- `docker-compose.plaintext.yml`
- `.env.example`
- `config.yaml` — the Hermes profile config (TLS variants) to copy into `./hermes-home/`
- `config.plaintext.yaml` — the profile config for the plaintext variant

## Usage

1. Build the `hermes-agent` image from your Hermes checkout (`docker compose build` in that repo), or substitute your own image tag in the compose file.
2. Initialize Phoenix state into `./phoenix-data`:

   ```bash
   docker compose -f docker-compose.bearer.yml run --rm phoenix --init /data
   ```

   Record the one-time admin token it prints through your normal operator workflow; never write it into files in this folder.
3. Edit `./phoenix-data/config.json`: set `server.listen` to `0.0.0.0:9090` (container-internal; the published port controls actual exposure) and confirm TLS is enabled (`auth.mtls.enabled: true`). For the bearer variant, `auth.mtls.require` stays `false`.
4. Add the Compose DNS name to the Phoenix server certificate, then restart:

   ```bash
   docker compose -f docker-compose.bearer.yml run --rm phoenix \
     --reissue-cert --san phoenix --config /data/config.json
   ```

   This matters because `https://phoenix:9090` is non-loopback — requests cross the container bridge, a wire — and the plugin validates the certificate against the URL hostname (`phoenix`).
5. Provision the profile's Phoenix identity with your Phoenix CLI (synthetic example):

   ```bash
   phoenix agent create hermes-example-main -t synthetic-token-not-real \
     --acl 'services/hermes/example-main/**:read'
   phoenix keypair generate hermes-example-main -o ./secrets-example/hermes-main.seal.key
   printf '%s' 'synthetic-token-not-real' > ./secrets-example/hermes-main.token
   chmod 600 ./secrets-example/hermes-main.token ./secrets-example/hermes-main.seal.key
   ```

6. Copy `.env.example` to `.env` and point the `*_HOST` variables at your real host paths. Copy `config.yaml` to `./hermes-home/config.yaml`.
7. Start the stack:

   ```bash
   docker compose -f docker-compose.bearer.yml up -d
   ```

8. Verify:

   ```bash
   docker compose -f docker-compose.bearer.yml run --rm hermes phoenix verify
   ```

   Hermes discards plugin CLI exit codes, so read the printed top-level `"ok"` field.

## Plaintext dev variant

`docker-compose.plaintext.yml` skips TLS entirely: bearer auth over plain `http://phoenix:9090`. Follow the usage steps above, except: in step 3 still set `server.listen` to `0.0.0.0:9090` but leave TLS off, skip step 4 entirely (no certificate reissue, no CA mount), and copy `config.plaintext.yaml` — not `config.yaml` — to `./hermes-home/config.yaml`.

Why plaintext is acceptable **in this context and no further**: the Compose project creates a private single-host bridge network carrying exactly these two containers, and the variant publishes Phoenix on `127.0.0.1` only, so the cleartext bearer token never crosses a wire another machine can see. The plugin still logs its non-loopback plaintext transport warning at registration and reports it in `status`/`verify` output — that is expected here, not a defect. The moment any other container joins the network, the port binding widens, or Phoenix serves another host, switch to the bearer (TLS) or mTLS variant.

## Notes

- **File modes and ownership.** Token, seal-key, and mTLS private-key files must have no group/other permission bits (`chmod 600`) *on the host* before mounting; `:ro` mounts do not fix insecure host modes. The plugin also requires the files to be owned by the Hermes process user, so set `HERMES_UID`/`HERMES_GID` in `.env` to the host UID/GID that owns them.
- **Transport.** Phoenix is LAN-scoped by design and plaintext is intended for loopback; `https://phoenix:9090` is a non-loopback URL, so the TLS variants encrypt the pipe and the plugin warns loudly — never refuses — on non-loopback plain HTTP (see the plaintext variant above for the one context where that warning is acceptable).
- **Plugin delivery.** The compose files mount this checkout as a directory plugin (`plugin.yaml` plus the package files at `/opt/data/plugins/phoenix/`) for example/dev use. The Hermes image already ships the plugin's one dependency (PyNaCl). For a release install, `pip install hermes-phoenix` into the image's Hermes environment instead.
- **Conservative rollout.** `config.yaml` keeps `enable_resolve: false`, so `phoenix_resolve` is not even registered. Enable it per profile only after choosing sealed or explicitly-unsealed behavior, and put `require_sealed: true` in Phoenix attestation policy on any path that must never leave the server as plaintext — that server-side check binds every client regardless of plugin configuration.
- **One profile per gateway.** Hermes runs one gateway per profile and the profile is the identity boundary. Run more profiles by repeating the pattern with a distinct token and seal key per profile — never shared. `hermes phoenix verify --all-profiles` fails closed on duplicate identity material.
- **Scope.** This example wires Phoenix into a containerized Hermes; messaging channels, dashboards, and other Hermes services are out of scope here — see the Hermes docs.
