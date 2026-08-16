# Hermes + Phoenix Docker example

This folder shows a containerized Hermes gateway using the Phoenix plugin, in two auth patterns:

- bearer token (`docker-compose.bearer.yml`)
- mTLS client certificate (`docker-compose.mtls.yml`)

Every value in this folder is a synthetic placeholder. Do not commit real tokens, certificates, or seal private keys — here or anywhere.

## Files

- `docker-compose.bearer.yml`
- `docker-compose.mtls.yml`
- `.env.example`
- `config.yaml` — the Hermes profile config to copy into `./hermes-home/`

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

   This matters because the plugin requires HTTPS for bearer auth to any non-loopback server, and it validates the certificate against the URL hostname (`phoenix`).
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

## Notes

- **File modes and ownership.** Token, seal-key, and mTLS private-key files must have no group/other permission bits (`chmod 600`) *on the host* before mounting; `:ro` mounts do not fix insecure host modes. The plugin also requires the files to be owned by the Hermes process user, so set `HERMES_UID`/`HERMES_GID` in `.env` to the host UID/GID that owns them.
- **HTTPS is mandatory here.** `https://phoenix:9090` is a non-loopback URL, and the plugin rejects plain HTTP bearer auth to non-loopback servers by design. There is no HTTP variant of this example.
- **Plugin delivery.** The compose files mount this checkout as a directory plugin (`plugin.yaml` plus the package files at `/opt/data/plugins/phoenix/`) for example/dev use. The Hermes image already ships the plugin's one dependency (PyNaCl). For a release install, `pip install hermes-phoenix` into the image's Hermes environment instead.
- **Conservative rollout.** `config.yaml` keeps `enable_resolve: false`, so `phoenix_resolve` is not even registered. Enable it per profile only after choosing sealed or explicitly-unsealed behavior, and put `require_sealed: true` in Phoenix attestation policy on any path that must never leave the server as plaintext — that server-side check binds every client regardless of plugin configuration.
- **One profile per gateway.** Hermes runs one gateway per profile and the profile is the identity boundary. Run more profiles by repeating the pattern with a distinct token and seal key per profile — never shared. `hermes phoenix verify --all-profiles` fails closed on duplicate identity material.
- **Scope.** This example wires Phoenix into a containerized Hermes; messaging channels, dashboards, and other Hermes services are out of scope here — see the Hermes docs.
