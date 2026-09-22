# ACME/TLS implementation plan

Branch: `acme-tls`

## Goal

Add optional HTTPS termination for Blockinator without putting certificate lifecycle work inside Uvicorn. Caddy runs as a sidecar reverse proxy and Blockinator manages its configuration through Caddy's internal admin API.

## Design

- Blockinator remains HTTP-only on the Docker-internal network at `blockinator:8080`.
- Caddy is the only host-published HTTP/HTTPS service.
- Existing HTTP access remains available on `POLICY_PORT`.
- HTTPS is published separately on `HTTPS_PORT`.
- Caddy's admin API is reachable only on the Docker network, never published to the host.
- TLS modes:
  - HTTP only
  - uploaded PEM certificate + private key
  - ACME
- ACME configuration supports:
  - certificate hostname
  - account email
  - custom ACME directory URL
  - optional custom ACME CA/root PEM
  - optional External Account Binding (EAB) key ID + HMAC key
- Uploaded private keys and EAB secrets are stored as files under `/data/tls`, not in SQLite.
- SQLite stores non-secret TLS configuration and certificate metadata.
- Configuration activation uses Caddy `POST /load`, which provides atomic rollback if a new config cannot be loaded.

## Work items

1. TLS persistence and migration
   - Add system settings for TLS mode, hostname, ACME URL/email, EAB key ID and status flags.
   - Add `/data/tls` file layout for uploaded certificate/key, custom CA root and EAB HMAC key.
   - Preserve HTTP-only behavior for existing installs.

2. TLS validation and configuration manager
   - Validate hostname and HTTPS settings.
   - Parse uploaded X.509 certificates.
   - Verify uploaded private key matches the certificate.
   - Validate certificate validity period and SAN coverage for the configured hostname.
   - Validate optional ACME CA root PEM.
   - Render Caddyfile configuration for each TLS mode.
   - Validate candidate Caddyfile with Caddy's `/adapt` endpoint.
   - Activate with Caddy's `/load` endpoint.
   - Preserve the previous active configuration on any validation/load failure.

3. Docker/Caddy integration
   - Add Caddy 2.11.x sidecar.
   - Keep `POLICY_PORT` as the HTTP entry point.
   - Add `HTTPS_PORT` for HTTPS.
   - Persist Caddy ACME state.
   - Share read-only Blockinator TLS material with Caddy.
   - Do not publish the Caddy admin API.

4. System Settings UI
   - Add TLS mode selector.
   - Add hostname, ACME directory, email and EAB controls.
   - Add certificate/key upload controls.
   - Add custom CA root upload.
   - Show TLS status, certificate subject/issuer/SANs and expiration for uploaded certificates.
   - Show whether sensitive material is currently stored without revealing it.
   - Add an explicit Apply TLS settings action.

5. Runtime integration
   - Apply saved TLS configuration during startup after Caddy is reachable.
   - Continue serving Blockinator internally even if TLS activation fails.
   - Make admin session cookies Secure automatically for requests received over HTTPS.

6. Testing
   - TLS settings migration/defaults.
   - PEM certificate/key matching.
   - hostname/SAN validation.
   - Caddyfile rendering for HTTP/uploaded/ACME modes.
   - custom ACME URL, CA root and EAB rendering.
   - safe secret file permissions.
   - rollback/error handling for invalid Caddy config/API failure.
   - HTTP-only upgrade compatibility.

## Explicit non-goals for the first implementation

- DNS-01 provider plugins such as Cloudflare/Route53. Those require custom Caddy builds/plugins.
- Automated certificate import from external secret managers.
- Mutual TLS/client-certificate authentication.

## Acceptance criteria

- Existing installs come up in HTTP-only mode without manual migration.
- Uploaded certificate/key HTTPS works without restarting Blockinator.
- ACME can use the default public CA or a custom ACME directory.
- Private/internal ACME can use a custom root certificate.
- EAB can be configured without storing the HMAC secret in SQLite.
- Invalid TLS changes leave the previous working Caddy configuration active.
- Automatic ACME renewal is delegated to Caddy and survives container restarts.


## Implementation status

Implemented on `acme-tls`:

- [x] Caddy sidecar and HTTP compatibility path.
- [x] Separate configurable HTTPS host port.
- [x] HTTP-only, uploaded-certificate, and ACME modes.
- [x] Certificate/private-key upload and validation.
- [x] Custom ACME directory URL.
- [x] Optional private ACME CA root.
- [x] Optional EAB key ID/HMAC secret.
- [x] Secret-file storage with restrictive permissions.
- [x] Caddy config validation/load with rollback.
- [x] TLS reconciliation after Caddy restarts.
- [x] HTTPS-aware Secure administrator cookies.
- [x] HTTPS-only control for redirect-only HTTP mode.
- [x] Method-preserving 308 redirects with non-standard HTTPS port support.
- [x] System Settings UI and TLS runtime status.
- [x] Python regression tests.
- [x] CI validation of Docker Compose and bootstrap Caddyfile.

Still intentionally excluded from this branch:

- DNS-01 provider plugins/custom Caddy builds.
- External secret-manager integrations.
- Mutual TLS/client certificates.
