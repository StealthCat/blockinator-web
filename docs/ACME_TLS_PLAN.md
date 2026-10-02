# ACME/TLS plan — implemented

The original `acme-tls` work is merged into `main`. This path remains as a pointer for existing links; the completed checklist is no longer a deployment guide.

- [Current HTTPS configuration and supported modes](OPERATIONS.md#https-and-tls)
- [TLS files, Caddy state, and backups](OPERATIONS.md#data-and-backups)
- [Environment variables](OPERATIONS.md#environment-variables)
- [Validation and development](DEVELOPMENT.md#testing)

Caddy handles certificate issuance/renewal and terminates TLS; Blockinator manages native Caddy JSON through the internal admin API. Uploaded keys and ACME EAB secrets stay in protected files, while non-secret configuration is stored in the selected SQLite or MySQL database.

DNS-01 provider plugins, external secret-manager integration, and client-certificate authentication for the policy API remain outside the built-in TLS controls.
