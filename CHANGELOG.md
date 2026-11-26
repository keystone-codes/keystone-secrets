# Changelog

## [0.1.0] - 2026-11-26

### Added

- `SecretStore` protocol, domain models, and shared errors.
- AES-256-GCM sealing with HKDF labels for keystone-secrets (ported from stdio-box).
- `local-postgres` backend with schema constants, audit log, `rekey`, and `needs_reentry`.
- OpenAPI 3.1 description `docs/protocol-v1.yaml`.
- `SecretStoreConformance` test suite and `keystone-secrets` CLI (`put`, `rekey`, `schema install`).
- CI workflow with Postgres 16 service.