# Security and operations

Use separate `librasys_runtime`, `librasys_reporting`, `librasys_migrator`, and DBA accounts from `database/operations/security-and-operations.sql`. Replace placeholder passwords using a secret manager; never commit them. Runtime connections must use TLS certificate verification and a private network. Rotate credentials and revoke sessions after suspected compromise.

Provide the complete `ConnectionStrings__LibraryDatabase` value through deployment configuration. Do not rely on `${...}` interpolation inside JSON configuration; .NET treats such text literally. Readiness remains unhealthy until a complete, non-placeholder connection string is configured.

Interactive Swagger documentation is enabled only in the Development environment. Keep production API documentation behind an authenticated internal route or an external access control layer if it is required for operations.

Production responses enable HSTS and baseline browser protections (`nosniff`, frame denial, and strict referrer policy). Configure `AllowedHosts` with the actual API hostnames for each deployment; do not use a wildcard in production.

Enable structured application audit events and immutable `audit_logs` records for authentication, catalog/member changes, circulation, fines, and payments. Encrypt backups and sensitive exports with managed keys; document key ownership, rotation, and break-glass access. Do not store raw passwords or payment card data.

Run full backups daily, binlog shipping continuously, and verify restore to an isolated MySQL instance at least quarterly. Target RPO 15 minutes and RTO 4 hours unless the deployment owner approves otherwise. Retain backups according to policy and test logical and physical restore procedures.

For tuning, run the parameterized checks in `database/operations/query-tuning.sql` against a staging replica with representative data. Preserve composite indexes, use bounded page sizes, and prefer keyset pagination for large deployments.

For split frontend/API deployments, set `Cors:AllowedOrigins` to the exact HTTPS frontend origins. Keep production origins in deployment configuration, never use `*` for authenticated traffic, and do not enable credential sharing unless the deployment explicitly requires it.
